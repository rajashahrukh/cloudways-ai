<?php
/**
 * Plugin Name: Cloudways MCP Server
 * Description: Model Context Protocol (MCP) server for WordPress on Cloudways. Enables AI assistants (ChatGPT, Cursor, Claude) to manage your site via standardized MCP tools.
 * Version: 1.0.0
 * Author: Cloudways
 * License: GPL-2.0-or-later
 * Network: true
 *
 * Single-file must-use plugin. Drop into wp-content/mu-plugins/cw-mcp.php
 * Only activates on Cloudways infrastructure.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'CW_MCP_VERSION', '1.0.0' );
define( 'CW_MCP_MIN_PHP', '7.4' );

if ( version_compare( PHP_VERSION, CW_MCP_MIN_PHP, '<' ) ) {
    return;
}

// ============================================================================
// Cloudways Detection
// ============================================================================

class CW_MCP_Cloudways {

    public static function is_cloudways(): bool {
        if ( self::check_path_structure() ) {
            return true;
        }
        if ( is_dir( '/opt/cloudways' ) || is_dir( '/etc/cw' ) ) {
            return true;
        }
        if ( file_exists( '/var/run/cw-agent.pid' ) ) {
            return true;
        }
        if ( defined( 'CW_MCP_FORCE_ENABLE' ) && CW_MCP_FORCE_ENABLE ) {
            return true;
        }
        return false;
    }

    private static function check_path_structure(): bool {
        $abspath = str_replace( '\\', '/', ABSPATH );
        return (bool) preg_match( '#^/home/[^/]+/applications/[^/]+/public_html#', $abspath );
    }
}

if ( ! CW_MCP_Cloudways::is_cloudways() ) {
    return;
}

// ============================================================================
// Site Identity
// ============================================================================

class CW_MCP_Site_ID {

    const OPTION_KEY = 'cw_mcp_site_id';

    public static function get(): string {
        $site_id = get_option( self::OPTION_KEY );
        if ( ! $site_id || ! self::is_valid_uuid( $site_id ) ) {
            $site_id = self::generate_uuid_v4();
            update_option( self::OPTION_KEY, $site_id, true );
        }
        return $site_id;
    }

    public static function get_identity(): array {
        return array(
            'site_id'    => self::get(),
            'site_url'   => site_url(),
            'site_name'  => get_bloginfo( 'name' ),
            'wp_version' => get_bloginfo( 'version' ),
        );
    }

    private static function generate_uuid_v4(): string {
        $data    = random_bytes( 16 );
        $data[6] = chr( ord( $data[6] ) & 0x0f | 0x40 );
        $data[8] = chr( ord( $data[8] ) & 0x3f | 0x80 );
        return vsprintf( '%s%s-%s-%s-%s-%s%s%s', str_split( bin2hex( $data ), 4 ) );
    }

    private static function is_valid_uuid( string $uuid ): bool {
        return (bool) preg_match(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i',
            $uuid
        );
    }
}

// ============================================================================
// Authentication (SHA-256 hashed keys, role-bound, expiring)
// ============================================================================

class CW_MCP_Auth {

    const KEYS_OPTION = 'cw_mcp_api_keys';

    public function authenticate( WP_REST_Request $request ) {
        $header = $request->get_header( 'Authorization' );

        if ( ! $header || stripos( $header, 'Bearer ' ) !== 0 ) {
            return new WP_Error( 'cw_mcp_missing_auth',
                'Missing or malformed Authorization header. Use: Bearer <api_key>',
                array( 'status' => 401 ) );
        }

        $provided_key = substr( $header, 7 );
        if ( empty( $provided_key ) ) {
            return new WP_Error( 'cw_mcp_empty_key', 'API key is empty.', array( 'status' => 401 ) );
        }

        $keys = self::get_keys();
        if ( empty( $keys ) ) {
            return new WP_Error( 'cw_mcp_no_keys',
                'No API keys configured. Visit Settings > Cloudways MCP in wp-admin.',
                array( 'status' => 401 ) );
        }

        $provided_hash = hash( 'sha256', $provided_key );

        foreach ( $keys as $key_id => &$key_data ) {
            if ( ! hash_equals( $key_data['hash'], $provided_hash ) ) {
                continue;
            }
            if ( ! empty( $key_data['expires_at'] ) && time() > $key_data['expires_at'] ) {
                return new WP_Error( 'cw_mcp_key_expired',
                    'API key has expired. Generate a new one in Settings > Cloudways MCP.',
                    array( 'status' => 401 ) );
            }
            $key_data['last_used_at'] = time();
            $key_data['last_used_ip'] = self::get_client_ip();
            update_option( self::KEYS_OPTION, $keys );
            return (int) $key_data['user_id'];
        }

        return new WP_Error( 'cw_mcp_invalid_key', 'Invalid API key.', array( 'status' => 401 ) );
    }

    public static function generate_key( int $user_id, string $label = 'Default', int $expires_days = 0 ): string {
        $raw_key  = bin2hex( random_bytes( 32 ) );
        $key_hash = hash( 'sha256', $raw_key );
        $key_id   = substr( $key_hash, 0, 12 );

        $keys = self::get_keys();
        $keys[ $key_id ] = array(
            'hash'         => $key_hash,
            'label'        => sanitize_text_field( $label ),
            'user_id'      => $user_id,
            'created_at'   => time(),
            'expires_at'   => $expires_days > 0 ? time() + ( $expires_days * DAY_IN_SECONDS ) : 0,
            'last_used_at' => 0,
            'last_used_ip' => '',
        );
        update_option( self::KEYS_OPTION, $keys );
        return $raw_key;
    }

    public static function revoke_key( string $key_id ): bool {
        $keys = self::get_keys();
        if ( ! isset( $keys[ $key_id ] ) ) {
            return false;
        }
        unset( $keys[ $key_id ] );
        update_option( self::KEYS_OPTION, $keys );
        return true;
    }

    public static function get_keys(): array {
        $keys = get_option( self::KEYS_OPTION, array() );
        return is_array( $keys ) ? $keys : array();
    }

    public static function maybe_generate_default_key(): string {
        if ( ! empty( self::get_keys() ) ) {
            return '';
        }
        $admin_users = get_users( array( 'role' => 'administrator', 'number' => 1, 'orderby' => 'ID', 'order' => 'ASC' ) );
        $user_id = ! empty( $admin_users ) ? $admin_users[0]->ID : 1;
        return self::generate_key( $user_id, 'Default (auto-generated)', 90 );
    }

    private static function get_client_ip(): string {
        $ip = '';
        if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            $parts = explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
            $ip = trim( $parts[0] );
        } elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        }
        return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
    }
}

// ============================================================================
// Security (HTTPS enforcement, IP allowlist, replay protection)
// ============================================================================

class CW_MCP_Security {

    const SETTINGS_OPTION    = 'cw_mcp_security_settings';
    const NONCE_TRANSIENT_PX = 'cw_mcp_nonce_';
    const TIMESTAMP_WINDOW   = 300;

    public function check( WP_REST_Request $request ) {
        $ssl = $this->enforce_https();
        if ( is_wp_error( $ssl ) ) return $ssl;

        $ip = $this->check_ip_allowlist();
        if ( is_wp_error( $ip ) ) return $ip;

        $replay = $this->check_replay( $request );
        if ( is_wp_error( $replay ) ) return $replay;

        return true;
    }

    private function enforce_https() {
        if ( is_ssl() ) return true;

        $host = isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : '';
        if ( in_array( $host, array( 'localhost', '127.0.0.1', '::1' ), true ) ) return true;

        if ( ! empty( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https' ) return true;

        $settings = self::get_settings();
        if ( ! empty( $settings['allow_http'] ) ) return true;

        return new WP_Error( 'cw_mcp_ssl_required', 'MCP endpoint requires HTTPS.', array( 'status' => 403 ) );
    }

    private function check_ip_allowlist() {
        $settings  = self::get_settings();
        $allowlist = ! empty( $settings['ip_allowlist'] ) ? $settings['ip_allowlist'] : array();
        if ( empty( $allowlist ) ) return true;

        $client_ip = self::get_client_ip();
        foreach ( $allowlist as $allowed ) {
            if ( self::ip_matches( $client_ip, trim( $allowed ) ) ) return true;
        }
        return new WP_Error( 'cw_mcp_ip_blocked', 'Your IP address is not in the allowlist.', array( 'status' => 403 ) );
    }

    private function check_replay( WP_REST_Request $request ) {
        $settings = self::get_settings();
        if ( empty( $settings['replay_protection'] ) ) return true;

        $timestamp = $request->get_header( 'X-MCP-Timestamp' );
        if ( $timestamp && abs( time() - (int) $timestamp ) > self::TIMESTAMP_WINDOW ) {
            return new WP_Error( 'cw_mcp_stale_request', 'Request timestamp is too old or too far in the future.', array( 'status' => 400 ) );
        }

        $nonce = $request->get_header( 'X-MCP-Nonce' );
        if ( $nonce ) {
            $nonce_key = self::NONCE_TRANSIENT_PX . hash( 'sha256', $nonce );
            if ( get_transient( $nonce_key ) ) {
                return new WP_Error( 'cw_mcp_replay_detected', 'This request nonce has already been used.', array( 'status' => 400 ) );
            }
            set_transient( $nonce_key, 1, self::TIMESTAMP_WINDOW );
        }
        return true;
    }

    public static function get_settings(): array {
        return wp_parse_args( get_option( self::SETTINGS_OPTION, array() ), array(
            'allow_http'        => false,
            'replay_protection' => true,
            'ip_allowlist'      => array(),
        ) );
    }

    public static function update_settings( array $settings ): void {
        update_option( self::SETTINGS_OPTION, $settings );
    }

    public static function get_client_ip(): string {
        if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            $parts = explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
            $ip = trim( $parts[0] );
        } elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        } else {
            $ip = '';
        }
        return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
    }

    private static function ip_matches( string $ip, string $range ): bool {
        if ( $ip === $range ) return true;
        if ( strpos( $range, '/' ) !== false ) {
            list( $subnet, $bits ) = explode( '/', $range );
            $mask = -1 << ( 32 - (int) $bits );
            return ( ip2long( $ip ) & $mask ) === ( ip2long( $subnet ) & $mask );
        }
        return false;
    }
}

// ============================================================================
// Rate Limiter
// ============================================================================

class CW_MCP_Rate_Limiter {

    const OPTION_KEY       = 'cw_mcp_rate_limit_settings';
    const TRANSIENT_PREFIX = 'cw_mcp_rl_';

    public function check( WP_REST_Request $request ) {
        $settings = self::get_settings();
        if ( empty( $settings['enabled'] ) ) return true;

        $key          = self::get_rate_key( $request );
        $window       = (int) $settings['window_seconds'];
        $max_requests = (int) $settings['max_requests'];
        $tkey         = self::TRANSIENT_PREFIX . md5( $key );
        $data         = get_transient( $tkey );

        if ( false === $data ) {
            set_transient( $tkey, array( 'count' => 1, 'window_start' => time() ), $window );
            return true;
        }

        if ( $data['count'] >= $max_requests ) {
            $retry_after = $window - ( time() - $data['window_start'] );
            return new WP_Error( 'cw_mcp_rate_limited',
                sprintf( 'Rate limit exceeded. Try again in %d seconds.', max( 1, $retry_after ) ),
                array( 'status' => 429, 'headers' => array(
                    'Retry-After'          => max( 1, $retry_after ),
                    'X-RateLimit-Limit'    => $max_requests,
                    'X-RateLimit-Remaining' => 0,
                ) ) );
        }

        $data['count']++;
        set_transient( $tkey, $data, max( 1, $window - ( time() - $data['window_start'] ) ) );
        return true;
    }

    private static function get_rate_key( WP_REST_Request $request ): string {
        $auth = $request->get_header( 'Authorization' );
        return ( $auth ? hash( 'sha256', $auth ) : 'anon' ) . ':' . CW_MCP_Security::get_client_ip();
    }

    public static function get_settings(): array {
        return wp_parse_args( get_option( self::OPTION_KEY, array() ), array(
            'enabled' => true, 'max_requests' => 60, 'window_seconds' => 60,
        ) );
    }

    public static function update_settings( array $s ): void {
        update_option( self::OPTION_KEY, $s );
    }
}

// ============================================================================
// Audit Log (custom DB table, 30-day auto-prune)
// ============================================================================

class CW_MCP_Audit_Log {

    const TABLE_SUFFIX   = 'cw_mcp_audit_log';
    const RETENTION_DAYS = 30;
    const PRUNE_KEY      = 'cw_mcp_last_prune';

    public function log( string $tool, array $params, string $status, string $ip, int $uid ): void {
        global $wpdb;
        $safe = $params;
        foreach ( array( 'password', 'secret', 'token', 'key' ) as $k ) {
            if ( isset( $safe[ $k ] ) ) $safe[ $k ] = '***REDACTED***';
        }
        $wpdb->insert( self::table_name(), array(
            'tool_name' => sanitize_text_field( $tool ), 'params' => wp_json_encode( $safe ),
            'result_status' => sanitize_text_field( $status ), 'client_ip' => sanitize_text_field( $ip ),
            'user_id' => $uid, 'created_at' => current_time( 'mysql', true ),
        ), array( '%s', '%s', '%s', '%s', '%d', '%s' ) );
        $this->maybe_prune();
    }

    public function get_entries( int $limit = 50, int $offset = 0 ): array {
        global $wpdb;
        $t = self::table_name();
        return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$t} ORDER BY id DESC LIMIT %d OFFSET %d", $limit, $offset ), ARRAY_A );
    }

    private function maybe_prune(): void {
        $last = get_option( self::PRUNE_KEY, 0 );
        if ( time() - $last < DAY_IN_SECONDS ) return;
        global $wpdb;
        $wpdb->query( $wpdb->prepare( "DELETE FROM " . self::table_name() . " WHERE created_at < %s",
            gmdate( 'Y-m-d H:i:s', time() - ( self::RETENTION_DAYS * DAY_IN_SECONDS ) ) ) );
        update_option( self::PRUNE_KEY, time() );
    }

    public static function create_table(): void {
        global $wpdb;
        $t = self::table_name();
        $c = $wpdb->get_charset_collate();
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( "CREATE TABLE IF NOT EXISTS {$t} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            tool_name VARCHAR(100) NOT NULL,
            params LONGTEXT,
            result_status VARCHAR(20) NOT NULL DEFAULT 'success',
            client_ip VARCHAR(45) NOT NULL DEFAULT '',
            user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            KEY idx_created_at (created_at),
            KEY idx_tool_name (tool_name)
        ) {$c};" );
    }

    public static function table_name(): string {
        global $wpdb;
        return $wpdb->prefix . self::TABLE_SUFFIX;
    }
}

// ============================================================================
// Tool Provider Interface & Registry
// ============================================================================

interface CW_MCP_Tool_Provider {
    public function get_tools(): array;
    public function call( string $tool_name, array $arguments );
    public function get_required_capability( string $tool_name ): string;
}

class CW_MCP_Tools {

    private array $providers = array();
    private array $tool_map  = array();

    public function register_provider( CW_MCP_Tool_Provider $p ): void {
        $this->providers[] = $p;
        foreach ( $p->get_tools() as $t ) {
            $this->tool_map[ $t['name'] ] = $p;
        }
    }

    public function list_tools(): array {
        $tools = array();
        foreach ( $this->providers as $p ) {
            foreach ( $p->get_tools() as $t ) {
                $entry = array( 'name' => $t['name'], 'description' => $t['description'], 'inputSchema' => $t['inputSchema'] );
                if ( ! empty( $t['annotations'] ) ) $entry['annotations'] = $t['annotations'];
                $tools[] = $entry;
            }
        }
        return $tools;
    }

    public function get_tool_meta( string $name ): ?array {
        if ( ! isset( $this->tool_map[ $name ] ) ) return null;
        foreach ( $this->tool_map[ $name ]->get_tools() as $t ) {
            if ( $t['name'] === $name ) return $t;
        }
        return null;
    }

    public function call_tool( string $name, array $args ) {
        if ( ! isset( $this->tool_map[ $name ] ) ) {
            return new WP_Error( 'cw_mcp_unknown_tool', "Unknown tool: {$name}" );
        }
        $p   = $this->tool_map[ $name ];
        $cap = $p->get_required_capability( $name );
        if ( ! current_user_can( $cap ) ) {
            return new WP_Error( 'cw_mcp_capability_denied',
                "The API key's bound user does not have the '{$cap}' capability required for '{$name}'." );
        }
        return $p->call( $name, $args );
    }
}

// ============================================================================
// MCP Resources
// ============================================================================

class CW_MCP_Resources {

    public function list_resources(): array {
        return array(
            array( 'uri' => 'wordpress://site/info', 'name' => 'Site Information', 'description' => 'WordPress site name, URL, version, and configuration details.', 'mimeType' => 'application/json' ),
            array( 'uri' => 'wordpress://posts/recent', 'name' => 'Recent Posts', 'description' => 'The 10 most recently published posts.', 'mimeType' => 'application/json' ),
            array( 'uri' => 'wordpress://plugins/active', 'name' => 'Active Plugins', 'description' => 'List of currently active plugins.', 'mimeType' => 'application/json' ),
            array( 'uri' => 'wordpress://theme/active', 'name' => 'Active Theme', 'description' => 'Information about the currently active theme.', 'mimeType' => 'application/json' ),
        );
    }

    public function list_templates(): array {
        return array(
            array( 'uriTemplate' => 'wordpress://posts/{id}', 'name' => 'Post by ID', 'description' => 'Get a single post by its ID.', 'mimeType' => 'application/json' ),
            array( 'uriTemplate' => 'wordpress://pages/{id}', 'name' => 'Page by ID', 'description' => 'Get a single page by its ID.', 'mimeType' => 'application/json' ),
        );
    }

    public function read_resource( string $uri ) {
        if ( strpos( $uri, 'wordpress://' ) !== 0 ) {
            return new WP_Error( 'invalid_uri', 'URI must start with wordpress://' );
        }
        $path  = substr( $uri, strlen( 'wordpress://' ) );
        $parts = explode( '/', $path, 2 );
        $type  = $parts[0] ?? '';
        $id    = $parts[1] ?? '';

        switch ( $type ) {
            case 'site':    return $this->read_site_info();
            case 'posts':   return $id === 'recent' ? $this->read_recent_posts() : $this->read_post( (int) $id );
            case 'pages':   return $this->read_page( (int) $id );
            case 'plugins': return $this->read_active_plugins();
            case 'theme':   return $this->read_active_theme();
            default:        return new WP_Error( 'unknown_resource', "Unknown resource type: {$type}" );
        }
    }

    private function read_site_info(): array {
        $d = array_merge( CW_MCP_Site_ID::get_identity(), array(
            'description' => get_bloginfo( 'description' ), 'admin_email' => get_option( 'admin_email' ),
            'timezone' => get_option( 'timezone_string' ) ?: 'UTC', 'language' => get_locale(),
            'php_version' => PHP_VERSION, 'permalink_structure' => get_option( 'permalink_structure' ), 'is_multisite' => is_multisite(),
        ) );
        return array( array( 'uri' => 'wordpress://site/info', 'mimeType' => 'application/json', 'text' => wp_json_encode( $d, JSON_PRETTY_PRINT ) ) );
    }

    private function read_recent_posts(): array {
        $posts = get_posts( array( 'numberposts' => 10, 'post_status' => 'publish' ) );
        $d = array_map( function( $p ) {
            return array( 'id' => $p->ID, 'title' => $p->post_title, 'date' => $p->post_date, 'status' => $p->post_status,
                'excerpt' => wp_trim_words( $p->post_content, 30 ), 'url' => get_permalink( $p->ID ) );
        }, $posts );
        return array( array( 'uri' => 'wordpress://posts/recent', 'mimeType' => 'application/json', 'text' => wp_json_encode( $d, JSON_PRETTY_PRINT ) ) );
    }

    private function read_post( int $id ) {
        $p = get_post( $id );
        if ( ! $p ) return new WP_Error( 'not_found', "Post {$id} not found." );
        $d = array( 'id' => $p->ID, 'title' => $p->post_title, 'content' => $p->post_content, 'excerpt' => $p->post_excerpt,
            'status' => $p->post_status, 'date' => $p->post_date, 'modified' => $p->post_modified,
            'author' => get_the_author_meta( 'display_name', $p->post_author ), 'url' => get_permalink( $p->ID ),
            'categories' => wp_get_post_categories( $p->ID, array( 'fields' => 'names' ) ),
            'tags' => wp_get_post_tags( $p->ID, array( 'fields' => 'names' ) ),
            'featured_image' => get_the_post_thumbnail_url( $p->ID, 'full' ) );
        return array( array( 'uri' => "wordpress://posts/{$id}", 'mimeType' => 'application/json', 'text' => wp_json_encode( $d, JSON_PRETTY_PRINT ) ) );
    }

    private function read_page( int $id ) {
        $p = get_post( $id );
        if ( ! $p || $p->post_type !== 'page' ) return new WP_Error( 'not_found', "Page {$id} not found." );
        $d = array( 'id' => $p->ID, 'title' => $p->post_title, 'content' => $p->post_content, 'status' => $p->post_status,
            'date' => $p->post_date, 'modified' => $p->post_modified, 'url' => get_permalink( $p->ID ),
            'template' => get_page_template_slug( $p->ID ), 'parent' => $p->post_parent );
        return array( array( 'uri' => "wordpress://pages/{$id}", 'mimeType' => 'application/json', 'text' => wp_json_encode( $d, JSON_PRETTY_PRINT ) ) );
    }

    private function read_active_plugins(): array {
        if ( ! function_exists( 'get_plugins' ) ) require_once ABSPATH . 'wp-admin/includes/plugin.php';
        $active = get_option( 'active_plugins', array() );
        $all    = get_plugins();
        $d      = array();
        foreach ( $active as $f ) {
            if ( isset( $all[ $f ] ) ) $d[] = array( 'file' => $f, 'name' => $all[ $f ]['Name'], 'version' => $all[ $f ]['Version'], 'author' => $all[ $f ]['Author'] );
        }
        return array( array( 'uri' => 'wordpress://plugins/active', 'mimeType' => 'application/json', 'text' => wp_json_encode( $d, JSON_PRETTY_PRINT ) ) );
    }

    private function read_active_theme(): array {
        $t = wp_get_theme();
        $d = array( 'name' => $t->get( 'Name' ), 'version' => $t->get( 'Version' ), 'author' => $t->get( 'Author' ),
            'template' => $t->get_template(), 'stylesheet' => $t->get_stylesheet(),
            'parent' => $t->parent() ? $t->parent()->get( 'Name' ) : null );
        return array( array( 'uri' => 'wordpress://theme/active', 'mimeType' => 'application/json', 'text' => wp_json_encode( $d, JSON_PRETTY_PRINT ) ) );
    }
}

// ============================================================================
// MCP Server (JSON-RPC 2.0 / Streamable HTTP)
// ============================================================================

class CW_MCP_Server {

    const NAMESPACE        = 'cw-mcp/v1';
    const ROUTE            = '/mcp';
    const PROTOCOL_VERSION = '2025-03-26';

    private CW_MCP_Auth $auth;
    private CW_MCP_Security $security;
    private CW_MCP_Rate_Limiter $rate_limiter;
    private CW_MCP_Audit_Log $audit;
    private CW_MCP_Tools $tools;
    private CW_MCP_Resources $resources;

    public function __construct( CW_MCP_Auth $auth, CW_MCP_Security $security, CW_MCP_Rate_Limiter $rl, CW_MCP_Audit_Log $audit, CW_MCP_Tools $tools, CW_MCP_Resources $res ) {
        $this->auth = $auth; $this->security = $security; $this->rate_limiter = $rl;
        $this->audit = $audit; $this->tools = $tools; $this->resources = $res;
    }

    public function register_routes(): void {
        register_rest_route( self::NAMESPACE, self::ROUTE, array(
            'methods' => 'POST', 'callback' => array( $this, 'handle_request' ), 'permission_callback' => '__return_true',
        ) );
    }

    public function handle_request( WP_REST_Request $request ): WP_REST_Response {
        $sc = $this->security->check( $request );
        if ( is_wp_error( $sc ) ) return $this->error_response( $sc, null );

        $rc = $this->rate_limiter->check( $request );
        if ( is_wp_error( $rc ) ) return $this->error_response( $rc, null );

        $body = $request->get_json_params();
        if ( empty( $body ) || ! isset( $body['jsonrpc'] ) || $body['jsonrpc'] !== '2.0' ) {
            return $this->jsonrpc_error( -32600, 'Invalid JSON-RPC 2.0 request.', $body['id'] ?? null );
        }

        $method = $body['method'] ?? '';
        $params = $body['params'] ?? array();
        $rpc_id = $body['id'] ?? null;

        if ( $method === 'initialize' )              return $this->handle_initialize( $params, $rpc_id );
        if ( $method === 'notifications/initialized' ) return new WP_REST_Response( null, 204 );
        if ( $method === 'ping' )                    return $this->jsonrpc_success( array(), $rpc_id );

        $user_id = $this->auth->authenticate( $request );
        if ( is_wp_error( $user_id ) ) return $this->error_response( $user_id, $rpc_id );
        wp_set_current_user( $user_id );

        switch ( $method ) {
            case 'tools/list':              return $this->handle_tools_list( $params, $rpc_id );
            case 'tools/call':              return $this->handle_tools_call( $params, $rpc_id, $request );
            case 'resources/list':          return $this->handle_resources_list( $params, $rpc_id );
            case 'resources/read':          return $this->handle_resources_read( $params, $rpc_id );
            case 'resources/templates/list': return $this->handle_resource_templates_list( $params, $rpc_id );
            default:                        return $this->jsonrpc_error( -32601, "Method not found: {$method}", $rpc_id );
        }
    }

    private function handle_initialize( array $params, $rpc_id ): WP_REST_Response {
        $id = CW_MCP_Site_ID::get_identity();
        return $this->jsonrpc_success( array(
            'protocolVersion' => self::PROTOCOL_VERSION,
            'capabilities'    => array( 'tools' => array( 'listChanged' => false ), 'resources' => array( 'subscribe' => false, 'listChanged' => false ) ),
            'serverInfo'      => array( 'name' => 'Cloudways WP MCP - ' . $id['site_name'], 'version' => CW_MCP_VERSION ),
            'instructions'    => sprintf( 'This MCP server manages the WordPress site "%s" at %s. Use the available tools to create, read, update, and delete WordPress content, manage plugins, themes, users, and site settings. Site ID: %s. WordPress %s.',
                $id['site_name'], $id['site_url'], $id['site_id'], $id['wp_version'] ),
        ), $rpc_id );
    }

    private function handle_tools_list( array $params, $rpc_id ): WP_REST_Response {
        $s = get_option( 'cw_mcp_tool_settings', array() );
        $disabled = ! empty( $s['disabled_tools'] ) ? $s['disabled_tools'] : array();
        $filtered = array();
        foreach ( $this->tools->list_tools() as $t ) {
            if ( ! in_array( $t['name'], $disabled, true ) ) $filtered[] = $t;
        }
        return $this->jsonrpc_success( array( 'tools' => $filtered ), $rpc_id );
    }

    private function handle_tools_call( array $params, $rpc_id, WP_REST_Request $request ): WP_REST_Response {
        $tool_name = $params['name'] ?? '';
        $tool_args = $params['arguments'] ?? array();
        if ( empty( $tool_name ) ) return $this->jsonrpc_error( -32602, 'Missing tool name.', $rpc_id );

        $s = get_option( 'cw_mcp_tool_settings', array() );
        $disabled = ! empty( $s['disabled_tools'] ) ? $s['disabled_tools'] : array();
        if ( in_array( $tool_name, $disabled, true ) ) return $this->jsonrpc_error( -32601, "Tool '{$tool_name}' is disabled.", $rpc_id );

        $meta = $this->tools->get_tool_meta( $tool_name );
        if ( $meta && ! empty( $meta['annotations']['destructiveHint'] ) && ! empty( $s['require_confirmation'] ) ) {
            $confirmation = $tool_args['_confirmation_token'] ?? '';
            $expected     = hash( 'sha256', $tool_name . ':' . wp_json_encode( $tool_args ) . ':' . date( 'Y-m-d-H' ) );
            if ( $confirmation !== $expected ) {
                return $this->jsonrpc_success( array( 'content' => array( array( 'type' => 'text',
                    'text' => "This is a destructive operation. To confirm, re-call with _confirmation_token: {$expected}" ) ), 'isError' => true ), $rpc_id );
            }
            unset( $tool_args['_confirmation_token'] );
        }

        $result = $this->tools->call_tool( $tool_name, $tool_args );
        $this->audit->log( $tool_name, $tool_args, is_wp_error( $result ) ? 'error' : 'success', CW_MCP_Security::get_client_ip(), get_current_user_id() );

        if ( is_wp_error( $result ) ) {
            return $this->jsonrpc_success( array( 'content' => array( array( 'type' => 'text', 'text' => $result->get_error_message() ) ), 'isError' => true ), $rpc_id );
        }
        return $this->jsonrpc_success( array( 'content' => $this->normalize( $result ) ), $rpc_id );
    }

    private function handle_resources_list( array $params, $rpc_id ): WP_REST_Response {
        return $this->jsonrpc_success( array( 'resources' => $this->resources->list_resources() ), $rpc_id );
    }

    private function handle_resources_read( array $params, $rpc_id ): WP_REST_Response {
        $uri = $params['uri'] ?? '';
        if ( empty( $uri ) ) return $this->jsonrpc_error( -32602, 'Missing resource URI.', $rpc_id );
        $r = $this->resources->read_resource( $uri );
        if ( is_wp_error( $r ) ) return $this->jsonrpc_error( -32002, $r->get_error_message(), $rpc_id );
        return $this->jsonrpc_success( array( 'contents' => $r ), $rpc_id );
    }

    private function handle_resource_templates_list( array $params, $rpc_id ): WP_REST_Response {
        return $this->jsonrpc_success( array( 'resourceTemplates' => $this->resources->list_templates() ), $rpc_id );
    }

    private function jsonrpc_success( $result, $id ): WP_REST_Response {
        return new WP_REST_Response( array( 'jsonrpc' => '2.0', 'id' => $id, 'result' => $result ), 200 );
    }

    private function jsonrpc_error( int $code, string $msg, $id ): WP_REST_Response {
        return new WP_REST_Response( array( 'jsonrpc' => '2.0', 'id' => $id, 'error' => array( 'code' => $code, 'message' => $msg ) ), 200 );
    }

    private function error_response( WP_Error $e, $id ): WP_REST_Response {
        $d = $e->get_error_data();
        $status = is_array( $d ) && isset( $d['status'] ) ? $d['status'] : 500;
        $r = new WP_REST_Response( array( 'jsonrpc' => '2.0', 'id' => $id, 'error' => array( 'code' => -32000, 'message' => $e->get_error_message() ) ), $status );
        if ( is_array( $d ) && ! empty( $d['headers'] ) ) {
            foreach ( $d['headers'] as $h => $v ) $r->header( $h, $v );
        }
        return $r;
    }

    private function normalize( $result ): array {
        if ( is_string( $result ) ) return array( array( 'type' => 'text', 'text' => $result ) );
        if ( is_array( $result ) || is_object( $result ) ) return array( array( 'type' => 'text', 'text' => wp_json_encode( $result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) ) );
        return array( array( 'type' => 'text', 'text' => (string) $result ) );
    }
}

// ============================================================================
// Tool: Posts (get_posts, get_post, create, update, delete)
// ============================================================================

class CW_MCP_Tool_Posts implements CW_MCP_Tool_Provider {

    public function get_tools(): array {
        return array(
            array( 'name' => 'wp_get_posts', 'description' => 'List or search WordPress posts. Returns titles, IDs, statuses, dates, and excerpts.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array(
                    'search' => array( 'type' => 'string', 'description' => 'Search keyword.' ),
                    'status' => array( 'type' => 'string', 'description' => 'Post status: publish, draft, pending, private, trash, any.', 'default' => 'any' ),
                    'per_page' => array( 'type' => 'integer', 'description' => 'Number of posts (max 100).', 'default' => 10 ),
                    'page' => array( 'type' => 'integer', 'default' => 1 ),
                    'category' => array( 'type' => 'string', 'description' => 'Filter by category slug.' ),
                    'tag' => array( 'type' => 'string', 'description' => 'Filter by tag slug.' ),
                    'orderby' => array( 'type' => 'string', 'default' => 'date' ),
                    'order' => array( 'type' => 'string', 'default' => 'DESC' ),
                ) ), 'annotations' => array( 'readOnlyHint' => true ) ),
            array( 'name' => 'wp_get_post', 'description' => 'Get a single WordPress post by ID with full content.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'id' => array( 'type' => 'integer' ) ), 'required' => array( 'id' ) ),
                'annotations' => array( 'readOnlyHint' => true ) ),
            array( 'name' => 'wp_create_post', 'description' => 'Create a new WordPress post.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array(
                    'title' => array( 'type' => 'string' ), 'content' => array( 'type' => 'string' ),
                    'status' => array( 'type' => 'string', 'default' => 'draft' ), 'excerpt' => array( 'type' => 'string' ),
                    'categories' => array( 'type' => 'array', 'items' => array( 'type' => 'integer' ) ),
                    'tags' => array( 'type' => 'array', 'items' => array( 'type' => 'string' ) ),
                ), 'required' => array( 'title' ) ) ),
            array( 'name' => 'wp_update_post', 'description' => 'Update an existing WordPress post.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array(
                    'id' => array( 'type' => 'integer' ), 'title' => array( 'type' => 'string' ),
                    'content' => array( 'type' => 'string' ), 'status' => array( 'type' => 'string' ),
                    'excerpt' => array( 'type' => 'string' ), 'categories' => array( 'type' => 'array', 'items' => array( 'type' => 'integer' ) ),
                    'tags' => array( 'type' => 'array', 'items' => array( 'type' => 'string' ) ),
                ), 'required' => array( 'id' ) ) ),
            array( 'name' => 'wp_delete_post', 'description' => 'Move a WordPress post to trash or permanently delete it.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array(
                    'id' => array( 'type' => 'integer' ), 'force' => array( 'type' => 'boolean', 'default' => false ),
                ), 'required' => array( 'id' ) ), 'annotations' => array( 'destructiveHint' => true ) ),
        );
    }

    public function call( string $n, array $a ) {
        switch ( $n ) {
            case 'wp_get_posts':   return $this->get_posts( $a );
            case 'wp_get_post':    return $this->get_post( $a );
            case 'wp_create_post': return $this->create_post( $a );
            case 'wp_update_post': return $this->update_post( $a );
            case 'wp_delete_post': return $this->delete_post( $a );
        }
        return new WP_Error( 'unknown_tool', "Unknown tool: {$n}" );
    }

    public function get_required_capability( string $n ): string {
        return in_array( $n, array( 'wp_get_posts', 'wp_get_post' ) ) ? 'read' : ( $n === 'wp_delete_post' ? 'delete_posts' : 'edit_posts' );
    }

    private function get_posts( array $a ): array {
        $qa = array( 'post_type' => 'post', 'post_status' => sanitize_text_field( $a['status'] ?? 'any' ),
            'posts_per_page' => min( (int) ( $a['per_page'] ?? 10 ), 100 ), 'paged' => max( (int) ( $a['page'] ?? 1 ), 1 ),
            'orderby' => sanitize_text_field( $a['orderby'] ?? 'date' ), 'order' => strtoupper( $a['order'] ?? 'DESC' ) === 'ASC' ? 'ASC' : 'DESC' );
        if ( ! empty( $a['search'] ) )   $qa['s'] = sanitize_text_field( $a['search'] );
        if ( ! empty( $a['category'] ) ) $qa['category_name'] = sanitize_text_field( $a['category'] );
        if ( ! empty( $a['tag'] ) )      $qa['tag'] = sanitize_text_field( $a['tag'] );
        $q = new WP_Query( $qa );
        $posts = array();
        foreach ( $q->posts as $p ) {
            $posts[] = array( 'id' => $p->ID, 'title' => $p->post_title, 'status' => $p->post_status, 'date' => $p->post_date,
                'modified' => $p->post_modified, 'excerpt' => wp_trim_words( $p->post_content, 30 ), 'url' => get_permalink( $p->ID ),
                'author' => get_the_author_meta( 'display_name', $p->post_author ) );
        }
        return array( 'posts' => $posts, 'total' => $q->found_posts, 'total_pages' => $q->max_num_pages, 'page' => $qa['paged'] );
    }

    private function get_post( array $a ) {
        $p = get_post( (int) $a['id'] );
        if ( ! $p || $p->post_type !== 'post' ) return new WP_Error( 'not_found', 'Post not found.' );
        return array( 'id' => $p->ID, 'title' => $p->post_title, 'content' => $p->post_content, 'excerpt' => $p->post_excerpt,
            'status' => $p->post_status, 'date' => $p->post_date, 'modified' => $p->post_modified,
            'author' => get_the_author_meta( 'display_name', $p->post_author ), 'url' => get_permalink( $p->ID ),
            'categories' => wp_get_post_categories( $p->ID, array( 'fields' => 'names' ) ),
            'tags' => wp_get_post_tags( $p->ID, array( 'fields' => 'names' ) ),
            'featured_image' => get_the_post_thumbnail_url( $p->ID, 'full' ), 'comment_count' => (int) $p->comment_count );
    }

    private function create_post( array $a ) {
        $pd = array( 'post_title' => sanitize_text_field( $a['title'] ), 'post_content' => wp_kses_post( $a['content'] ?? '' ),
            'post_status' => sanitize_text_field( $a['status'] ?? 'draft' ), 'post_excerpt' => sanitize_textarea_field( $a['excerpt'] ?? '' ), 'post_type' => 'post' );
        $id = wp_insert_post( $pd, true );
        if ( is_wp_error( $id ) ) return $id;
        if ( ! empty( $a['categories'] ) ) wp_set_post_categories( $id, array_map( 'intval', $a['categories'] ) );
        if ( ! empty( $a['tags'] ) )       wp_set_post_tags( $id, array_map( 'sanitize_text_field', $a['tags'] ) );
        return array( 'id' => $id, 'title' => $pd['post_title'], 'status' => $pd['post_status'], 'url' => get_permalink( $id ) );
    }

    private function update_post( array $a ) {
        $p = get_post( (int) $a['id'] );
        if ( ! $p ) return new WP_Error( 'not_found', 'Post not found.' );
        $pd = array( 'ID' => $p->ID );
        if ( isset( $a['title'] ) )   $pd['post_title']   = sanitize_text_field( $a['title'] );
        if ( isset( $a['content'] ) ) $pd['post_content'] = wp_kses_post( $a['content'] );
        if ( isset( $a['status'] ) )  $pd['post_status']  = sanitize_text_field( $a['status'] );
        if ( isset( $a['excerpt'] ) ) $pd['post_excerpt'] = sanitize_textarea_field( $a['excerpt'] );
        $r = wp_update_post( $pd, true );
        if ( is_wp_error( $r ) ) return $r;
        if ( isset( $a['categories'] ) ) wp_set_post_categories( $p->ID, array_map( 'intval', $a['categories'] ) );
        if ( isset( $a['tags'] ) )       wp_set_post_tags( $p->ID, array_map( 'sanitize_text_field', $a['tags'] ) );
        return array( 'id' => $p->ID, 'updated' => true, 'url' => get_permalink( $p->ID ) );
    }

    private function delete_post( array $a ) {
        $p = get_post( (int) $a['id'] );
        if ( ! $p ) return new WP_Error( 'not_found', 'Post not found.' );
        $force = ! empty( $a['force'] );
        $r = wp_delete_post( $p->ID, $force );
        return $r ? array( 'id' => $p->ID, 'deleted' => true, 'trashed' => ! $force ) : new WP_Error( 'delete_failed', 'Failed to delete the post.' );
    }
}

// ============================================================================
// Tool: Pages
// ============================================================================

class CW_MCP_Tool_Pages implements CW_MCP_Tool_Provider {

    public function get_tools(): array {
        return array(
            array( 'name' => 'wp_get_pages', 'description' => 'List WordPress pages.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'status' => array( 'type' => 'string', 'default' => 'any' ),
                    'per_page' => array( 'type' => 'integer', 'default' => 20 ), 'search' => array( 'type' => 'string' ),
                    'parent' => array( 'type' => 'integer', 'description' => 'Filter by parent page ID.' ) ) ),
                'annotations' => array( 'readOnlyHint' => true ) ),
            array( 'name' => 'wp_create_page', 'description' => 'Create a new WordPress page.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'title' => array( 'type' => 'string' ), 'content' => array( 'type' => 'string' ),
                    'status' => array( 'type' => 'string', 'default' => 'draft' ), 'parent' => array( 'type' => 'integer', 'default' => 0 ),
                    'template' => array( 'type' => 'string' ) ), 'required' => array( 'title' ) ) ),
            array( 'name' => 'wp_update_page', 'description' => 'Update an existing WordPress page.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'id' => array( 'type' => 'integer' ), 'title' => array( 'type' => 'string' ),
                    'content' => array( 'type' => 'string' ), 'status' => array( 'type' => 'string' ), 'parent' => array( 'type' => 'integer' ),
                    'template' => array( 'type' => 'string' ) ), 'required' => array( 'id' ) ) ),
            array( 'name' => 'wp_delete_page', 'description' => 'Trash or permanently delete a page.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'id' => array( 'type' => 'integer' ), 'force' => array( 'type' => 'boolean', 'default' => false ) ),
                    'required' => array( 'id' ) ), 'annotations' => array( 'destructiveHint' => true ) ),
        );
    }

    public function call( string $n, array $a ) {
        switch ( $n ) {
            case 'wp_get_pages':   return $this->get_pages( $a );
            case 'wp_create_page': return $this->create_page( $a );
            case 'wp_update_page': return $this->update_page( $a );
            case 'wp_delete_page': return $this->delete_page( $a );
        }
        return new WP_Error( 'unknown_tool', "Unknown tool: {$n}" );
    }

    public function get_required_capability( string $n ): string {
        return $n === 'wp_get_pages' ? 'read' : ( $n === 'wp_delete_page' ? 'delete_pages' : 'edit_pages' );
    }

    private function get_pages( array $a ): array {
        $qa = array( 'post_type' => 'page', 'post_status' => sanitize_text_field( $a['status'] ?? 'any' ),
            'posts_per_page' => min( (int) ( $a['per_page'] ?? 20 ), 100 ), 'orderby' => 'menu_order title', 'order' => 'ASC' );
        if ( ! empty( $a['search'] ) ) $qa['s'] = sanitize_text_field( $a['search'] );
        if ( isset( $a['parent'] ) )   $qa['post_parent'] = (int) $a['parent'];
        $q = new WP_Query( $qa );
        $pages = array();
        foreach ( $q->posts as $p ) {
            $pages[] = array( 'id' => $p->ID, 'title' => $p->post_title, 'status' => $p->post_status, 'url' => get_permalink( $p->ID ),
                'parent' => $p->post_parent, 'template' => get_page_template_slug( $p->ID ), 'modified' => $p->post_modified );
        }
        return array( 'pages' => $pages, 'total' => $q->found_posts );
    }

    private function create_page( array $a ) {
        $id = wp_insert_post( array( 'post_title' => sanitize_text_field( $a['title'] ), 'post_content' => wp_kses_post( $a['content'] ?? '' ),
            'post_status' => sanitize_text_field( $a['status'] ?? 'draft' ), 'post_type' => 'page', 'post_parent' => (int) ( $a['parent'] ?? 0 ) ), true );
        if ( is_wp_error( $id ) ) return $id;
        if ( ! empty( $a['template'] ) ) update_post_meta( $id, '_wp_page_template', sanitize_text_field( $a['template'] ) );
        return array( 'id' => $id, 'url' => get_permalink( $id ) );
    }

    private function update_page( array $a ) {
        $p = get_post( (int) $a['id'] );
        if ( ! $p || $p->post_type !== 'page' ) return new WP_Error( 'not_found', 'Page not found.' );
        $pd = array( 'ID' => $p->ID );
        if ( isset( $a['title'] ) )   $pd['post_title']   = sanitize_text_field( $a['title'] );
        if ( isset( $a['content'] ) ) $pd['post_content'] = wp_kses_post( $a['content'] );
        if ( isset( $a['status'] ) )  $pd['post_status']  = sanitize_text_field( $a['status'] );
        if ( isset( $a['parent'] ) )  $pd['post_parent']  = (int) $a['parent'];
        $r = wp_update_post( $pd, true );
        if ( is_wp_error( $r ) ) return $r;
        if ( isset( $a['template'] ) ) update_post_meta( $p->ID, '_wp_page_template', sanitize_text_field( $a['template'] ) );
        return array( 'id' => $p->ID, 'updated' => true );
    }

    private function delete_page( array $a ) {
        $p = get_post( (int) $a['id'] );
        if ( ! $p || $p->post_type !== 'page' ) return new WP_Error( 'not_found', 'Page not found.' );
        $r = wp_delete_post( $p->ID, ! empty( $a['force'] ) );
        return $r ? array( 'id' => $p->ID, 'deleted' => true, 'trashed' => empty( $a['force'] ) ) : new WP_Error( 'delete_failed', 'Failed to delete page.' );
    }
}

// ============================================================================
// Tool: Media
// ============================================================================

class CW_MCP_Tool_Media implements CW_MCP_Tool_Provider {

    public function get_tools(): array {
        return array(
            array( 'name' => 'wp_get_media', 'description' => 'List media library items.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'per_page' => array( 'type' => 'integer', 'default' => 20 ),
                    'page' => array( 'type' => 'integer', 'default' => 1 ), 'mime_type' => array( 'type' => 'string' ), 'search' => array( 'type' => 'string' ) ) ),
                'annotations' => array( 'readOnlyHint' => true ) ),
            array( 'name' => 'wp_upload_media', 'description' => 'Upload a file to the media library from a base64-encoded string.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'filename' => array( 'type' => 'string' ), 'data' => array( 'type' => 'string', 'description' => 'Base64-encoded file content.' ),
                    'title' => array( 'type' => 'string' ), 'caption' => array( 'type' => 'string' ), 'alt_text' => array( 'type' => 'string' ) ),
                    'required' => array( 'filename', 'data' ) ) ),
            array( 'name' => 'wp_delete_media', 'description' => 'Permanently delete a media item.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'id' => array( 'type' => 'integer' ) ), 'required' => array( 'id' ) ),
                'annotations' => array( 'destructiveHint' => true ) ),
        );
    }

    public function call( string $n, array $a ) {
        switch ( $n ) {
            case 'wp_get_media':    return $this->get_media( $a );
            case 'wp_upload_media': return $this->upload_media( $a );
            case 'wp_delete_media': return $this->delete_media( $a );
        }
        return new WP_Error( 'unknown_tool', "Unknown tool: {$n}" );
    }

    public function get_required_capability( string $n ): string {
        return $n === 'wp_get_media' ? 'read' : 'upload_files';
    }

    private function get_media( array $a ): array {
        $qa = array( 'post_type' => 'attachment', 'post_status' => 'inherit', 'posts_per_page' => min( (int) ( $a['per_page'] ?? 20 ), 100 ), 'paged' => max( (int) ( $a['page'] ?? 1 ), 1 ) );
        if ( ! empty( $a['mime_type'] ) ) $qa['post_mime_type'] = sanitize_text_field( $a['mime_type'] );
        if ( ! empty( $a['search'] ) )    $qa['s'] = sanitize_text_field( $a['search'] );
        $q = new WP_Query( $qa );
        $items = array();
        foreach ( $q->posts as $i ) {
            $items[] = array( 'id' => $i->ID, 'title' => $i->post_title, 'url' => wp_get_attachment_url( $i->ID ),
                'mime_type' => $i->post_mime_type, 'date' => $i->post_date, 'alt_text' => get_post_meta( $i->ID, '_wp_attachment_image_alt', true ) );
        }
        return array( 'media' => $items, 'total' => $q->found_posts );
    }

    private function upload_media( array $a ) {
        $decoded = base64_decode( $a['data'], true );
        if ( false === $decoded ) return new WP_Error( 'invalid_data', 'Invalid base64 data.' );
        if ( strlen( $decoded ) > 10 * 1024 * 1024 ) return new WP_Error( 'file_too_large', 'File exceeds 10 MB limit.' );
        $filename = sanitize_file_name( $a['filename'] );
        $upload   = wp_upload_bits( $filename, null, $decoded );
        if ( ! empty( $upload['error'] ) ) return new WP_Error( 'upload_failed', $upload['error'] );
        $ft  = wp_check_filetype( $filename );
        $aid = wp_insert_attachment( array( 'post_title' => sanitize_text_field( $a['title'] ?? pathinfo( $filename, PATHINFO_FILENAME ) ),
            'post_content' => '', 'post_status' => 'inherit', 'post_mime_type' => $ft['type'],
            'post_excerpt' => sanitize_textarea_field( $a['caption'] ?? '' ) ), $upload['file'] );
        if ( is_wp_error( $aid ) ) return $aid;
        require_once ABSPATH . 'wp-admin/includes/image.php';
        wp_update_attachment_metadata( $aid, wp_generate_attachment_metadata( $aid, $upload['file'] ) );
        if ( ! empty( $a['alt_text'] ) ) update_post_meta( $aid, '_wp_attachment_image_alt', sanitize_text_field( $a['alt_text'] ) );
        return array( 'id' => $aid, 'url' => wp_get_attachment_url( $aid ) );
    }

    private function delete_media( array $a ) {
        $r = wp_delete_attachment( (int) $a['id'], true );
        return $r ? array( 'id' => (int) $a['id'], 'deleted' => true ) : new WP_Error( 'delete_failed', 'Failed to delete media item.' );
    }
}

// ============================================================================
// Tool: Comments
// ============================================================================

class CW_MCP_Tool_Comments implements CW_MCP_Tool_Provider {

    public function get_tools(): array {
        return array(
            array( 'name' => 'wp_get_comments', 'description' => 'List comments with optional filters.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'post_id' => array( 'type' => 'integer' ),
                    'status' => array( 'type' => 'string', 'default' => 'all' ), 'per_page' => array( 'type' => 'integer', 'default' => 20 ) ) ),
                'annotations' => array( 'readOnlyHint' => true ) ),
            array( 'name' => 'wp_create_comment', 'description' => 'Create a new comment on a post.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'post_id' => array( 'type' => 'integer' ), 'content' => array( 'type' => 'string' ),
                    'author' => array( 'type' => 'string' ), 'email' => array( 'type' => 'string' ) ), 'required' => array( 'post_id', 'content' ) ) ),
            array( 'name' => 'wp_update_comment', 'description' => 'Update a comment (content or status).',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'id' => array( 'type' => 'integer' ),
                    'content' => array( 'type' => 'string' ), 'status' => array( 'type' => 'string' ) ), 'required' => array( 'id' ) ) ),
            array( 'name' => 'wp_delete_comment', 'description' => 'Delete a comment.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'id' => array( 'type' => 'integer' ),
                    'force' => array( 'type' => 'boolean', 'default' => false ) ), 'required' => array( 'id' ) ),
                'annotations' => array( 'destructiveHint' => true ) ),
        );
    }

    public function call( string $n, array $a ) {
        switch ( $n ) {
            case 'wp_get_comments':    return $this->get_comments( $a );
            case 'wp_create_comment':  return $this->create_comment( $a );
            case 'wp_update_comment':  return $this->update_comment( $a );
            case 'wp_delete_comment':  return $this->delete_comment( $a );
        }
        return new WP_Error( 'unknown_tool', "Unknown tool: {$n}" );
    }

    public function get_required_capability( string $n ): string {
        return $n === 'wp_get_comments' ? 'read' : 'moderate_comments';
    }

    private function get_comments( array $a ): array {
        $qa = array( 'number' => min( (int) ( $a['per_page'] ?? 20 ), 100 ), 'status' => sanitize_text_field( $a['status'] ?? 'all' ) );
        if ( ! empty( $a['post_id'] ) ) $qa['post_id'] = (int) $a['post_id'];
        $comments = get_comments( $qa );
        $r = array();
        foreach ( $comments as $c ) {
            $r[] = array( 'id' => (int) $c->comment_ID, 'post_id' => (int) $c->comment_post_ID, 'author' => $c->comment_author,
                'email' => $c->comment_author_email, 'content' => $c->comment_content, 'status' => wp_get_comment_status( $c ), 'date' => $c->comment_date );
        }
        return array( 'comments' => $r );
    }

    private function create_comment( array $a ) {
        $id = wp_insert_comment( array( 'comment_post_ID' => (int) $a['post_id'], 'comment_content' => sanitize_textarea_field( $a['content'] ),
            'comment_author' => sanitize_text_field( $a['author'] ?? 'MCP' ), 'comment_author_email' => sanitize_email( $a['email'] ?? '' ), 'comment_approved' => 1 ) );
        return $id ? array( 'id' => $id ) : new WP_Error( 'create_failed', 'Failed to create comment.' );
    }

    private function update_comment( array $a ) {
        $c = get_comment( (int) $a['id'] );
        if ( ! $c ) return new WP_Error( 'not_found', 'Comment not found.' );
        $d = array( 'comment_ID' => $c->comment_ID );
        if ( isset( $a['content'] ) ) $d['comment_content'] = sanitize_textarea_field( $a['content'] );
        $r = wp_update_comment( $d, true );
        if ( is_wp_error( $r ) ) return $r;
        if ( isset( $a['status'] ) ) wp_set_comment_status( $c->comment_ID, sanitize_text_field( $a['status'] ) );
        return array( 'id' => $c->comment_ID, 'updated' => true );
    }

    private function delete_comment( array $a ) {
        $r = wp_delete_comment( (int) $a['id'], ! empty( $a['force'] ) );
        return $r ? array( 'id' => (int) $a['id'], 'deleted' => true ) : new WP_Error( 'delete_failed', 'Failed to delete comment.' );
    }
}

// ============================================================================
// Tool: Users (read-only)
// ============================================================================

class CW_MCP_Tool_Users implements CW_MCP_Tool_Provider {

    public function get_tools(): array {
        return array( array( 'name' => 'wp_get_users', 'description' => 'List WordPress users with display names, roles, and registration dates.',
            'inputSchema' => array( 'type' => 'object', 'properties' => array( 'role' => array( 'type' => 'string' ), 'search' => array( 'type' => 'string' ),
                'per_page' => array( 'type' => 'integer', 'default' => 20 ), 'page' => array( 'type' => 'integer', 'default' => 1 ) ) ),
            'annotations' => array( 'readOnlyHint' => true ) ) );
    }

    public function call( string $n, array $a ) {
        $qa = array( 'number' => min( (int) ( $a['per_page'] ?? 20 ), 100 ), 'paged' => max( (int) ( $a['page'] ?? 1 ), 1 ) );
        if ( ! empty( $a['role'] ) )   $qa['role'] = sanitize_text_field( $a['role'] );
        if ( ! empty( $a['search'] ) ) { $qa['search'] = '*' . sanitize_text_field( $a['search'] ) . '*'; $qa['search_columns'] = array( 'user_login', 'user_email', 'display_name' ); }
        $uq = new WP_User_Query( $qa );
        $users = array();
        foreach ( $uq->get_results() as $u ) {
            $users[] = array( 'id' => $u->ID, 'username' => $u->user_login, 'display_name' => $u->display_name,
                'email' => $u->user_email, 'roles' => $u->roles, 'registered' => $u->user_registered, 'posts_count' => count_user_posts( $u->ID ) );
        }
        return array( 'users' => $users, 'total' => $uq->get_total() );
    }

    public function get_required_capability( string $n ): string { return 'list_users'; }
}

// ============================================================================
// Tool: Plugins
// ============================================================================

class CW_MCP_Tool_Plugins implements CW_MCP_Tool_Provider {

    public function get_tools(): array {
        return array(
            array( 'name' => 'wp_get_plugins', 'description' => 'List all installed WordPress plugins with their status.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'status' => array( 'type' => 'string', 'default' => 'all' ) ) ),
                'annotations' => array( 'readOnlyHint' => true ) ),
            array( 'name' => 'wp_activate_plugin', 'description' => 'Activate a WordPress plugin by its file path (e.g. akismet/akismet.php).',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'plugin' => array( 'type' => 'string' ) ), 'required' => array( 'plugin' ) ),
                'annotations' => array( 'destructiveHint' => true ) ),
            array( 'name' => 'wp_deactivate_plugin', 'description' => 'Deactivate a WordPress plugin.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'plugin' => array( 'type' => 'string' ) ), 'required' => array( 'plugin' ) ),
                'annotations' => array( 'destructiveHint' => true ) ),
        );
    }

    public function call( string $n, array $a ) {
        if ( ! function_exists( 'get_plugins' ) ) require_once ABSPATH . 'wp-admin/includes/plugin.php';
        switch ( $n ) {
            case 'wp_get_plugins':
                $all = get_plugins(); $active = get_option( 'active_plugins', array() ); $sf = sanitize_text_field( $a['status'] ?? 'all' ); $r = array();
                foreach ( $all as $f => $d ) { $ia = in_array( $f, $active, true ); if ( $sf === 'active' && ! $ia ) continue; if ( $sf === 'inactive' && $ia ) continue;
                    $r[] = array( 'file' => $f, 'name' => $d['Name'], 'version' => $d['Version'], 'author' => $d['Author'], 'description' => $d['Description'], 'active' => $ia ); }
                return array( 'plugins' => $r );
            case 'wp_activate_plugin':
                if ( ! function_exists( 'activate_plugin' ) ) require_once ABSPATH . 'wp-admin/includes/plugin.php';
                $r = activate_plugin( sanitize_text_field( $a['plugin'] ) ); return is_wp_error( $r ) ? $r : array( 'plugin' => $a['plugin'], 'activated' => true );
            case 'wp_deactivate_plugin':
                if ( ! function_exists( 'deactivate_plugins' ) ) require_once ABSPATH . 'wp-admin/includes/plugin.php';
                deactivate_plugins( sanitize_text_field( $a['plugin'] ) ); return array( 'plugin' => $a['plugin'], 'deactivated' => true );
        }
        return new WP_Error( 'unknown_tool', "Unknown tool: {$n}" );
    }

    public function get_required_capability( string $n ): string { return $n === 'wp_get_plugins' ? 'read' : 'activate_plugins'; }
}

// ============================================================================
// Tool: Themes
// ============================================================================

class CW_MCP_Tool_Themes implements CW_MCP_Tool_Provider {

    public function get_tools(): array {
        return array(
            array( 'name' => 'wp_get_themes', 'description' => 'List all installed WordPress themes.',
                'inputSchema' => array( 'type' => 'object', 'properties' => new \stdClass() ), 'annotations' => array( 'readOnlyHint' => true ) ),
            array( 'name' => 'wp_activate_theme', 'description' => 'Switch the active WordPress theme.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'stylesheet' => array( 'type' => 'string' ) ), 'required' => array( 'stylesheet' ) ),
                'annotations' => array( 'destructiveHint' => true ) ),
        );
    }

    public function call( string $n, array $a ) {
        if ( $n === 'wp_get_themes' ) {
            $themes = wp_get_themes(); $as = get_stylesheet(); $r = array();
            foreach ( $themes as $s => $t ) { $r[] = array( 'stylesheet' => $s, 'name' => $t->get( 'Name' ), 'version' => $t->get( 'Version' ),
                'author' => $t->get( 'Author' ), 'active' => $s === $as, 'parent' => $t->parent() ? $t->parent()->get_stylesheet() : null ); }
            return array( 'themes' => $r );
        }
        if ( $n === 'wp_activate_theme' ) {
            $ss = sanitize_text_field( $a['stylesheet'] ); $t = wp_get_theme( $ss );
            if ( ! $t->exists() ) return new WP_Error( 'not_found', "Theme '{$ss}' not found." );
            switch_theme( $ss ); return array( 'stylesheet' => $ss, 'activated' => true );
        }
        return new WP_Error( 'unknown_tool', "Unknown tool: {$n}" );
    }

    public function get_required_capability( string $n ): string { return $n === 'wp_get_themes' ? 'read' : 'switch_themes'; }
}

// ============================================================================
// Tool: Taxonomies (categories & tags)
// ============================================================================

class CW_MCP_Tool_Taxonomies implements CW_MCP_Tool_Provider {

    public function get_tools(): array {
        return array(
            array( 'name' => 'wp_get_categories', 'description' => 'List all categories.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'hide_empty' => array( 'type' => 'boolean', 'default' => false ), 'search' => array( 'type' => 'string' ) ) ),
                'annotations' => array( 'readOnlyHint' => true ) ),
            array( 'name' => 'wp_create_category', 'description' => 'Create a new category.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'name' => array( 'type' => 'string' ), 'slug' => array( 'type' => 'string' ),
                    'description' => array( 'type' => 'string' ), 'parent' => array( 'type' => 'integer', 'default' => 0 ) ), 'required' => array( 'name' ) ) ),
            array( 'name' => 'wp_get_tags', 'description' => 'List all tags.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'hide_empty' => array( 'type' => 'boolean', 'default' => false ), 'search' => array( 'type' => 'string' ),
                    'per_page' => array( 'type' => 'integer', 'default' => 50 ) ) ), 'annotations' => array( 'readOnlyHint' => true ) ),
            array( 'name' => 'wp_create_tag', 'description' => 'Create a new tag.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'name' => array( 'type' => 'string' ), 'slug' => array( 'type' => 'string' ),
                    'description' => array( 'type' => 'string' ) ), 'required' => array( 'name' ) ) ),
        );
    }

    public function call( string $n, array $a ) {
        switch ( $n ) {
            case 'wp_get_categories':
                $terms = get_categories( array( 'hide_empty' => ! empty( $a['hide_empty'] ), 'search' => sanitize_text_field( $a['search'] ?? '' ) ) );
                $r = array(); foreach ( $terms as $t ) { $r[] = array( 'id' => $t->term_id, 'name' => $t->name, 'slug' => $t->slug, 'description' => $t->description, 'parent' => $t->parent, 'count' => $t->count ); }
                return array( 'categories' => $r );
            case 'wp_create_category':
                $r = wp_insert_term( sanitize_text_field( $a['name'] ), 'category', array( 'slug' => sanitize_title( $a['slug'] ?? '' ), 'description' => sanitize_textarea_field( $a['description'] ?? '' ), 'parent' => (int) ( $a['parent'] ?? 0 ) ) );
                return is_wp_error( $r ) ? $r : array( 'id' => $r['term_id'], 'name' => $a['name'] );
            case 'wp_get_tags':
                $terms = get_tags( array( 'hide_empty' => ! empty( $a['hide_empty'] ), 'search' => sanitize_text_field( $a['search'] ?? '' ), 'number' => min( (int) ( $a['per_page'] ?? 50 ), 200 ) ) );
                if ( is_wp_error( $terms ) ) $terms = array();
                $r = array(); foreach ( $terms as $t ) { $r[] = array( 'id' => $t->term_id, 'name' => $t->name, 'slug' => $t->slug, 'count' => $t->count ); }
                return array( 'tags' => $r );
            case 'wp_create_tag':
                $r = wp_insert_term( sanitize_text_field( $a['name'] ), 'post_tag', array( 'slug' => sanitize_title( $a['slug'] ?? '' ), 'description' => sanitize_textarea_field( $a['description'] ?? '' ) ) );
                return is_wp_error( $r ) ? $r : array( 'id' => $r['term_id'], 'name' => $a['name'] );
        }
        return new WP_Error( 'unknown_tool', "Unknown tool: {$n}" );
    }

    public function get_required_capability( string $n ): string { return strpos( $n, 'get_' ) !== false ? 'read' : 'manage_categories'; }
}

// ============================================================================
// Tool: Options (allowlisted)
// ============================================================================

class CW_MCP_Tool_Options implements CW_MCP_Tool_Provider {

    const ALLOWED = array( 'blogname', 'blogdescription', 'siteurl', 'home', 'admin_email', 'timezone_string', 'date_format', 'time_format',
        'start_of_week', 'posts_per_page', 'default_category', 'default_post_format', 'show_on_front', 'page_on_front', 'page_for_posts',
        'permalink_structure', 'default_comment_status', 'comment_moderation', 'comments_per_page', 'blog_public', 'WPLANG',
        'thumbnail_size_w', 'thumbnail_size_h', 'medium_size_w', 'medium_size_h', 'large_size_w', 'large_size_h' );

    public function get_tools(): array {
        return array(
            array( 'name' => 'wp_get_option', 'description' => 'Read a WordPress option. Only allowlisted options are accessible.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'name' => array( 'type' => 'string' ) ), 'required' => array( 'name' ) ),
                'annotations' => array( 'readOnlyHint' => true ) ),
            array( 'name' => 'wp_update_option', 'description' => 'Update a WordPress option. Only allowlisted options can be modified.',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'name' => array( 'type' => 'string' ), 'value' => array( 'type' => 'string' ) ), 'required' => array( 'name', 'value' ) ),
                'annotations' => array( 'destructiveHint' => true ) ),
            array( 'name' => 'wp_list_allowed_options', 'description' => 'List all option names that can be read or updated via MCP.',
                'inputSchema' => array( 'type' => 'object', 'properties' => new \stdClass() ), 'annotations' => array( 'readOnlyHint' => true ) ),
        );
    }

    public function call( string $n, array $a ) {
        if ( $n === 'wp_list_allowed_options' ) return array( 'allowed_options' => self::ALLOWED );
        $name = sanitize_text_field( $a['name'] ?? '' );
        if ( ! in_array( $name, self::ALLOWED, true ) ) return new WP_Error( 'option_not_allowed', "Option '{$name}' is not in the allowed list. Use wp_list_allowed_options to see available options." );
        if ( $n === 'wp_get_option' ) return array( 'name' => $name, 'value' => get_option( $name ) );
        if ( $n === 'wp_update_option' ) { $old = get_option( $name ); update_option( $name, sanitize_text_field( $a['value'] ) ); return array( 'name' => $name, 'old_value' => $old, 'new_value' => $a['value'], 'updated' => true ); }
        return new WP_Error( 'unknown_tool', "Unknown tool: {$n}" );
    }

    public function get_required_capability( string $n ): string { return $n === 'wp_update_option' ? 'manage_options' : 'read'; }
}

// ============================================================================
// Tool: Menus (read-only)
// ============================================================================

class CW_MCP_Tool_Menus implements CW_MCP_Tool_Provider {

    public function get_tools(): array {
        return array( array( 'name' => 'wp_get_menus', 'description' => 'List all registered navigation menus and their items.',
            'inputSchema' => array( 'type' => 'object', 'properties' => new \stdClass() ), 'annotations' => array( 'readOnlyHint' => true ) ) );
    }

    public function call( string $n, array $a ) {
        $menus = wp_get_nav_menus(); $r = array();
        foreach ( $menus as $m ) {
            $items = wp_get_nav_menu_items( $m->term_id ); $md = array( 'id' => $m->term_id, 'name' => $m->name, 'slug' => $m->slug, 'count' => $m->count, 'items' => array() );
            if ( $items ) { foreach ( $items as $i ) { $md['items'][] = array( 'id' => $i->ID, 'title' => $i->title, 'url' => $i->url, 'type' => $i->type, 'parent' => (int) $i->menu_item_parent ); } }
            $r[] = $md;
        }
        $locs = get_nav_menu_locations(); $reg = get_registered_nav_menus(); $lm = array();
        foreach ( $reg as $ls => $ln ) { $lm[] = array( 'slug' => $ls, 'name' => $ln, 'menu_id' => $locs[ $ls ] ?? null ); }
        return array( 'menus' => $r, 'locations' => $lm );
    }

    public function get_required_capability( string $n ): string { return 'read'; }
}

// ============================================================================
// Tool: Site Info, Health & Search
// ============================================================================

class CW_MCP_Tool_Site_Info implements CW_MCP_Tool_Provider {

    public function get_tools(): array {
        return array(
            array( 'name' => 'wp_get_site_info', 'description' => 'Get comprehensive WordPress site information: name, URL, versions, active theme, plugin count, post counts, and more.',
                'inputSchema' => array( 'type' => 'object', 'properties' => new \stdClass() ), 'annotations' => array( 'readOnlyHint' => true ) ),
            array( 'name' => 'wp_get_site_health', 'description' => 'Get WordPress site health status and diagnostics.',
                'inputSchema' => array( 'type' => 'object', 'properties' => new \stdClass() ), 'annotations' => array( 'readOnlyHint' => true ) ),
            array( 'name' => 'wp_search', 'description' => 'Search across all WordPress content (posts, pages, media).',
                'inputSchema' => array( 'type' => 'object', 'properties' => array( 'query' => array( 'type' => 'string' ),
                    'post_type' => array( 'type' => 'string', 'default' => 'any' ), 'per_page' => array( 'type' => 'integer', 'default' => 10 ) ), 'required' => array( 'query' ) ),
                'annotations' => array( 'readOnlyHint' => true ) ),
        );
    }

    public function call( string $n, array $a ) {
        switch ( $n ) {
            case 'wp_get_site_info':  return $this->site_info();
            case 'wp_get_site_health': return $this->site_health();
            case 'wp_search':         return $this->search( $a );
        }
        return new WP_Error( 'unknown_tool', "Unknown tool: {$n}" );
    }

    public function get_required_capability( string $n ): string { return $n === 'wp_get_site_health' ? 'manage_options' : 'read'; }

    private function site_info(): array {
        if ( ! function_exists( 'get_plugins' ) ) require_once ABSPATH . 'wp-admin/includes/plugin.php';
        $t = wp_get_theme(); $pc = wp_count_posts(); $pgc = wp_count_posts( 'page' ); global $wpdb;
        return array( 'site_name' => get_bloginfo( 'name' ), 'site_url' => site_url(), 'home_url' => home_url(),
            'description' => get_bloginfo( 'description' ), 'wp_version' => get_bloginfo( 'version' ), 'php_version' => PHP_VERSION,
            'mysql_version' => $wpdb->db_version(), 'language' => get_locale(), 'timezone' => get_option( 'timezone_string' ) ?: wp_timezone_string(),
            'active_theme' => $t->get( 'Name' ) . ' ' . $t->get( 'Version' ), 'active_plugins' => count( get_option( 'active_plugins', array() ) ),
            'total_plugins' => count( get_plugins() ), 'posts' => array( 'publish' => (int) $pc->publish, 'draft' => (int) $pc->draft, 'trash' => (int) $pc->trash ),
            'pages' => array( 'publish' => (int) $pgc->publish, 'draft' => (int) $pgc->draft ),
            'users_count' => (int) count_users()['total_users'], 'comments_count' => (int) wp_count_comments()->total_comments,
            'is_multisite' => is_multisite(), 'permalink_structure' => get_option( 'permalink_structure' ),
            'mcp_site_id' => CW_MCP_Site_ID::get(), 'mcp_version' => CW_MCP_VERSION );
    }

    private function site_health(): array {
        $h = array( 'wp_version' => get_bloginfo( 'version' ), 'php_version' => PHP_VERSION, 'max_upload_size' => size_format( wp_max_upload_size() ),
            'memory_limit' => WP_MEMORY_LIMIT, 'debug_mode' => defined( 'WP_DEBUG' ) && WP_DEBUG, 'cron_enabled' => ! ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ),
            'ssl' => is_ssl(), 'object_cache' => wp_using_ext_object_cache() ? 'External' : 'Default' );
        $up = get_site_transient( 'update_plugins' ); $ut = get_site_transient( 'update_themes' ); $uc = get_site_transient( 'update_core' );
        $h['updates'] = array( 'plugins' => $up && ! empty( $up->response ) ? count( $up->response ) : 0,
            'themes' => $ut && ! empty( $ut->response ) ? count( $ut->response ) : 0,
            'core' => $uc && ! empty( $uc->updates ) && $uc->updates[0]->response === 'upgrade' );
        return $h;
    }

    private function search( array $a ): array {
        $q = new WP_Query( array( 's' => sanitize_text_field( $a['query'] ), 'post_type' => sanitize_text_field( $a['post_type'] ?? 'any' ),
            'posts_per_page' => min( (int) ( $a['per_page'] ?? 10 ), 50 ), 'post_status' => 'any' ) );
        $r = array();
        foreach ( $q->posts as $p ) { $r[] = array( 'id' => $p->ID, 'title' => $p->post_title, 'type' => $p->post_type, 'status' => $p->post_status,
            'date' => $p->post_date, 'excerpt' => wp_trim_words( $p->post_content, 25 ), 'url' => get_permalink( $p->ID ) ); }
        return array( 'query' => $a['query'], 'results' => $r, 'total' => $q->found_posts );
    }
}

// ============================================================================
// Admin Settings Page (inline CSS & template)
// ============================================================================

class CW_MCP_Admin {

    const PAGE_SLUG = 'cw-mcp-settings';

    public function init(): void {
        add_action( 'admin_menu', array( $this, 'add_menu_page' ) );
        add_action( 'admin_init', array( $this, 'handle_actions' ) );
    }

    public function add_menu_page(): void {
        add_options_page( 'Cloudways MCP', 'Cloudways MCP', 'manage_options', self::PAGE_SLUG, array( $this, 'render_page' ) );
    }

    public function handle_actions(): void {
        if ( ! current_user_can( 'manage_options' ) || empty( $_POST['cw_mcp_action'] ) || ! wp_verify_nonce( $_POST['_wpnonce'] ?? '', 'cw_mcp_admin' ) ) return;
        $action = sanitize_text_field( wp_unslash( $_POST['cw_mcp_action'] ) );

        switch ( $action ) {
            case 'generate_key':
                $raw = CW_MCP_Auth::generate_key( (int) ( $_POST['key_user_id'] ?? get_current_user_id() ),
                    sanitize_text_field( wp_unslash( $_POST['key_label'] ?? 'Default' ) ), (int) ( $_POST['key_expires_days'] ?? 90 ) );
                set_transient( 'cw_mcp_new_key', $raw, 120 );
                wp_safe_redirect( add_query_arg( 'cw_mcp_notice', 'key_generated', $this->page_url() ) ); exit;

            case 'revoke_key':
                CW_MCP_Auth::revoke_key( sanitize_text_field( wp_unslash( $_POST['key_id'] ?? '' ) ) );
                wp_safe_redirect( add_query_arg( 'cw_mcp_notice', 'key_revoked', $this->page_url() ) ); exit;

            case 'update_security':
                CW_MCP_Security::update_settings( array( 'allow_http' => ! empty( $_POST['allow_http'] ), 'replay_protection' => ! empty( $_POST['replay_protection'] ),
                    'ip_allowlist' => array_filter( array_map( 'trim', explode( "\n", sanitize_textarea_field( wp_unslash( $_POST['ip_allowlist'] ?? '' ) ) ) ) ) ) );
                wp_safe_redirect( add_query_arg( 'cw_mcp_notice', 'settings_saved', $this->page_url() ) ); exit;

            case 'update_rate_limit':
                CW_MCP_Rate_Limiter::update_settings( array( 'enabled' => ! empty( $_POST['rl_enabled'] ),
                    'max_requests' => max( 1, (int) ( $_POST['rl_max_requests'] ?? 60 ) ), 'window_seconds' => max( 1, (int) ( $_POST['rl_window_seconds'] ?? 60 ) ) ) );
                wp_safe_redirect( add_query_arg( 'cw_mcp_notice', 'settings_saved', $this->page_url() ) ); exit;

            case 'update_tools':
                $disabled = array(); if ( ! empty( $_POST['disabled_tools'] ) && is_array( $_POST['disabled_tools'] ) ) $disabled = array_map( 'sanitize_text_field', wp_unslash( $_POST['disabled_tools'] ) );
                update_option( 'cw_mcp_tool_settings', array( 'disabled_tools' => $disabled, 'require_confirmation' => ! empty( $_POST['require_confirmation'] ) ) );
                wp_safe_redirect( add_query_arg( 'cw_mcp_notice', 'settings_saved', $this->page_url() ) ); exit;
        }
    }

    public function render_page(): void {
        if ( ! current_user_can( 'manage_options' ) ) return;

        $endpoint_url    = rest_url( CW_MCP_Server::NAMESPACE . CW_MCP_Server::ROUTE );
        $site_id         = CW_MCP_Site_ID::get();
        $keys            = CW_MCP_Auth::get_keys();
        $new_key         = get_transient( 'cw_mcp_new_key' );
        $security        = CW_MCP_Security::get_settings();
        $rate_limit      = CW_MCP_Rate_Limiter::get_settings();
        $tool_settings   = get_option( 'cw_mcp_tool_settings', array() );
        $disabled_tools  = $tool_settings['disabled_tools'] ?? array();
        $require_confirm = $tool_settings['require_confirmation'] ?? false;
        $notice          = isset( $_GET['cw_mcp_notice'] ) ? sanitize_text_field( wp_unslash( $_GET['cw_mcp_notice'] ) ) : '';
        $users           = get_users( array( 'role__in' => array( 'administrator', 'editor', 'author' ) ) );
        $audit           = new CW_MCP_Audit_Log();
        $log_entries     = $audit->get_entries( 20 );

        if ( $new_key ) delete_transient( 'cw_mcp_new_key' );

        $all_tools = array();
        foreach ( array( new CW_MCP_Tool_Posts(), new CW_MCP_Tool_Pages(), new CW_MCP_Tool_Media(), new CW_MCP_Tool_Comments(),
            new CW_MCP_Tool_Users(), new CW_MCP_Tool_Plugins(), new CW_MCP_Tool_Themes(), new CW_MCP_Tool_Taxonomies(),
            new CW_MCP_Tool_Options(), new CW_MCP_Tool_Menus(), new CW_MCP_Tool_Site_Info() ) as $prov ) {
            foreach ( $prov->get_tools() as $t ) $all_tools[] = $t;
        }

        $site_slug = sanitize_title( get_bloginfo( 'name' ) );
        ?>
<style>
.cw-mcp-admin{max-width:960px}.cw-mcp-card{background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:20px 24px;margin:16px 0;box-shadow:0 1px 1px rgba(0,0,0,.04)}
.cw-mcp-card h2{margin-top:0;font-size:1.3em;border-bottom:1px solid #eee;padding-bottom:10px}.cw-mcp-card h2 small,.cw-mcp-card h3 small{font-weight:normal;color:#888;font-size:.75em}
.cw-mcp-card h3{margin-top:20px}.cw-mcp-card pre{background:#f6f7f7;padding:12px 16px;border:1px solid #ddd;border-radius:3px;overflow-x:auto;font-size:13px;line-height:1.5;white-space:pre-wrap;word-wrap:break-word}
.cw-mcp-status{display:inline-block;padding:2px 8px;border-radius:3px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.3px}
.cw-mcp-status--active{background:#d4edda;color:#155724}.cw-mcp-status--error{background:#f8d7da;color:#721c24}
.cw-mcp-key-display{font-size:14px;padding:6px 12px;background:#fffde7;border:1px solid #f9a825;word-break:break-all}.cw-mcp-key-notice{border-left-color:#f9a825!important}
.cw-mcp-tool-grid{display:grid;grid-template-columns:1fr;gap:4px;margin:12px 0}
.cw-mcp-tool-toggle{display:flex;align-items:flex-start;gap:8px;padding:8px 12px;background:#f9f9f9;border:1px solid #eee;border-radius:3px;cursor:pointer;flex-wrap:wrap}
.cw-mcp-tool-toggle:hover{background:#f0f0f1}.cw-mcp-tool-toggle input[type=checkbox]{margin-top:2px}
.cw-mcp-tool-name{font-family:monospace;font-weight:600;font-size:13px;min-width:200px}.cw-mcp-tool-desc{color:#666;font-size:12px;flex:1;min-width:200px}
.cw-mcp-badge{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.3px}
.cw-mcp-badge--destructive{background:#f8d7da;color:#721c24}.cw-mcp-badge--readonly{background:#d1ecf1;color:#0c5460}
.cw-mcp-params{font-size:11px;max-width:250px;display:inline-block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cw-mcp-copy{margin-left:8px!important;vertical-align:middle!important}
</style>
<div class="wrap cw-mcp-admin">
<h1>Cloudways MCP Server</h1>
<p class="description">Model Context Protocol server for your WordPress site. Connect AI assistants like ChatGPT, Cursor, or Claude.</p>

<?php if ($notice==='key_generated'): ?><div class="notice notice-success is-dismissible"><p>API key generated successfully.</p></div>
<?php elseif ($notice==='key_revoked'): ?><div class="notice notice-warning is-dismissible"><p>API key revoked.</p></div>
<?php elseif ($notice==='settings_saved'): ?><div class="notice notice-success is-dismissible"><p>Settings saved.</p></div><?php endif; ?>

<div class="cw-mcp-card"><h2>Connection</h2>
<table class="form-table"><tr><th>MCP Endpoint</th><td><code id="cw-mcp-endpoint"><?php echo esc_html($endpoint_url); ?></code> <button type="button" class="button button-small cw-mcp-copy" data-target="cw-mcp-endpoint">Copy</button></td></tr>
<tr><th>Site ID</th><td><code><?php echo esc_html($site_id); ?></code></td></tr>
<tr><th>Status</th><td><span class="cw-mcp-status cw-mcp-status--active">Active</span></td></tr></table></div>

<?php if ($new_key): ?>
<div class="notice notice-info cw-mcp-key-notice"><p><strong>Your new API key (copy it now — it won't be shown again):</strong></p>
<p><code id="cw-mcp-new-key" class="cw-mcp-key-display"><?php echo esc_html($new_key); ?></code> <button type="button" class="button button-small cw-mcp-copy" data-target="cw-mcp-new-key">Copy</button></p></div>
<?php endif; ?>

<div class="cw-mcp-card"><h2>API Keys</h2><p class="description">Each key is bound to a WordPress user and inherits that user's role and capabilities.</p>
<?php if (!empty($keys)): ?>
<table class="widefat striped"><thead><tr><th>Key ID</th><th>Label</th><th>Bound User</th><th>Created</th><th>Expires</th><th>Last Used</th><th>Actions</th></tr></thead><tbody>
<?php foreach ($keys as $kid => $kd): $u=get_user_by('ID',$kd['user_id']); ?>
<tr><td><code><?php echo esc_html($kid); ?></code></td><td><?php echo esc_html($kd['label']); ?></td>
<td><?php echo $u ? esc_html($u->display_name.' ('.implode(', ',$u->roles).')') : 'Unknown'; ?></td>
<td><?php echo esc_html(date('Y-m-d H:i',$kd['created_at'])); ?></td>
<td><?php if($kd['expires_at']){$exp=time()>$kd['expires_at'];echo '<span class="'.($exp?'cw-mcp-status--error':'').'">'.esc_html(date('Y-m-d',$kd['expires_at'])).($exp?' (EXPIRED)':'').'</span>';}else echo'Never'; ?></td>
<td><?php if($kd['last_used_at']){echo esc_html(date('Y-m-d H:i',$kd['last_used_at']));if($kd['last_used_ip'])echo ' from '.esc_html($kd['last_used_ip']);}else echo'Never'; ?></td>
<td><form method="post" style="display:inline"><?php wp_nonce_field('cw_mcp_admin'); ?><input type="hidden" name="cw_mcp_action" value="revoke_key"><input type="hidden" name="key_id" value="<?php echo esc_attr($kid); ?>">
<button type="submit" class="button button-small" onclick="return confirm('Revoke this key?')">Revoke</button></form></td></tr>
<?php endforeach; ?></tbody></table>
<?php else: ?><p><em>No API keys configured. Generate one below.</em></p><?php endif; ?>

<h3>Generate New Key</h3><form method="post"><?php wp_nonce_field('cw_mcp_admin'); ?><input type="hidden" name="cw_mcp_action" value="generate_key">
<table class="form-table"><tr><th><label for="key_label">Label</label></th><td><input type="text" name="key_label" id="key_label" value="Default" class="regular-text"></td></tr>
<tr><th><label for="key_user_id">Bind to User</label></th><td><select name="key_user_id" id="key_user_id">
<?php foreach($users as $u): ?><option value="<?php echo esc_attr($u->ID); ?>"><?php echo esc_html($u->display_name.' ('.implode(', ',$u->roles).')'); ?></option><?php endforeach; ?>
</select><p class="description">The key will inherit this user's capabilities. Choose Editor for content-only access.</p></td></tr>
<tr><th><label for="key_expires_days">Expires In</label></th><td><select name="key_expires_days" id="key_expires_days">
<option value="30">30 days</option><option value="90" selected>90 days</option><option value="180">180 days</option><option value="365">1 year</option><option value="0">Never</option></select></td></tr></table>
<?php submit_button('Generate API Key','primary'); ?></form></div>

<div class="cw-mcp-card"><h2>Quick Setup</h2><p class="description">Copy these config snippets into your AI tool. Replace <code>&lt;your-api-key&gt;</code> with the key above.</p>
<h3>Cursor IDE <small>(<code>.cursor/mcp.json</code>)</small></h3>
<pre id="cw-mcp-cursor-config">{
  "mcpServers": {
    "<?php echo esc_js($site_slug); ?>": {
      "url": "<?php echo esc_js($endpoint_url); ?>",
      "headers": {
        "Authorization": "Bearer &lt;your-api-key&gt;"
      }
    }
  }
}</pre><button type="button" class="button button-small cw-mcp-copy" data-target="cw-mcp-cursor-config">Copy</button>

<h3>Claude Desktop <small>(<code>claude_desktop_config.json</code>)</small></h3>
<pre id="cw-mcp-claude-config">{
  "mcpServers": {
    "<?php echo esc_js($site_slug); ?>": {
      "transport": "streamable-http",
      "url": "<?php echo esc_js($endpoint_url); ?>",
      "headers": {
        "Authorization": "Bearer &lt;your-api-key&gt;"
      }
    }
  }
}</pre><button type="button" class="button button-small cw-mcp-copy" data-target="cw-mcp-claude-config">Copy</button></div>

<div class="cw-mcp-card"><h2>Security</h2><form method="post"><?php wp_nonce_field('cw_mcp_admin'); ?><input type="hidden" name="cw_mcp_action" value="update_security">
<table class="form-table"><tr><th>HTTPS Enforcement</th><td><label><input type="checkbox" name="allow_http" <?php checked($security['allow_http']); ?>> Allow HTTP (not recommended)</label></td></tr>
<tr><th>Replay Protection</th><td><label><input type="checkbox" name="replay_protection" <?php checked($security['replay_protection']); ?>> Reject stale/reused timestamps and nonces</label></td></tr>
<tr><th><label for="ip_allowlist">IP Allowlist</label></th><td><textarea name="ip_allowlist" id="ip_allowlist" rows="4" class="large-text code"><?php echo esc_textarea(implode("\n",$security['ip_allowlist'])); ?></textarea>
<p class="description">One IP or CIDR per line. Leave empty to allow all.</p></td></tr></table><?php submit_button('Save Security Settings'); ?></form></div>

<div class="cw-mcp-card"><h2>Rate Limiting</h2><form method="post"><?php wp_nonce_field('cw_mcp_admin'); ?><input type="hidden" name="cw_mcp_action" value="update_rate_limit">
<table class="form-table"><tr><th>Enable</th><td><label><input type="checkbox" name="rl_enabled" <?php checked($rate_limit['enabled']); ?>> Enable rate limiting</label></td></tr>
<tr><th><label for="rl_max_requests">Max Requests</label></th><td><input type="number" name="rl_max_requests" id="rl_max_requests" value="<?php echo esc_attr($rate_limit['max_requests']); ?>" min="1" class="small-text"> per window</td></tr>
<tr><th><label for="rl_window_seconds">Window (seconds)</label></th><td><input type="number" name="rl_window_seconds" id="rl_window_seconds" value="<?php echo esc_attr($rate_limit['window_seconds']); ?>" min="1" class="small-text"></td></tr></table>
<?php submit_button('Save Rate Limit Settings'); ?></form></div>

<div class="cw-mcp-card"><h2>Tool Management</h2><form method="post"><?php wp_nonce_field('cw_mcp_admin'); ?><input type="hidden" name="cw_mcp_action" value="update_tools">
<table class="form-table"><tr><th>Confirmation Mode</th><td><label><input type="checkbox" name="require_confirmation" <?php checked($require_confirm); ?>> Require confirmation token for destructive operations</label></td></tr></table>
<h3>Disable Individual Tools</h3><p class="description">Checked tools are <strong>disabled</strong> and won't appear in tools/list.</p>
<div class="cw-mcp-tool-grid">
<?php foreach ($all_tools as $t): ?>
<label class="cw-mcp-tool-toggle"><input type="checkbox" name="disabled_tools[]" value="<?php echo esc_attr($t['name']); ?>" <?php checked(in_array($t['name'],$disabled_tools,true)); ?>>
<span class="cw-mcp-tool-name"><?php echo esc_html($t['name']); ?></span>
<?php if(!empty($t['annotations']['destructiveHint'])): ?><span class="cw-mcp-badge cw-mcp-badge--destructive">destructive</span>
<?php elseif(!empty($t['annotations']['readOnlyHint'])): ?><span class="cw-mcp-badge cw-mcp-badge--readonly">read-only</span><?php endif; ?>
<span class="cw-mcp-tool-desc"><?php echo esc_html($t['description']); ?></span></label>
<?php endforeach; ?>
</div><?php submit_button('Save Tool Settings'); ?></form></div>

<div class="cw-mcp-card"><h2>Audit Log <small>(last 20 actions)</small></h2>
<?php if (!empty($log_entries)): ?>
<table class="widefat striped"><thead><tr><th>Time</th><th>Tool</th><th>Status</th><th>User</th><th>IP</th><th>Parameters</th></tr></thead><tbody>
<?php foreach ($log_entries as $e): $lu=get_user_by('ID',$e['user_id']); ?>
<tr><td><?php echo esc_html($e['created_at']); ?></td><td><code><?php echo esc_html($e['tool_name']); ?></code></td>
<td><span class="cw-mcp-status cw-mcp-status--<?php echo $e['result_status']==='success'?'active':'error'; ?>"><?php echo esc_html($e['result_status']); ?></span></td>
<td><?php echo $lu?esc_html($lu->display_name):'#'.esc_html($e['user_id']); ?></td><td><?php echo esc_html($e['client_ip']); ?></td>
<td><code class="cw-mcp-params"><?php echo esc_html(wp_trim_words($e['params'],15)); ?></code></td></tr>
<?php endforeach; ?></tbody></table>
<?php else: ?><p><em>No actions logged yet.</em></p><?php endif; ?></div>
</div>
<script>document.addEventListener('DOMContentLoaded',function(){document.querySelectorAll('.cw-mcp-copy').forEach(function(b){b.addEventListener('click',function(){var t=document.getElementById(this.dataset.target);navigator.clipboard.writeText(t.textContent||t.innerText).then(function(){b.textContent='Copied!';setTimeout(function(){b.textContent='Copy'},2e3)})})})});</script>
        <?php
    }

    private function page_url(): string {
        return admin_url( 'options-general.php?page=' . self::PAGE_SLUG );
    }
}

// ============================================================================
// Bootstrap
// ============================================================================

function cw_mcp_init() {
    $auth      = new CW_MCP_Auth();
    $security  = new CW_MCP_Security();
    $limiter   = new CW_MCP_Rate_Limiter();
    $audit     = new CW_MCP_Audit_Log();
    $tools     = new CW_MCP_Tools();
    $resources = new CW_MCP_Resources();

    foreach ( array( new CW_MCP_Tool_Posts(), new CW_MCP_Tool_Pages(), new CW_MCP_Tool_Media(), new CW_MCP_Tool_Comments(),
        new CW_MCP_Tool_Users(), new CW_MCP_Tool_Plugins(), new CW_MCP_Tool_Themes(), new CW_MCP_Tool_Taxonomies(),
        new CW_MCP_Tool_Options(), new CW_MCP_Tool_Menus(), new CW_MCP_Tool_Site_Info() ) as $provider ) {
        $tools->register_provider( $provider );
    }

    $server = new CW_MCP_Server( $auth, $security, $limiter, $audit, $tools, $resources );
    $server->register_routes();
}
add_action( 'rest_api_init', 'cw_mcp_init' );

function cw_mcp_admin_init() {
    $admin = new CW_MCP_Admin();
    $admin->init();
}
add_action( 'init', 'cw_mcp_admin_init' );

function cw_mcp_maybe_install() {
    $installed = get_option( 'cw_mcp_db_version', '0' );
    if ( version_compare( $installed, CW_MCP_VERSION, '<' ) ) {
        CW_MCP_Audit_Log::create_table();
        update_option( 'cw_mcp_db_version', CW_MCP_VERSION );
    }
}
add_action( 'init', 'cw_mcp_maybe_install' );

function cw_mcp_hide_from_index( $response ) {
    $data = $response->get_data();
    if ( isset( $data['routes'] ) ) {
        foreach ( $data['routes'] as $route => $_ ) {
            if ( strpos( $route, 'cw-mcp/' ) !== false ) unset( $data['routes'][ $route ] );
        }
        $response->set_data( $data );
    }
    return $response;
}
add_filter( 'rest_index', 'cw_mcp_hide_from_index' );
