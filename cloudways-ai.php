<?php
/**
 * Plugin Name: WP MCP Error Helper
 * Description: Must-use plugin that provides file access and context for the WordPress Error Fixer MCP Server
 * Version: 4.0.0
 * Author: WordPress MCP Error Fixer
 * 
 * Installation:
 * 1. Copy this file to: wp-content/mu-plugins/wp-mcp-error-helper.php
 * 2. Set your API key below
 * 3. Use the same key in your dashboard configuration
 * 
 * This plugin:
 * - Executes WP-CLI commands immediately (before themes load - works even when site has errors)
 * - Pushes errors to FastAPI Error Receiver
 * - Provides REST API endpoints for file access (when site is working)
 */

/*
|--------------------------------------------------------------------------
| IMMEDIATE WP-CLI EXECUTION (runs BEFORE WordPress loads themes)
|--------------------------------------------------------------------------
|
| This block executes WP-CLI commands immediately when requested.
| It runs before themes/plugins load, so it works even when the site has fatal errors.
| 
| Usage: POST to any WordPress URL with:
|   Header: X-MCP-API-Key: your-api-key
|   Header: X-MCP-Command: plugin list
|
| Or GET: ?mcp_action=exec&mcp_key=your-key&mcp_cmd=plugin+list
|
*/

// Check for immediate WP-CLI execution request
$mcp_api_key_header = $_SERVER['HTTP_X_MCP_API_KEY'] ?? '';
$mcp_command_header = $_SERVER['HTTP_X_MCP_COMMAND'] ?? '';
$mcp_action = $_GET['mcp_action'] ?? $_POST['mcp_action'] ?? '';

if ($mcp_command_header || $mcp_action === 'exec') {
    // Get API key (will be validated after we define the constant)
    $provided_key = $mcp_api_key_header ?: ($_GET['mcp_key'] ?? $_POST['mcp_key'] ?? '');
    $command = $mcp_command_header ?: ($_GET['mcp_cmd'] ?? $_POST['mcp_cmd'] ?? '');
    
    // We need to define ABSPATH to find wp-cli
    if (!defined('ABSPATH')) {
        // Find WordPress root by looking for wp-config.php
        $path = dirname(__FILE__);
        for ($i = 0; $i < 10; $i++) {
            if (file_exists($path . '/wp-config.php')) {
                define('ABSPATH', $path . '/');
                break;
            }
            $path = dirname($path);
        }
    }
    
    // Define API key constant for validation (skip to config section below if needed)
    // For now, use a hardcoded check that will be overridden by the config section
    $expected_key = 'CHANGE_THIS_TO_YOUR_SECURE_KEY'; // Default, will be replaced by constant
    
    // Try to read the actual key from this file
    $self_content = file_get_contents(__FILE__);
    if (preg_match("/define\s*\(\s*'WP_MCP_API_KEY'\s*,\s*'([^']+)'\s*\)/", $self_content, $matches)) {
        $expected_key = $matches[1];
    }
    
    // Validate API key
    if (empty($provided_key) || $provided_key !== $expected_key) {
        header('Content-Type: application/json');
        http_response_code(403);
        die(json_encode(['success' => false, 'error' => 'Invalid or missing API key']));
    }
    
    // Validate command
    if (empty($command)) {
        header('Content-Type: application/json');
        http_response_code(400);
        die(json_encode(['success' => false, 'error' => 'No command provided']));
    }
    
    // Security: Block dangerous commands
    $blocked = ['db export', 'db import', 'db drop', 'db reset', 'db create', 'eval', 'eval-file', 'shell'];
    foreach ($blocked as $block) {
        if (stripos($command, $block) === 0) {
            header('Content-Type: application/json');
            http_response_code(403);
            die(json_encode(['success' => false, 'error' => "Command '$block' is blocked for security"]));
        }
    }
    
    // Find WP-CLI
    $wp_cli = null;
    $cli_paths = ['/usr/local/bin/wp', '/usr/bin/wp', '/opt/homebrew/bin/wp'];
    if (defined('ABSPATH')) {
        $cli_paths[] = ABSPATH . 'wp-cli.phar';
        $cli_paths[] = ABSPATH . '../wp-cli.phar';
    }
    foreach ($cli_paths as $path) {
        if (file_exists($path) && is_executable($path)) {
            $wp_cli = $path;
            break;
        }
    }
    if (!$wp_cli) {
        $which = @shell_exec('which wp 2>/dev/null');
        if ($which && trim($which)) {
            $wp_cli = trim($which);
        }
    }
    
    if (!$wp_cli) {
        header('Content-Type: application/json');
        http_response_code(500);
        die(json_encode(['success' => false, 'error' => 'WP-CLI not found on this server']));
    }
    
    // Build and execute command
    $wp_path = defined('ABSPATH') ? ABSPATH : dirname(dirname(dirname(__FILE__)));
    $full_command = escapeshellarg($wp_cli) . ' ' . $command;
    $full_command .= ' --path=' . escapeshellarg($wp_path);
    $full_command .= ' --skip-themes --skip-plugins --skip-packages --allow-root --no-color 2>&1';
    
    $output = [];
    $return_code = 0;
    exec($full_command, $output, $return_code);
    
    $output_str = implode("\n", $output);
    
    // Return JSON result and EXIT - WordPress never loads themes
    header('Content-Type: application/json');
    die(json_encode([
        'success' => $return_code === 0,
        'output' => $output_str,
        'return_code' => $return_code,
        'command' => $command
    ]));
}

// Normal WordPress loading continues...
if (!defined('ABSPATH')) {
    exit;
}

/*
|--------------------------------------------------------------------------
| API KEY CONFIGURATION
|--------------------------------------------------------------------------
|
| Set your secure API key here. Generate one using:
|   openssl rand -hex 32
|
| This key must match the WP_MCP_API_KEY in your MCP config and FastAPI server.
|
*/
define('WP_MCP_API_KEY', 'CHANGE_THIS_TO_YOUR_SECURE_KEY');

/*
|--------------------------------------------------------------------------
| ERROR RECEIVER URL (FastAPI Server)
|--------------------------------------------------------------------------
|
| URL of the FastAPI error receiver server. Errors will be pushed here
| in real-time, allowing you to see them even when WordPress crashes.
|
| Example: http://your-server:8766 or https://errors.yourdomain.com
|
*/
define('WP_MCP_ERROR_RECEIVER_URL', 'http://localhost:8766');

/*
|--------------------------------------------------------------------------
| EXCLUDED PATHS (files that cannot be accessed)
|--------------------------------------------------------------------------
*/
define('WP_MCP_EXCLUDED_PATHS', 'wp-content/uploads');

/*
|--------------------------------------------------------------------------
| ERROR PUSHER CLASS - Sends errors to FastAPI server
|--------------------------------------------------------------------------
*/
class WP_MCP_Error_Pusher {
    
    private static $last_log_position = 0;
    private static $position_file;
    private static $initialized = false;
    
    /**
     * Initialize error pushing
     */
    public static function init() {
        if (self::$initialized) return;
        self::$initialized = true;
        
        // Track debug.log position
        self::$position_file = WP_CONTENT_DIR . '/.mcp_log_position';
        
        // Register custom error handler
        set_error_handler([self::class, 'handle_error']);
        
        // Register shutdown function to catch fatal errors
        register_shutdown_function([self::class, 'handle_shutdown']);
        
        // Also watch debug.log for new entries
        add_action('shutdown', [self::class, 'check_debug_log'], 1);
    }
    
    /**
     * Handle PHP errors
     */
    public static function handle_error($errno, $errstr, $errfile, $errline) {
        // Map error numbers to types
        $error_types = [
            E_ERROR => 'Fatal error',
            E_WARNING => 'Warning',
            E_NOTICE => 'Notice',
            E_PARSE => 'Parse error',
            E_DEPRECATED => 'Deprecated',
            E_USER_ERROR => 'User error',
            E_USER_WARNING => 'User warning',
            E_USER_NOTICE => 'User notice',
            E_USER_DEPRECATED => 'User deprecated',
        ];
        
        $error_type = isset($error_types[$errno]) ? $error_types[$errno] : 'Unknown';
        
        // Only push warnings and above, skip notices in production
        if (!in_array($errno, [E_ERROR, E_WARNING, E_PARSE, E_USER_ERROR, E_DEPRECATED])) {
            return false; // Let PHP handle it
        }
        
        self::push_error([
            'error_type' => $error_type,
            'message' => $errstr,
            'file_path' => $errfile,
            'line_number' => $errline,
            'timestamp' => date('d-M-Y H:i:s T'),
        ]);
        
        return false; // Let PHP's default handler also run
    }
    
    /**
     * Handle shutdown - captures fatal errors
     */
    public static function handle_shutdown() {
        $error = error_get_last();
        
        if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
            $error_types = [
                E_ERROR => 'Fatal error',
                E_PARSE => 'Parse error',
                E_CORE_ERROR => 'Core error',
                E_COMPILE_ERROR => 'Compile error',
            ];
            
            self::push_error([
                'error_type' => $error_types[$error['type']] ?? 'Fatal error',
                'message' => $error['message'],
                'file_path' => $error['file'],
                'line_number' => $error['line'],
                'timestamp' => date('d-M-Y H:i:s T'),
            ]);
            
            // Also try to send the file content around the error
            self::push_file_snapshot($error['file'], $error['line']);
        }
    }
    
    /**
     * Check debug.log for new entries
     */
    public static function check_debug_log() {
        $log_path = self::get_debug_log_path();
        if (!file_exists($log_path)) return;
        
        // Get last known position
        self::$last_log_position = 0;
        if (file_exists(self::$position_file)) {
            self::$last_log_position = (int) file_get_contents(self::$position_file);
        }
        
        $current_size = filesize($log_path);
        
        // If file was truncated, reset position
        if ($current_size < self::$last_log_position) {
            self::$last_log_position = 0;
        }
        
        // Read new content
        if ($current_size > self::$last_log_position) {
            $handle = fopen($log_path, 'r');
            if ($handle) {
                fseek($handle, self::$last_log_position);
                $new_content = fread($handle, $current_size - self::$last_log_position);
                fclose($handle);
                
                // Send each new line
                $lines = explode("\n", trim($new_content));
                foreach ($lines as $line) {
                    if (!empty(trim($line))) {
                        self::push_debug_line($line);
                    }
                }
                
                // Update position
                file_put_contents(self::$position_file, $current_size);
            }
        }
    }
    
    /**
     * Get debug log path
     */
    private static function get_debug_log_path() {
        if (defined('WP_DEBUG_LOG') && is_string(WP_DEBUG_LOG)) {
            return WP_DEBUG_LOG;
        }
        return WP_CONTENT_DIR . '/debug.log';
    }
    
    /**
     * Push error to FastAPI server
     */
    public static function push_error($error_data) {
        $url = defined('WP_MCP_ERROR_RECEIVER_URL') ? WP_MCP_ERROR_RECEIVER_URL : '';
        if (empty($url)) return;
        
        $error_data['site_url'] = home_url();
        $error_data['php_version'] = PHP_VERSION;
        $error_data['wordpress_version'] = get_bloginfo('version');
        
        self::send_to_receiver('/wp/error', $error_data);
    }
    
    /**
     * Push debug log line to FastAPI server
     */
    public static function push_debug_line($line) {
        $url = defined('WP_MCP_ERROR_RECEIVER_URL') ? WP_MCP_ERROR_RECEIVER_URL : '';
        if (empty($url)) return;
        
        self::send_to_receiver('/wp/debug-line', [
            'line' => $line,
            'site_url' => home_url(),
        ]);
    }
    
    /**
     * Push file snapshot (code around error)
     */
    public static function push_file_snapshot($file_path, $error_line) {
        $url = defined('WP_MCP_ERROR_RECEIVER_URL') ? WP_MCP_ERROR_RECEIVER_URL : '';
        if (empty($url) || !file_exists($file_path)) return;
        
        $lines = file($file_path);
        if (!$lines) return;
        
        // Get 20 lines around the error
        $start = max(0, $error_line - 10);
        $end = min(count($lines), $error_line + 10);
        
        $content = '';
        for ($i = $start; $i < $end; $i++) {
            $marker = ($i + 1 == $error_line) ? '>>> ' : '    ';
            $content .= $marker . ($i + 1) . ': ' . $lines[$i];
        }
        
        self::send_to_receiver('/wp/file-snapshot', [
            'file_path' => $file_path,
            'content' => $content,
            'total_lines' => count($lines),
            'site_url' => home_url(),
        ]);
    }
    
    /**
     * Send data to FastAPI receiver
     */
    private static function send_to_receiver($endpoint, $data) {
        $url = rtrim(WP_MCP_ERROR_RECEIVER_URL, '/') . $endpoint;
        $api_key = defined('WP_MCP_API_KEY') ? WP_MCP_API_KEY : '';
        
        // Use wp_remote_post if available, otherwise fall back to curl
        if (function_exists('wp_remote_post')) {
            wp_remote_post($url, [
                'timeout' => 5,
                'blocking' => false, // Don't wait for response
                'headers' => [
                    'Content-Type' => 'application/json',
                    'X-MCP-API-Key' => $api_key,
                ],
                'body' => json_encode($data),
            ]);
        } else {
            // Fallback to curl for early errors before WordPress loads
            self::curl_post($url, $data, $api_key);
        }
    }
    
    /**
     * Curl fallback for sending data
     */
    private static function curl_post($url, $data, $api_key) {
        if (!function_exists('curl_init')) return;
        
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($data),
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'X-MCP-API-Key: ' . $api_key,
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_CONNECTTIMEOUT => 3,
        ]);
        
        @curl_exec($ch);
        curl_close($ch);
    }
}

// Initialize error pushing immediately
WP_MCP_Error_Pusher::init();


/*
|--------------------------------------------------------------------------
| AUTO-FIX CLASS - Applies fixes from FastAPI before WordPress fully loads
|--------------------------------------------------------------------------
|
| This runs BEFORE themes load, allowing us to fix fatal errors in theme files
| before they crash the site.
|
*/
class WP_MCP_Auto_Fixer {
    
    private static $initialized = false;
    
    /**
     * Check for and apply pending fixes and WP-CLI commands immediately
     */
    public static function init() {
        if (self::$initialized) return;
        self::$initialized = true;
        
        // Only run if error receiver is configured
        if (!defined('WP_MCP_ERROR_RECEIVER_URL') || empty(WP_MCP_ERROR_RECEIVER_URL)) {
            return;
        }
        
        // Check for pending fixes
        self::apply_pending_fixes();
        
        // Check for pending WP-CLI commands
        self::execute_pending_wp_cli_commands();
    }
    
    /**
     * Fetch and execute pending WP-CLI commands from FastAPI
     * This runs BEFORE themes/plugins load, so it works even when site has fatal errors
     */
    private static function execute_pending_wp_cli_commands() {
        $url = rtrim(WP_MCP_ERROR_RECEIVER_URL, '/') . '/wp/pending-commands';
        $api_key = defined('WP_MCP_API_KEY') ? WP_MCP_API_KEY : '';
        
        // Add site URL as query param
        $site_url = self::get_site_url();
        if ($site_url) {
            $url .= '?site_url=' . urlencode($site_url);
        }
        
        // Fetch pending commands
        $response = self::curl_get($url, $api_key);
        if (!$response) return;
        
        $data = json_decode($response, true);
        if (!$data || !isset($data['commands']) || empty($data['commands'])) {
            return;
        }
        
        // Execute each command
        foreach ($data['commands'] as $command) {
            $result = self::execute_wp_cli_command($command);
            
            // Report result back to FastAPI
            self::report_wp_cli_result($command['id'], $result);
        }
    }
    
    /**
     * Execute a single WP-CLI command
     */
    private static function execute_wp_cli_command($command) {
        $cmd = $command['command'];
        
        // Security: Block dangerous commands
        $blocked = ['db export', 'db import', 'db drop', 'db reset', 'db create', 'eval', 'eval-file', 'shell'];
        foreach ($blocked as $block) {
            if (stripos($cmd, $block) === 0) {
                return [
                    'success' => false,
                    'output' => "Command '$block' is blocked for security reasons.",
                    'return_code' => 1
                ];
            }
        }
        
        // Find WP-CLI
        $wp_cli = self::find_wp_cli();
        if (!$wp_cli) {
            return [
                'success' => false,
                'output' => 'WP-CLI not found on this server.',
                'return_code' => 1
            ];
        }
        
        // Build the full command with safety flags
        $full_command = escapeshellarg($wp_cli) . ' ' . $cmd;
        
        // Add WordPress path
        if (defined('ABSPATH')) {
            $full_command .= ' --path=' . escapeshellarg(ABSPATH);
        }
        
        // Add resilience flags - these ensure command works even with site errors
        $full_command .= ' --skip-themes';      // Don't load themes
        $full_command .= ' --skip-plugins';     // Don't load plugins
        $full_command .= ' --skip-packages';    // Don't load PHAR packages
        $full_command .= ' --allow-root';       // Allow running as root
        $full_command .= ' --no-color';         // No ANSI colors
        
        // Redirect stderr to stdout
        $full_command .= ' 2>&1';
        
        // Execute
        $output = [];
        $return_code = 0;
        exec($full_command, $output, $return_code);
        
        $output_str = implode("\n", $output);
        
        error_log("[WP-MCP WP-CLI] Executed: $cmd (exit code: $return_code)");
        
        return [
            'success' => $return_code === 0,
            'output' => $output_str,
            'return_code' => $return_code
        ];
    }
    
    /**
     * Find WP-CLI executable
     */
    private static function find_wp_cli() {
        // Common WP-CLI locations
        $paths = [
            '/usr/local/bin/wp',
            '/usr/bin/wp',
            '/opt/homebrew/bin/wp',
        ];
        
        if (defined('ABSPATH')) {
            $paths[] = ABSPATH . 'wp-cli.phar';
            $paths[] = ABSPATH . '../wp-cli.phar';
        }
        
        foreach ($paths as $path) {
            if (file_exists($path) && is_executable($path)) {
                return $path;
            }
        }
        
        // Try to find via which
        $which = @shell_exec('which wp 2>/dev/null');
        if ($which && trim($which)) {
            return trim($which);
        }
        
        return null;
    }
    
    /**
     * Report WP-CLI command result back to FastAPI
     */
    private static function report_wp_cli_result($command_id, $result) {
        $url = rtrim(WP_MCP_ERROR_RECEIVER_URL, '/') . '/wp/command-result';
        $api_key = defined('WP_MCP_API_KEY') ? WP_MCP_API_KEY : '';
        
        $data = [
            'command_id' => $command_id,
            'success' => $result['success'],
            'output' => $result['output'],
            'return_code' => $result['return_code'],
            'site_url' => self::get_site_url()
        ];
        
        self::curl_post($url, $data, $api_key);
    }
    
    /**
     * Fetch and apply pending fixes from FastAPI
     */
    private static function apply_pending_fixes() {
        $url = rtrim(WP_MCP_ERROR_RECEIVER_URL, '/') . '/wp/pending-fixes';
        $api_key = defined('WP_MCP_API_KEY') ? WP_MCP_API_KEY : '';
        
        // Add site URL as query param
        $site_url = self::get_site_url();
        if ($site_url) {
            $url .= '?site_url=' . urlencode($site_url);
        }
        
        // Fetch pending fixes using curl (wp_remote_get may not be loaded yet)
        $response = self::curl_get($url, $api_key);
        if (!$response) return;
        
        $data = json_decode($response, true);
        if (!$data || !isset($data['fixes']) || empty($data['fixes'])) {
            return;
        }
        
        // Apply each fix
        foreach ($data['fixes'] as $fix) {
            $result = self::apply_fix($fix);
            
            // Report result back to FastAPI
            self::report_fix_result($fix['id'], $result['success'], $result['error'] ?? null);
        }
    }
    
    /**
     * Apply a single fix
     */
    private static function apply_fix($fix) {
        $file_path = $fix['file_path'];
        
        // Security: Verify file is within WordPress
        if (!self::is_path_safe($file_path)) {
            return ['success' => false, 'error' => 'Path not allowed: ' . $file_path];
        }
        
        if (!file_exists($file_path)) {
            return ['success' => false, 'error' => 'File not found: ' . $file_path];
        }
        
        if (!is_writable($file_path)) {
            return ['success' => false, 'error' => 'File not writable: ' . $file_path];
        }
        
        // Read current file
        $lines = file($file_path);
        if ($lines === false) {
            return ['success' => false, 'error' => 'Cannot read file'];
        }
        
        // Create backup
        $backup_path = $file_path . '.bak.autofix.' . date('Ymd_His');
        if (file_put_contents($backup_path, implode('', $lines)) === false) {
            return ['success' => false, 'error' => 'Cannot create backup'];
        }
        
        // Apply the fix based on action type
        $action = $fix['action'];
        $start_line = isset($fix['start_line']) ? (int)$fix['start_line'] : 0;
        $end_line = isset($fix['end_line']) ? (int)$fix['end_line'] : $start_line;
        $new_content = isset($fix['new_content']) ? $fix['new_content'] : '';
        
        switch ($action) {
            case 'delete_lines':
                // Delete lines from start_line to end_line (1-indexed)
                $start_idx = $start_line - 1;
                $count = $end_line - $start_line + 1;
                array_splice($lines, $start_idx, $count);
                break;
                
            case 'replace_lines':
                // Replace lines from start_line to end_line with new_content
                $start_idx = $start_line - 1;
                $count = $end_line - $start_line + 1;
                $new_lines = explode("\n", $new_content);
                $new_lines = array_map(function($l) {
                    return rtrim($l) . "\n";
                }, $new_lines);
                array_splice($lines, $start_idx, $count, $new_lines);
                break;
                
            case 'insert_lines':
                // Insert new_content after start_line
                $insert_idx = min($start_line, count($lines));
                $new_lines = explode("\n", $new_content);
                $new_lines = array_map(function($l) {
                    return rtrim($l) . "\n";
                }, $new_lines);
                array_splice($lines, $insert_idx, 0, $new_lines);
                break;
                
            default:
                return ['success' => false, 'error' => 'Unknown action: ' . $action];
        }
        
        // Write the fixed file
        if (file_put_contents($file_path, implode('', $lines)) === false) {
            // Try to restore backup
            copy($backup_path, $file_path);
            return ['success' => false, 'error' => 'Failed to write file'];
        }
        
        // Log the fix
        error_log("[WP-MCP Auto-Fix] Applied fix: {$action} on {$file_path} (lines {$start_line}-{$end_line})");
        
        return [
            'success' => true,
            'backup_path' => $backup_path,
            'action' => $action,
            'file_path' => $file_path
        ];
    }
    
    /**
     * Report fix result back to FastAPI
     */
    private static function report_fix_result($fix_id, $success, $error = null) {
        $url = rtrim(WP_MCP_ERROR_RECEIVER_URL, '/') . '/wp/fix-applied';
        $url .= '?fix_id=' . urlencode($fix_id);
        $url .= '&success=' . ($success ? 'true' : 'false');
        if ($error) {
            $url .= '&error_message=' . urlencode($error);
        }
        
        $api_key = defined('WP_MCP_API_KEY') ? WP_MCP_API_KEY : '';
        self::curl_post($url, [], $api_key);
    }
    
    /**
     * Check if path is safe (within WordPress directory)
     */
    private static function is_path_safe($path) {
        // Must be absolute path
        if (strpos($path, '/') !== 0) {
            return false;
        }
        
        // Must be within WordPress installation
        $wp_root = defined('ABSPATH') ? realpath(ABSPATH) : null;
        if (!$wp_root) {
            // Fallback: check for common WordPress paths
            if (strpos($path, '/wp-content/') === false && 
                strpos($path, '/wp-includes/') === false &&
                strpos($path, '/wp-admin/') === false) {
                return false;
            }
        } else {
            $real_path = realpath(dirname($path));
            if ($real_path === false || strpos($real_path, $wp_root) !== 0) {
                return false;
            }
        }
        
        // Don't allow editing core WordPress files (optional safety)
        // Uncomment if you want to prevent editing wp-includes:
        // if (strpos($path, '/wp-includes/') !== false) return false;
        
        return true;
    }
    
    /**
     * Get site URL (before WordPress fully loads)
     */
    private static function get_site_url() {
        // Try to get from database directly if WordPress isn't fully loaded
        if (function_exists('home_url')) {
            return home_url();
        }
        
        // Fallback: read from wp-config if possible
        if (defined('ABSPATH')) {
            $config_file = ABSPATH . 'wp-config.php';
            if (file_exists($config_file)) {
                $content = file_get_contents($config_file);
                if (preg_match("/define\s*\(\s*['\"]WP_HOME['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/", $content, $match)) {
                    return $match[1];
                }
                if (preg_match("/define\s*\(\s*['\"]WP_SITEURL['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/", $content, $match)) {
                    return $match[1];
                }
            }
        }
        
        // Fallback to request host
        if (isset($_SERVER['HTTP_HOST'])) {
            $scheme = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
            return $scheme . '://' . $_SERVER['HTTP_HOST'];
        }
        
        return null;
    }
    
    /**
     * Curl GET request
     */
    private static function curl_get($url, $api_key) {
        if (!function_exists('curl_init')) return null;
        
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_HTTPHEADER => [
                'X-MCP-API-Key: ' . $api_key,
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_FOLLOWLOCATION => true,
        ]);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($http_code !== 200) {
            return null;
        }
        
        return $response;
    }
    
    /**
     * Curl POST request
     */
    private static function curl_post($url, $data, $api_key) {
        if (!function_exists('curl_init')) return null;
        
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($data),
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'X-MCP-API-Key: ' . $api_key,
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_CONNECTTIMEOUT => 3,
        ]);
        
        $response = curl_exec($ch);
        curl_close($ch);
        
        return $response;
    }
}

// Run auto-fixer IMMEDIATELY - before themes load
WP_MCP_Auto_Fixer::init();


class WP_MCP_Error_Helper {
    
    const API_NAMESPACE = 'wp-mcp/v1';
    const VERSION = '3.0.0';
    
    // Paths that cannot be accessed (loaded from constant)
    private $excluded_paths = [];
    
    public function __construct() {
        // Load excluded paths from constant
        if (defined('WP_MCP_EXCLUDED_PATHS')) {
            $this->excluded_paths = array_map('trim', explode(',', WP_MCP_EXCLUDED_PATHS));
        }
        
        add_action('rest_api_init', [$this, 'register_rest_routes']);
        
        // Enhanced error logging
        if (defined('WP_DEBUG') && WP_DEBUG) {
            add_action('shutdown', [$this, 'log_shutdown_errors']);
        }
    }
    
    /**
     * Register all REST API routes
     */
    public function register_rest_routes() {
        // ============ DEBUG LOG ENDPOINTS ============
        
        // Get parsed errors from debug.log
        register_rest_route(self::API_NAMESPACE, '/debug-log/errors', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_debug_log_errors'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'limit' => ['default' => 50, 'type' => 'integer'],
                'error_types' => ['default' => 'all', 'type' => 'string'],
            ],
        ]);
        
        // Get raw debug.log tail
        register_rest_route(self::API_NAMESPACE, '/debug-log/tail', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_debug_log_tail'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'lines' => ['default' => 100, 'type' => 'integer'],
            ],
        ]);
        
        // Clear debug.log
        register_rest_route(self::API_NAMESPACE, '/debug-log/clear', [
            'methods'  => 'POST',
            'callback' => [$this, 'clear_debug_log'],
            'permission_callback' => [$this, 'check_permissions'],
        ]);
        
        // Analyze specific error
        register_rest_route(self::API_NAMESPACE, '/debug-log/analyze', [
            'methods'  => 'POST',
            'callback' => [$this, 'analyze_error'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'error_message' => ['required' => true, 'type' => 'string'],
            ],
        ]);
        
        // ============ FILE OPERATION ENDPOINTS ============
        
        // Read file contents
        register_rest_route(self::API_NAMESPACE, '/file/read', [
            'methods'  => 'POST',
            'callback' => [$this, 'read_file'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'file_path' => ['required' => true, 'type' => 'string'],
                'start_line' => ['default' => 1, 'type' => 'integer'],
                'end_line' => ['default' => -1, 'type' => 'integer'],
            ],
        ]);
        
        // Read file around a specific line
        register_rest_route(self::API_NAMESPACE, '/file/read-around-line', [
            'methods'  => 'POST',
            'callback' => [$this, 'read_file_around_line'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'file_path' => ['required' => true, 'type' => 'string'],
                'line_number' => ['required' => true, 'type' => 'integer'],
                'context_lines' => ['default' => 10, 'type' => 'integer'],
            ],
        ]);
        
        // Edit file (replace lines)
        register_rest_route(self::API_NAMESPACE, '/file/edit', [
            'methods'  => 'POST',
            'callback' => [$this, 'edit_file'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'file_path' => ['required' => true, 'type' => 'string'],
                'line_number' => ['required' => true, 'type' => 'integer'],
                'new_content' => ['required' => true, 'type' => 'string'],
                'end_line' => ['default' => -1, 'type' => 'integer'],
            ],
        ]);
        
        // Insert lines
        register_rest_route(self::API_NAMESPACE, '/file/insert', [
            'methods'  => 'POST',
            'callback' => [$this, 'insert_lines'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'file_path' => ['required' => true, 'type' => 'string'],
                'after_line' => ['required' => true, 'type' => 'integer'],
                'content' => ['required' => true, 'type' => 'string'],
            ],
        ]);
        
        // Delete lines
        register_rest_route(self::API_NAMESPACE, '/file/delete-lines', [
            'methods'  => 'POST',
            'callback' => [$this, 'delete_lines'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'file_path' => ['required' => true, 'type' => 'string'],
                'start_line' => ['required' => true, 'type' => 'integer'],
                'end_line' => ['required' => true, 'type' => 'integer'],
            ],
        ]);
        
        // Search in file
        register_rest_route(self::API_NAMESPACE, '/file/search', [
            'methods'  => 'POST',
            'callback' => [$this, 'search_in_file'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'file_path' => ['required' => true, 'type' => 'string'],
                'pattern' => ['required' => true, 'type' => 'string'],
                'regex' => ['default' => false, 'type' => 'boolean'],
            ],
        ]);
        
        // Search across WordPress
        register_rest_route(self::API_NAMESPACE, '/file/search-all', [
            'methods'  => 'POST',
            'callback' => [$this, 'search_wordpress'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'pattern' => ['required' => true, 'type' => 'string'],
                'file_extensions' => ['default' => 'php', 'type' => 'string'],
                'max_results' => ['default' => 50, 'type' => 'integer'],
            ],
        ]);
        
        // List directory
        register_rest_route(self::API_NAMESPACE, '/file/list', [
            'methods'  => 'POST',
            'callback' => [$this, 'list_directory'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'path' => ['default' => '', 'type' => 'string'],
            ],
        ]);
        
        // Get function definition
        register_rest_route(self::API_NAMESPACE, '/file/function', [
            'methods'  => 'POST',
            'callback' => [$this, 'get_function_definition'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'file_path' => ['required' => true, 'type' => 'string'],
                'function_name' => ['required' => true, 'type' => 'string'],
            ],
        ]);
        
        // Validate PHP syntax
        register_rest_route(self::API_NAMESPACE, '/file/validate-syntax', [
            'methods'  => 'POST',
            'callback' => [$this, 'validate_php_syntax'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'file_path' => ['required' => true, 'type' => 'string'],
            ],
        ]);
        
        // Restore backup
        register_rest_route(self::API_NAMESPACE, '/file/restore-backup', [
            'methods'  => 'POST',
            'callback' => [$this, 'restore_backup'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'backup_path' => ['required' => true, 'type' => 'string'],
            ],
        ]);
        
        // List backups
        register_rest_route(self::API_NAMESPACE, '/file/list-backups', [
            'methods'  => 'POST',
            'callback' => [$this, 'list_backups'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'file_path' => ['required' => true, 'type' => 'string'],
            ],
        ]);
        
        // ============ WORDPRESS CONTEXT ENDPOINTS ============
        
        // Get site info
        register_rest_route(self::API_NAMESPACE, '/info', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_site_info'],
            'permission_callback' => [$this, 'check_permissions'],
        ]);
        
        // Get plugins info
        register_rest_route(self::API_NAMESPACE, '/plugins', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_plugins_info'],
            'permission_callback' => [$this, 'check_permissions'],
        ]);
        
        // Get theme info
        register_rest_route(self::API_NAMESPACE, '/theme', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_theme_info'],
            'permission_callback' => [$this, 'check_permissions'],
        ]);
        
        // Get database info
        register_rest_route(self::API_NAMESPACE, '/database', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_database_info'],
            'permission_callback' => [$this, 'check_permissions'],
        ]);
        
        // Get hooks info
        register_rest_route(self::API_NAMESPACE, '/hooks', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_hooks_info'],
            'permission_callback' => [$this, 'check_permissions'],
        ]);
        
        // Get constants
        register_rest_route(self::API_NAMESPACE, '/constants', [
            'methods'  => 'GET',
            'callback' => [$this, 'get_constants'],
            'permission_callback' => [$this, 'check_permissions'],
        ]);
        
        // Locate function/class
        register_rest_route(self::API_NAMESPACE, '/locate', [
            'methods'  => 'GET',
            'callback' => [$this, 'locate_definition'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'name' => ['required' => true, 'type' => 'string'],
                'type' => ['default' => 'function', 'enum' => ['function', 'class', 'method']],
            ],
        ]);
        
        // Health check (no auth required)
        register_rest_route(self::API_NAMESPACE, '/health', [
            'methods'  => 'GET',
            'callback' => [$this, 'health_check'],
            'permission_callback' => '__return_true',
        ]);
        
        // ============ WP-CLI ENDPOINTS ============
        
        // Run WP-CLI command (generic)
        register_rest_route(self::API_NAMESPACE, '/wp-cli/run', [
            'methods'  => 'POST',
            'callback' => [$this, 'run_wp_cli'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'command' => ['required' => true, 'type' => 'string'],
            ],
        ]);
        
        // Plugin management
        register_rest_route(self::API_NAMESPACE, '/wp-cli/plugin/list', [
            'methods'  => 'GET',
            'callback' => [$this, 'wp_cli_plugin_list'],
            'permission_callback' => [$this, 'check_permissions'],
        ]);
        
        register_rest_route(self::API_NAMESPACE, '/wp-cli/plugin/activate', [
            'methods'  => 'POST',
            'callback' => [$this, 'wp_cli_plugin_activate'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'plugin' => ['required' => true, 'type' => 'string'],
            ],
        ]);
        
        register_rest_route(self::API_NAMESPACE, '/wp-cli/plugin/deactivate', [
            'methods'  => 'POST',
            'callback' => [$this, 'wp_cli_plugin_deactivate'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'plugin' => ['required' => true, 'type' => 'string'],
            ],
        ]);
        
        register_rest_route(self::API_NAMESPACE, '/wp-cli/plugin/install', [
            'methods'  => 'POST',
            'callback' => [$this, 'wp_cli_plugin_install'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'plugin' => ['required' => true, 'type' => 'string'],
                'activate' => ['default' => false, 'type' => 'boolean'],
            ],
        ]);
        
        register_rest_route(self::API_NAMESPACE, '/wp-cli/plugin/delete', [
            'methods'  => 'POST',
            'callback' => [$this, 'wp_cli_plugin_delete'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'plugin' => ['required' => true, 'type' => 'string'],
            ],
        ]);
        
        register_rest_route(self::API_NAMESPACE, '/wp-cli/plugin/update', [
            'methods'  => 'POST',
            'callback' => [$this, 'wp_cli_plugin_update'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'plugin' => ['required' => true, 'type' => 'string'],
            ],
        ]);
        
        // Theme management
        register_rest_route(self::API_NAMESPACE, '/wp-cli/theme/list', [
            'methods'  => 'GET',
            'callback' => [$this, 'wp_cli_theme_list'],
            'permission_callback' => [$this, 'check_permissions'],
        ]);
        
        register_rest_route(self::API_NAMESPACE, '/wp-cli/theme/activate', [
            'methods'  => 'POST',
            'callback' => [$this, 'wp_cli_theme_activate'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'theme' => ['required' => true, 'type' => 'string'],
            ],
        ]);
        
        register_rest_route(self::API_NAMESPACE, '/wp-cli/theme/install', [
            'methods'  => 'POST',
            'callback' => [$this, 'wp_cli_theme_install'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'theme' => ['required' => true, 'type' => 'string'],
                'activate' => ['default' => false, 'type' => 'boolean'],
            ],
        ]);
        
        register_rest_route(self::API_NAMESPACE, '/wp-cli/theme/delete', [
            'methods'  => 'POST',
            'callback' => [$this, 'wp_cli_theme_delete'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'theme' => ['required' => true, 'type' => 'string'],
            ],
        ]);
        
        // Core/Site info
        register_rest_route(self::API_NAMESPACE, '/wp-cli/core/version', [
            'methods'  => 'GET',
            'callback' => [$this, 'wp_cli_core_version'],
            'permission_callback' => [$this, 'check_permissions'],
        ]);
        
        register_rest_route(self::API_NAMESPACE, '/wp-cli/core/check-update', [
            'methods'  => 'GET',
            'callback' => [$this, 'wp_cli_core_check_update'],
            'permission_callback' => [$this, 'check_permissions'],
        ]);
        
        // Cache management
        register_rest_route(self::API_NAMESPACE, '/wp-cli/cache/flush', [
            'methods'  => 'POST',
            'callback' => [$this, 'wp_cli_cache_flush'],
            'permission_callback' => [$this, 'check_permissions'],
        ]);
        
        // Database
        register_rest_route(self::API_NAMESPACE, '/wp-cli/db/check', [
            'methods'  => 'GET',
            'callback' => [$this, 'wp_cli_db_check'],
            'permission_callback' => [$this, 'check_permissions'],
        ]);
        
        register_rest_route(self::API_NAMESPACE, '/wp-cli/db/optimize', [
            'methods'  => 'POST',
            'callback' => [$this, 'wp_cli_db_optimize'],
            'permission_callback' => [$this, 'check_permissions'],
        ]);
        
        // Options
        register_rest_route(self::API_NAMESPACE, '/wp-cli/option/get', [
            'methods'  => 'GET',
            'callback' => [$this, 'wp_cli_option_get'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'option' => ['required' => true, 'type' => 'string'],
            ],
        ]);
        
        register_rest_route(self::API_NAMESPACE, '/wp-cli/option/update', [
            'methods'  => 'POST',
            'callback' => [$this, 'wp_cli_option_update'],
            'permission_callback' => [$this, 'check_permissions'],
            'args' => [
                'option' => ['required' => true, 'type' => 'string'],
                'value' => ['required' => true, 'type' => 'string'],
            ],
        ]);
        
        // User management
        register_rest_route(self::API_NAMESPACE, '/wp-cli/user/list', [
            'methods'  => 'GET',
            'callback' => [$this, 'wp_cli_user_list'],
            'permission_callback' => [$this, 'check_permissions'],
        ]);
        
        // Rewrite/Permalinks
        register_rest_route(self::API_NAMESPACE, '/wp-cli/rewrite/flush', [
            'methods'  => 'POST',
            'callback' => [$this, 'wp_cli_rewrite_flush'],
            'permission_callback' => [$this, 'check_permissions'],
        ]);
    }
    
    /**
     * Check API permissions using API key
     */
    public function check_permissions() {
        // Check for API key in header
        $api_key = '';
        if (isset($_SERVER['HTTP_X_MCP_API_KEY'])) {
            $api_key = sanitize_text_field($_SERVER['HTTP_X_MCP_API_KEY']);
        } elseif (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            // Support Bearer token format
            $auth = $_SERVER['HTTP_AUTHORIZATION'];
            if (preg_match('/Bearer\s+(.+)/i', $auth, $matches)) {
                $api_key = sanitize_text_field($matches[1]);
            }
        }
        
        $stored_key = defined('WP_MCP_API_KEY') ? WP_MCP_API_KEY : '';
        
        if (empty($stored_key) || $stored_key === 'CHANGE_THIS_TO_YOUR_SECURE_KEY') {
            return new WP_Error(
                'mcp_no_api_key',
                'WP_MCP_API_KEY not configured. Edit wp-mcp-error-helper.php and set your API key.',
                ['status' => 500]
            );
        }
        
        if (empty($api_key)) {
            return new WP_Error(
                'mcp_missing_key',
                'API key required. Send via X-MCP-API-Key header or Authorization: Bearer <key>',
                ['status' => 401]
            );
        }
        
        if (!hash_equals($stored_key, $api_key)) {
            return new WP_Error('mcp_invalid_key', 'Invalid API key', ['status' => 403]);
        }
        
        return true;
    }
    
    /**
     * Check if path is allowed (not in excluded paths)
     */
    private function is_path_allowed($file_path) {
        $real_path = realpath($file_path);
        $wp_path = realpath(ABSPATH);
        
        // Must be within WordPress directory
        if ($real_path === false || strpos($real_path, $wp_path) !== 0) {
            return false;
        }
        
        // Check excluded paths
        $relative = str_replace($wp_path . '/', '', $real_path);
        foreach ($this->excluded_paths as $excluded) {
            if (strpos($relative, $excluded) === 0) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Resolve file path (handle relative paths)
     */
    private function resolve_path($path) {
        if (strpos($path, ABSPATH) === 0) {
            return $path;
        }
        return ABSPATH . ltrim($path, '/');
    }
    
    /**
     * Get debug log path
     */
    private function get_debug_log_path() {
        if (defined('WP_DEBUG_LOG') && is_string(WP_DEBUG_LOG)) {
            return WP_DEBUG_LOG;
        }
        return WP_CONTENT_DIR . '/debug.log';
    }
    
    // ============ DEBUG LOG METHODS ============
    
    /**
     * Parse PHP error message
     */
    private function parse_php_error($error_text) {
        $patterns = [
            '/\[(?P<timestamp>[^\]]+)\]\s+PHP\s+(?P<type>Fatal error|Warning|Notice|Deprecated|Parse error):\s*(?P<message>.*?)\s+in\s+(?P<file>[^\s]+\.php)(?:\s+on\s+line\s+|\:)(?P<line>\d+)/is',
            '/(?P<type>Fatal error|Parse error|Warning|Notice|Deprecated):\s*(?P<message>.*?)\s+in\s+(?P<file>[^\s]+\.php)\s+on\s+line\s+(?P<line>\d+)/is',
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $error_text, $match)) {
                $function = null;
                if (preg_match('/(?:function|->|::)\s*(\w+)\s*\(/i', $match['message'], $func_match)) {
                    $function = $func_match[1];
                }
                
                return [
                    'timestamp' => $match['timestamp'] ?? null,
                    'error_type' => $match['type'],
                    'message' => trim($match['message']),
                    'file_path' => $match['file'],
                    'line_number' => (int)$match['line'],
                    'function_name' => $function,
                ];
            }
        }
        return null;
    }
    
    /**
     * Get debug log errors
     */
    public function get_debug_log_errors($request) {
        $log_path = $this->get_debug_log_path();
        
        if (!file_exists($log_path)) {
            return [
                'success' => false,
                'error' => 'Debug log not found',
                'path' => $log_path,
                'hint' => 'Enable WP_DEBUG and WP_DEBUG_LOG in wp-config.php',
            ];
        }
        
        $content = @file_get_contents($log_path);
        if ($content === false) {
            return ['success' => false, 'error' => 'Cannot read debug log'];
        }
        
        $limit = $request->get_param('limit');
        $error_types = strtolower($request->get_param('error_types'));
        
        // Split by timestamp
        $entries = preg_split('/(?=\[\d{2}-[A-Za-z]{3}-\d{4})/', $content);
        $parsed = [];
        
        foreach ($entries as $entry) {
            if (empty(trim($entry))) continue;
            
            $error = $this->parse_php_error($entry);
            if ($error) {
                if ($error_types !== 'all') {
                    if (stripos($error['error_type'], $error_types) === false) {
                        continue;
                    }
                }
                $parsed[] = $error;
            }
        }
        
        // Return most recent first
        $parsed = array_slice(array_reverse($parsed), 0, $limit);
        
        return [
            'success' => true,
            'total_errors' => count($parsed),
            'errors' => $parsed,
            'debug_log_path' => $log_path,
        ];
    }
    
    /**
     * Get debug log tail
     */
    public function get_debug_log_tail($request) {
        $log_path = $this->get_debug_log_path();
        
        if (!file_exists($log_path)) {
            return ['success' => false, 'error' => 'Debug log not found'];
        }
        
        $lines_count = $request->get_param('lines');
        $all_lines = file($log_path, FILE_IGNORE_NEW_LINES);
        $total = count($all_lines);
        $tail = array_slice($all_lines, -$lines_count);
        
        return [
            'success' => true,
            'total_lines' => $total,
            'showing_last' => count($tail),
            'content' => implode("\n", $tail),
        ];
    }
    
    /**
     * Clear debug log
     */
    public function clear_debug_log() {
        $log_path = $this->get_debug_log_path();
        
        if (file_put_contents($log_path, '') !== false) {
            return ['success' => true, 'message' => 'Debug log cleared'];
        }
        return ['success' => false, 'error' => 'Failed to clear debug log'];
    }
    
    /**
     * Analyze error with WordPress context
     */
    public function analyze_error($request) {
        $error_message = $request->get_param('error_message');
        $parsed = $this->parse_php_error($error_message);
        
        if (!$parsed) {
            return [
                'success' => false,
                'error' => 'Could not parse error message',
                'raw_input' => $error_message,
            ];
        }
        
        $result = [
            'success' => true,
            'parsed' => $parsed,
            'context' => [],
            'suggestions' => [],
        ];
        
        // File context
        $file = $parsed['file_path'];
        if (file_exists($file)) {
            $result['context']['file_exists'] = true;
            $result['context']['file_writable'] = is_writable($file);
            $result['context']['is_editable'] = $this->is_path_allowed($file);
            
            // Determine location type
            if (strpos($file, WP_PLUGIN_DIR) !== false) {
                $result['context']['location'] = 'plugin';
                preg_match('#' . preg_quote(WP_PLUGIN_DIR, '#') . '/([^/]+)#', $file, $m);
                $result['context']['plugin'] = $m[1] ?? null;
            } elseif (strpos($file, get_theme_root()) !== false) {
                $result['context']['location'] = 'theme';
            } elseif (strpos($file, ABSPATH . 'wp-includes') !== false) {
                $result['context']['location'] = 'wp-includes';
            } elseif (strpos($file, ABSPATH . 'wp-admin') !== false) {
                $result['context']['location'] = 'wp-admin';
            }
            
            // Get code context
            $lines = file($file);
            if ($lines) {
                $line_num = $parsed['line_number'];
                $start = max(0, $line_num - 6);
                $end = min(count($lines), $line_num + 5);
                
                $context_lines = [];
                for ($i = $start; $i < $end; $i++) {
                    $prefix = ($i + 1 == $line_num) ? '>>> ' : '    ';
                    $context_lines[] = $prefix . ($i + 1) . ': ' . rtrim($lines[$i]);
                }
                $result['code_context'] = implode("\n", $context_lines);
            }
        } else {
            $result['context']['file_exists'] = false;
        }
        
        // Suggestions
        $msg = strtolower($parsed['message']);
        if (strpos($msg, 'undefined function') !== false) {
            $result['suggestions'][] = 'Check if required plugin is active';
            $result['suggestions'][] = 'Verify function is defined before use';
        } elseif (strpos($msg, 'class not found') !== false) {
            $result['suggestions'][] = 'Check autoloading configuration';
            $result['suggestions'][] = 'Verify file is included';
        } elseif (strpos($msg, 'syntax error') !== false) {
            $result['suggestions'][] = 'Check for missing semicolons or brackets';
        }
        
        return $result;
    }
    
    // ============ FILE OPERATION METHODS ============
    
    /**
     * Read file contents
     */
    public function read_file($request) {
        $file_path = $this->resolve_path($request->get_param('file_path'));
        
        if (!$this->is_path_allowed($file_path)) {
            return ['success' => false, 'error' => 'Access denied: path is excluded'];
        }
        
        if (!file_exists($file_path)) {
            return ['success' => false, 'error' => 'File not found: ' . $file_path];
        }
        
        $lines = file($file_path);
        $total = count($lines);
        $start = max(0, $request->get_param('start_line') - 1);
        $end_param = $request->get_param('end_line');
        $end = $end_param == -1 ? $total : min($total, $end_param);
        
        $formatted = [];
        for ($i = $start; $i < $end; $i++) {
            $formatted[] = ($i + 1) . ': ' . rtrim($lines[$i]);
        }
        
        return [
            'success' => true,
            'file_path' => $file_path,
            'total_lines' => $total,
            'showing_lines' => ($start + 1) . '-' . $end,
            'content' => implode("\n", $formatted),
        ];
    }
    
    /**
     * Read file around a specific line
     */
    public function read_file_around_line($request) {
        $file_path = $this->resolve_path($request->get_param('file_path'));
        $line_num = $request->get_param('line_number');
        $context = $request->get_param('context_lines');
        
        if (!$this->is_path_allowed($file_path)) {
            return ['success' => false, 'error' => 'Access denied'];
        }
        
        if (!file_exists($file_path)) {
            return ['success' => false, 'error' => 'File not found'];
        }
        
        $lines = file($file_path);
        $total = count($lines);
        $start = max(0, $line_num - $context - 1);
        $end = min($total, $line_num + $context);
        
        $formatted = [];
        for ($i = $start; $i < $end; $i++) {
            $marker = ($i + 1 == $line_num) ? ' >>>' : '    ';
            $formatted[] = $marker . ' ' . ($i + 1) . ': ' . rtrim($lines[$i]);
        }
        
        // Find function at line
        $function = $this->find_function_at_line($lines, $line_num);
        
        return [
            'success' => true,
            'file_path' => $file_path,
            'target_line' => $line_num,
            'function_name' => $function,
            'total_lines' => $total,
            'showing_lines' => ($start + 1) . '-' . $end,
            'content' => implode("\n", $formatted),
        ];
    }
    
    /**
     * Find function name at line
     */
    private function find_function_at_line($lines, $target_line) {
        $current_func = null;
        $brace_count = 0;
        $in_function = false;
        
        for ($i = 0; $i < count($lines); $i++) {
            $line = $lines[$i];
            
            if (preg_match('/function\s+(\w+)\s*\(/', $line, $match) && !$in_function) {
                $current_func = $match[1];
                $in_function = true;
                $brace_count = 0;
            }
            
            if ($in_function) {
                $brace_count += substr_count($line, '{') - substr_count($line, '}');
                
                if ($i + 1 == $target_line) {
                    return $current_func;
                }
                
                if ($brace_count <= 0) {
                    $in_function = false;
                    $current_func = null;
                }
            }
        }
        
        return $current_func;
    }
    
    /**
     * Edit file - replace lines
     */
    public function edit_file($request) {
        $file_path = $this->resolve_path($request->get_param('file_path'));
        $line_num = $request->get_param('line_number');
        $new_content = $request->get_param('new_content');
        $end_line = $request->get_param('end_line');
        
        if (!$this->is_path_allowed($file_path)) {
            return ['success' => false, 'error' => 'Access denied'];
        }
        
        if (!file_exists($file_path)) {
            return ['success' => false, 'error' => 'File not found'];
        }
        
        if (!is_writable($file_path)) {
            return ['success' => false, 'error' => 'File not writable'];
        }
        
        $lines = file($file_path);
        $total = count($lines);
        
        if ($line_num < 1 || $line_num > $total) {
            return ['success' => false, 'error' => "Line $line_num out of range"];
        }
        
        // Create backup
        $backup = $file_path . '.bak.' . date('Ymd_His');
        file_put_contents($backup, implode('', $lines));
        
        // Calculate range
        $start_idx = $line_num - 1;
        $end_idx = ($end_line == -1) ? $start_idx + 1 : min($total, $end_line);
        
        $original = array_slice($lines, $start_idx, $end_idx - $start_idx);
        
        // Prepare new lines
        $new_lines = explode("\n", $new_content);
        $new_lines = array_map(function($l) {
            return rtrim($l) . "\n";
        }, $new_lines);
        
        // Replace
        array_splice($lines, $start_idx, $end_idx - $start_idx, $new_lines);
        
        if (file_put_contents($file_path, implode('', $lines)) !== false) {
            return [
                'success' => true,
                'file_path' => $file_path,
                'backup_path' => $backup,
                'lines_modified' => $end_line == -1 ? "$line_num" : "$line_num-$end_line",
                'original_content' => implode('', $original),
                'new_content' => implode('', $new_lines),
            ];
        }
        
        return ['success' => false, 'error' => 'Failed to write file'];
    }
    
    /**
     * Insert lines after specified line
     */
    public function insert_lines($request) {
        $file_path = $this->resolve_path($request->get_param('file_path'));
        $after_line = $request->get_param('after_line');
        $content = $request->get_param('content');
        
        if (!$this->is_path_allowed($file_path)) {
            return ['success' => false, 'error' => 'Access denied'];
        }
        
        if (!file_exists($file_path) || !is_writable($file_path)) {
            return ['success' => false, 'error' => 'File not found or not writable'];
        }
        
        $lines = file($file_path);
        
        // Backup
        $backup = $file_path . '.bak.' . date('Ymd_His');
        file_put_contents($backup, implode('', $lines));
        
        // Prepare new lines
        $new_lines = explode("\n", $content);
        $new_lines = array_map(function($l) {
            return rtrim($l) . "\n";
        }, $new_lines);
        
        // Insert
        $insert_idx = min($after_line, count($lines));
        array_splice($lines, $insert_idx, 0, $new_lines);
        
        if (file_put_contents($file_path, implode('', $lines)) !== false) {
            return [
                'success' => true,
                'file_path' => $file_path,
                'backup_path' => $backup,
                'inserted_after_line' => $after_line,
                'lines_inserted' => count($new_lines),
            ];
        }
        
        return ['success' => false, 'error' => 'Failed to write file'];
    }
    
    /**
     * Delete lines from file
     */
    public function delete_lines($request) {
        $file_path = $this->resolve_path($request->get_param('file_path'));
        $start = $request->get_param('start_line');
        $end = $request->get_param('end_line');
        
        if (!$this->is_path_allowed($file_path)) {
            return ['success' => false, 'error' => 'Access denied'];
        }
        
        if (!file_exists($file_path) || !is_writable($file_path)) {
            return ['success' => false, 'error' => 'File not found or not writable'];
        }
        
        $lines = file($file_path);
        
        // Backup
        $backup = $file_path . '.bak.' . date('Ymd_His');
        file_put_contents($backup, implode('', $lines));
        
        $start_idx = $start - 1;
        $end_idx = min(count($lines), $end);
        $deleted = implode('', array_slice($lines, $start_idx, $end_idx - $start_idx));
        
        array_splice($lines, $start_idx, $end_idx - $start_idx);
        
        if (file_put_contents($file_path, implode('', $lines)) !== false) {
            return [
                'success' => true,
                'file_path' => $file_path,
                'backup_path' => $backup,
                'deleted_lines' => "$start-$end",
                'deleted_content' => $deleted,
            ];
        }
        
        return ['success' => false, 'error' => 'Failed to write file'];
    }
    
    /**
     * Search in file
     */
    public function search_in_file($request) {
        $file_path = $this->resolve_path($request->get_param('file_path'));
        $pattern = $request->get_param('pattern');
        $is_regex = $request->get_param('regex');
        
        if (!$this->is_path_allowed($file_path)) {
            return ['success' => false, 'error' => 'Access denied'];
        }
        
        if (!file_exists($file_path)) {
            return ['success' => false, 'error' => 'File not found'];
        }
        
        $lines = file($file_path, FILE_IGNORE_NEW_LINES);
        $matches = [];
        
        foreach ($lines as $i => $line) {
            $found = $is_regex ? @preg_match($pattern, $line) : (stripos($line, $pattern) !== false);
            if ($found) {
                $matches[] = [
                    'line_number' => $i + 1,
                    'content' => $line,
                ];
            }
        }
        
        return [
            'success' => true,
            'file_path' => $file_path,
            'pattern' => $pattern,
            'total_matches' => count($matches),
            'matches' => $matches,
        ];
    }
    
    /**
     * Search across WordPress
     */
    public function search_wordpress($request) {
        $pattern = $request->get_param('pattern');
        $extensions = array_map('trim', explode(',', $request->get_param('file_extensions')));
        $max = $request->get_param('max_results');
        
        $matches = [];
        $files_searched = 0;
        
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator(ABSPATH, RecursiveDirectoryIterator::SKIP_DOTS)
        );
        
        foreach ($iterator as $file) {
            if (!$file->isFile()) continue;
            
            $path = $file->getPathname();
            
            // Skip excluded paths
            if (!$this->is_path_allowed($path)) continue;
            
            // Check extension
            $ext = pathinfo($path, PATHINFO_EXTENSION);
            if (!in_array($ext, $extensions)) continue;
            
            $files_searched++;
            
            $lines = @file($path, FILE_IGNORE_NEW_LINES);
            if (!$lines) continue;
            
            foreach ($lines as $i => $line) {
                if (stripos($line, $pattern) !== false) {
                    $matches[] = [
                        'file' => str_replace(ABSPATH, '', $path),
                        'line_number' => $i + 1,
                        'content' => substr($line, 0, 200),
                    ];
                    
                    if (count($matches) >= $max) {
                        return [
                            'success' => true,
                            'pattern' => $pattern,
                            'files_searched' => $files_searched,
                            'total_matches' => count($matches),
                            'truncated' => true,
                            'matches' => $matches,
                        ];
                    }
                }
            }
        }
        
        return [
            'success' => true,
            'pattern' => $pattern,
            'files_searched' => $files_searched,
            'total_matches' => count($matches),
            'truncated' => false,
            'matches' => $matches,
        ];
    }
    
    /**
     * List directory
     */
    public function list_directory($request) {
        $path = $request->get_param('path');
        $full_path = $path ? ABSPATH . ltrim($path, '/') : ABSPATH;
        
        if (!$this->is_path_allowed($full_path)) {
            return ['success' => false, 'error' => 'Access denied'];
        }
        
        if (!is_dir($full_path)) {
            return ['success' => false, 'error' => 'Directory not found'];
        }
        
        $items = [];
        foreach (scandir($full_path) as $item) {
            if ($item === '.' || $item === '..') continue;
            
            $item_path = $full_path . '/' . $item;
            $rel_path = str_replace(ABSPATH, '', $item_path);
            
            if (!$this->is_path_allowed($item_path)) continue;
            
            $items[] = [
                'name' => $item,
                'type' => is_dir($item_path) ? 'directory' : 'file',
                'path' => $rel_path,
            ];
        }
        
        usort($items, function($a, $b) {
            if ($a['type'] !== $b['type']) {
                return $a['type'] === 'directory' ? -1 : 1;
            }
            return strcasecmp($a['name'], $b['name']);
        });
        
        return [
            'success' => true,
            'path' => $path ?: '/',
            'items' => $items,
        ];
    }
    
    /**
     * Get function definition
     */
    public function get_function_definition($request) {
        $file_path = $this->resolve_path($request->get_param('file_path'));
        $func_name = $request->get_param('function_name');
        
        if (!$this->is_path_allowed($file_path)) {
            return ['success' => false, 'error' => 'Access denied'];
        }
        
        if (!file_exists($file_path)) {
            return ['success' => false, 'error' => 'File not found'];
        }
        
        $lines = file($file_path);
        $pattern = '/function\s+' . preg_quote($func_name, '/') . '\s*\(/';
        
        $start_line = null;
        foreach ($lines as $i => $line) {
            if (preg_match($pattern, $line)) {
                $start_line = $i + 1;
                break;
            }
        }
        
        if (!$start_line) {
            return ['success' => false, 'error' => "Function '$func_name' not found"];
        }
        
        // Find end of function
        $brace_count = 0;
        $end_line = $start_line;
        $in_func = false;
        
        for ($i = $start_line - 1; $i < count($lines); $i++) {
            $line = $lines[$i];
            $brace_count += substr_count($line, '{') - substr_count($line, '}');
            
            if ($brace_count > 0) $in_func = true;
            
            if ($in_func && $brace_count <= 0) {
                $end_line = $i + 1;
                break;
            }
        }
        
        $content = [];
        for ($i = $start_line - 1; $i < $end_line; $i++) {
            $content[] = ($i + 1) . ': ' . rtrim($lines[$i]);
        }
        
        return [
            'success' => true,
            'file_path' => $file_path,
            'function_name' => $func_name,
            'start_line' => $start_line,
            'end_line' => $end_line,
            'content' => implode("\n", $content),
        ];
    }
    
    /**
     * Validate PHP syntax
     */
    public function validate_php_syntax($request) {
        $file_path = $this->resolve_path($request->get_param('file_path'));
        
        if (!$this->is_path_allowed($file_path)) {
            return ['success' => false, 'error' => 'Access denied'];
        }
        
        if (!file_exists($file_path)) {
            return ['success' => false, 'error' => 'File not found'];
        }
        
        $output = [];
        $return_code = 0;
        exec('php -l ' . escapeshellarg($file_path) . ' 2>&1', $output, $return_code);
        
        return [
            'success' => true,
            'valid' => $return_code === 0,
            'message' => implode("\n", $output),
            'file_path' => $file_path,
        ];
    }
    
    /**
     * Restore backup
     */
    public function restore_backup($request) {
        $backup_path = $request->get_param('backup_path');
        
        if (!file_exists($backup_path)) {
            return ['success' => false, 'error' => 'Backup not found'];
        }
        
        // Extract original path
        $original = preg_replace('/\.bak\.\d{8}_\d{6}$/', '', $backup_path);
        
        if (!$this->is_path_allowed($original)) {
            return ['success' => false, 'error' => 'Access denied'];
        }
        
        $content = file_get_contents($backup_path);
        if (file_put_contents($original, $content) !== false) {
            return [
                'success' => true,
                'restored_file' => $original,
                'from_backup' => $backup_path,
            ];
        }
        
        return ['success' => false, 'error' => 'Failed to restore'];
    }
    
    /**
     * List backups for a file
     */
    public function list_backups($request) {
        $file_path = $this->resolve_path($request->get_param('file_path'));
        $dir = dirname($file_path);
        $base = basename($file_path);
        
        $backups = [];
        foreach (glob($dir . '/' . $base . '.bak.*') as $backup) {
            $backups[] = [
                'path' => $backup,
                'created' => date('Y-m-d H:i:s', filemtime($backup)),
                'size' => filesize($backup),
            ];
        }
        
        usort($backups, function($a, $b) {
            return $b['created'] <=> $a['created'];
        });
        
        return [
            'success' => true,
            'file_path' => $file_path,
            'backups' => $backups,
        ];
    }
    
    // ============ WORDPRESS CONTEXT METHODS ============
    
    /**
     * Health check
     */
    public function health_check() {
        $api_key_set = defined('WP_MCP_API_KEY') && WP_MCP_API_KEY !== 'CHANGE_THIS_TO_YOUR_SECURE_KEY';
        
        return [
            'success' => true,
            'version' => self::VERSION,
            'wordpress_version' => get_bloginfo('version'),
            'php_version' => PHP_VERSION,
            'api_key_configured' => $api_key_set,
            'api_key_hint' => $api_key_set ? null : 'Edit wp-mcp-error-helper.php and set WP_MCP_API_KEY',
            'debug_enabled' => defined('WP_DEBUG') && WP_DEBUG,
            'debug_log_path' => $this->get_debug_log_path(),
            'debug_log_exists' => file_exists($this->get_debug_log_path()),
        ];
    }
    
    /**
     * Get site info
     */
    public function get_site_info() {
        global $wp_version;
        
        return [
            'success' => true,
            'data' => [
                'wordpress_version' => $wp_version,
                'php_version' => PHP_VERSION,
                'site_url' => site_url(),
                'home_url' => home_url(),
                'wp_debug' => defined('WP_DEBUG') && WP_DEBUG,
                'wp_debug_log' => defined('WP_DEBUG_LOG') ? WP_DEBUG_LOG : false,
                'memory_limit' => ini_get('memory_limit'),
                'abspath' => ABSPATH,
                'wp_content_dir' => WP_CONTENT_DIR,
                'wp_plugin_dir' => WP_PLUGIN_DIR,
            ],
        ];
    }
    
    /**
     * Get plugins info
     */
    public function get_plugins_info() {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        
        $plugins = [];
        $active = get_option('active_plugins', []);
        
        foreach (get_plugins() as $file => $data) {
            $plugins[] = [
                'name' => $data['Name'],
                'version' => $data['Version'],
                'file' => $file,
                'path' => WP_PLUGIN_DIR . '/' . $file,
                'active' => in_array($file, $active),
            ];
        }
        
        return [
            'success' => true,
            'data' => [
                'plugins' => $plugins,
                'total' => count($plugins),
                'active' => count($active),
            ],
        ];
    }
    
    /**
     * Get theme info
     */
    public function get_theme_info() {
        $theme = wp_get_theme();
        
        return [
            'success' => true,
            'data' => [
                'name' => $theme->get('Name'),
                'version' => $theme->get('Version'),
                'template' => $theme->get_template(),
                'stylesheet' => $theme->get_stylesheet(),
                'is_child_theme' => is_child_theme(),
                'template_directory' => get_template_directory(),
                'stylesheet_directory' => get_stylesheet_directory(),
            ],
        ];
    }
    
    /**
     * Get database info
     */
    public function get_database_info() {
        global $wpdb;
        
        $tables = [];
        foreach ($wpdb->get_results("SHOW TABLES", ARRAY_N) as $row) {
            $tables[] = [
                'name' => $row[0],
                'is_wp_table' => strpos($row[0], $wpdb->prefix) === 0,
            ];
        }
        
        return [
            'success' => true,
            'data' => [
                'prefix' => $wpdb->prefix,
                'tables' => $tables,
                'total_tables' => count($tables),
            ],
        ];
    }
    
    /**
     * Get hooks info
     */
    public function get_hooks_info() {
        global $wp_filter;
        
        $search = isset($_GET['search']) ? sanitize_text_field($_GET['search']) : '';
        $hooks = [];
        
        foreach ($wp_filter as $tag => $hook) {
            if ($search && stripos($tag, $search) === false) continue;
            
            $callbacks = 0;
            foreach ($hook->callbacks as $priority => $funcs) {
                $callbacks += count($funcs);
            }
            
            $hooks[$tag] = $callbacks;
            
            if (count($hooks) >= 100) break;
        }
        
        return [
            'success' => true,
            'data' => [
                'hooks' => $hooks,
                'total' => count($hooks),
            ],
        ];
    }
    
    /**
     * Get constants
     */
    public function get_constants() {
        $constants = [
            'ABSPATH' => ABSPATH,
            'WP_CONTENT_DIR' => WP_CONTENT_DIR,
            'WP_PLUGIN_DIR' => WP_PLUGIN_DIR,
            'WP_DEBUG' => defined('WP_DEBUG') ? WP_DEBUG : null,
            'WP_DEBUG_LOG' => defined('WP_DEBUG_LOG') ? WP_DEBUG_LOG : null,
            'WP_DEBUG_DISPLAY' => defined('WP_DEBUG_DISPLAY') ? WP_DEBUG_DISPLAY : null,
            'WP_MEMORY_LIMIT' => defined('WP_MEMORY_LIMIT') ? WP_MEMORY_LIMIT : null,
            'DISALLOW_FILE_EDIT' => defined('DISALLOW_FILE_EDIT') ? DISALLOW_FILE_EDIT : null,
        ];
        
        return [
            'success' => true,
            'data' => array_filter($constants, function($v) { return $v !== null; }),
        ];
    }
    
    /**
     * Locate function/class definition
     */
    public function locate_definition($request) {
        $name = $request->get_param('name');
        $type = $request->get_param('type');
        
        $result = ['name' => $name, 'type' => $type, 'found' => false];
        
        try {
            switch ($type) {
                case 'function':
                    if (function_exists($name)) {
                        $ref = new ReflectionFunction($name);
                        $result['found'] = true;
                        $result['file'] = $ref->getFileName();
                        $result['line'] = $ref->getStartLine();
                        $result['end_line'] = $ref->getEndLine();
                    }
                    break;
                    
                case 'class':
                    if (class_exists($name)) {
                        $ref = new ReflectionClass($name);
                        $result['found'] = true;
                        $result['file'] = $ref->getFileName();
                        $result['line'] = $ref->getStartLine();
                        $result['end_line'] = $ref->getEndLine();
                    }
                    break;
                    
                case 'method':
                    if (strpos($name, '::') !== false) {
                        list($class, $method) = explode('::', $name);
                        if (method_exists($class, $method)) {
                            $ref = new ReflectionMethod($class, $method);
                            $result['found'] = true;
                            $result['file'] = $ref->getFileName();
                            $result['line'] = $ref->getStartLine();
                            $result['end_line'] = $ref->getEndLine();
                        }
                    }
                    break;
            }
        } catch (Exception $e) {
            $result['error'] = $e->getMessage();
        }
        
        return ['success' => true, 'data' => $result];
    }
    
    /**
     * Log shutdown errors with extra context
     */
    public function log_shutdown_errors() {
        $error = error_get_last();
        
        if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
            $log = WP_CONTENT_DIR . '/mcp-errors.log';
            $entry = '[' . date('d-M-Y H:i:s T') . '] ' . json_encode($error) . "\n";
            @error_log($entry, 3, $log);
        }
    }
    
    // ============ WP-CLI METHODS ============
    
    /**
     * Find WP-CLI executable path
     */
    private function get_wp_cli_path() {
        // Common WP-CLI locations
        $paths = [
            '/usr/local/bin/wp',
            '/usr/bin/wp',
            '/opt/homebrew/bin/wp',
            ABSPATH . 'wp-cli.phar',
            ABSPATH . '../wp-cli.phar',
        ];
        
        foreach ($paths as $path) {
            if (file_exists($path) && is_executable($path)) {
                return $path;
            }
        }
        
        // Try to find via which
        $which = @shell_exec('which wp 2>/dev/null');
        if ($which && trim($which)) {
            return trim($which);
        }
        
        return null;
    }
    
    /**
     * Execute a WP-CLI command
     * 
     * Uses multiple flags to ensure WP-CLI works even when site has fatal errors:
     * - --skip-themes: Don't load themes (avoids theme fatal errors)
     * - --skip-plugins: Don't load plugins (avoids plugin fatal errors)
     * - --skip-packages: Don't load PHAR packaged commands
     * - --allow-root: Allow running as root user if needed
     * - --no-color: Clean output for parsing
     * - --quiet: Suppress informational messages (for cleaner output)
     */
    private function execute_wp_cli($command, $format = 'json', $skip_loading = true) {
        $wp_cli = $this->get_wp_cli_path();
        
        if (!$wp_cli) {
            return [
                'success' => false,
                'error' => 'WP-CLI not found. Please install WP-CLI on this server.',
            ];
        }
        
        // Build command - use shell_exec friendly format
        $full_command = escapeshellarg($wp_cli) . ' ' . $command;
        
        // Add WordPress path
        $full_command .= ' --path=' . escapeshellarg(ABSPATH);
        
        // Add JSON format if requested
        if ($format === 'json') {
            $full_command .= ' --format=json';
        }
        
        // Resilience flags - these ensure WP-CLI works even when site has fatal errors
        if ($skip_loading) {
            $full_command .= ' --skip-themes';      // Don't load any themes
            $full_command .= ' --skip-plugins';     // Don't load any plugins
            $full_command .= ' --skip-packages';    // Don't load PHAR packages
        }
        
        // Additional stability flags
        $full_command .= ' --allow-root';           // Allow running as root
        $full_command .= ' --no-color';             // No ANSI colors for clean output
        
        // Redirect stderr to stdout
        $full_command .= ' 2>&1';
        
        // Execute
        $output = [];
        $return_code = 0;
        exec($full_command, $output, $return_code);
        
        $output_str = implode("\n", $output);
        
        // Try to parse JSON
        $json_result = null;
        if ($format === 'json') {
            $json_result = json_decode($output_str, true);
        }
        
        return [
            'success' => $return_code === 0,
            'return_code' => $return_code,
            'output' => $output_str,
            'data' => $json_result,
            'command' => $command,
            'flags_used' => $skip_loading 
                ? ['--skip-themes', '--skip-plugins', '--skip-packages', '--allow-root', '--no-color']
                : ['--allow-root', '--no-color'],
        ];
    }
    
    /**
     * Run arbitrary WP-CLI command
     */
    public function run_wp_cli($request) {
        $command = $request->get_param('command');
        
        // Security: Block dangerous commands
        $blocked = ['db export', 'db import', 'db drop', 'db reset', 'db create', 'eval', 'eval-file', 'shell'];
        foreach ($blocked as $block) {
            if (stripos($command, $block) === 0) {
                return [
                    'success' => false,
                    'error' => "Command '$block' is blocked for security reasons.",
                ];
            }
        }
        
        // Determine if command should use JSON format
        $use_json = !preg_match('/--format=/', $command);
        
        return $this->execute_wp_cli($command, $use_json ? 'json' : 'text');
    }
    
    // ---- Plugin Commands ----
    
    public function wp_cli_plugin_list() {
        return $this->execute_wp_cli('plugin list');
    }
    
    public function wp_cli_plugin_activate($request) {
        $plugin = $request->get_param('plugin');
        return $this->execute_wp_cli('plugin activate ' . escapeshellarg($plugin), 'text');
    }
    
    public function wp_cli_plugin_deactivate($request) {
        $plugin = $request->get_param('plugin');
        return $this->execute_wp_cli('plugin deactivate ' . escapeshellarg($plugin), 'text');
    }
    
    public function wp_cli_plugin_install($request) {
        $plugin = $request->get_param('plugin');
        $activate = $request->get_param('activate') ? ' --activate' : '';
        return $this->execute_wp_cli('plugin install ' . escapeshellarg($plugin) . $activate, 'text');
    }
    
    public function wp_cli_plugin_delete($request) {
        $plugin = $request->get_param('plugin');
        return $this->execute_wp_cli('plugin delete ' . escapeshellarg($plugin), 'text');
    }
    
    public function wp_cli_plugin_update($request) {
        $plugin = $request->get_param('plugin');
        if ($plugin === '--all') {
            return $this->execute_wp_cli('plugin update --all', 'text');
        }
        return $this->execute_wp_cli('plugin update ' . escapeshellarg($plugin), 'text');
    }
    
    // ---- Theme Commands ----
    
    public function wp_cli_theme_list() {
        return $this->execute_wp_cli('theme list');
    }
    
    public function wp_cli_theme_activate($request) {
        $theme = $request->get_param('theme');
        return $this->execute_wp_cli('theme activate ' . escapeshellarg($theme), 'text');
    }
    
    public function wp_cli_theme_install($request) {
        $theme = $request->get_param('theme');
        $activate = $request->get_param('activate') ? ' --activate' : '';
        return $this->execute_wp_cli('theme install ' . escapeshellarg($theme) . $activate, 'text');
    }
    
    public function wp_cli_theme_delete($request) {
        $theme = $request->get_param('theme');
        return $this->execute_wp_cli('theme delete ' . escapeshellarg($theme), 'text');
    }
    
    // ---- Core Commands ----
    
    public function wp_cli_core_version() {
        $result = $this->execute_wp_cli('core version', 'text');
        if ($result['success']) {
            $result['version'] = trim($result['output']);
        }
        return $result;
    }
    
    public function wp_cli_core_check_update() {
        return $this->execute_wp_cli('core check-update');
    }
    
    // ---- Cache Commands ----
    
    public function wp_cli_cache_flush() {
        return $this->execute_wp_cli('cache flush', 'text');
    }
    
    // ---- Database Commands ----
    
    public function wp_cli_db_check() {
        return $this->execute_wp_cli('db check', 'text');
    }
    
    public function wp_cli_db_optimize() {
        return $this->execute_wp_cli('db optimize', 'text');
    }
    
    // ---- Option Commands ----
    
    public function wp_cli_option_get($request) {
        $option = $request->get_param('option');
        $result = $this->execute_wp_cli('option get ' . escapeshellarg($option), 'text');
        if ($result['success']) {
            $result['value'] = trim($result['output']);
        }
        return $result;
    }
    
    public function wp_cli_option_update($request) {
        $option = $request->get_param('option');
        $value = $request->get_param('value');
        return $this->execute_wp_cli('option update ' . escapeshellarg($option) . ' ' . escapeshellarg($value), 'text');
    }
    
    // ---- User Commands ----
    
    public function wp_cli_user_list() {
        return $this->execute_wp_cli('user list');
    }
    
    // ---- Rewrite Commands ----
    
    public function wp_cli_rewrite_flush() {
        return $this->execute_wp_cli('rewrite flush', 'text');
    }
}

// Initialize
new WP_MCP_Error_Helper();
