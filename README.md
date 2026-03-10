# Cloudways MCP Server — WordPress MU-Plugin

A single-file must-use WordPress plugin that turns your Cloudways-hosted WordPress site into a Model Context Protocol (MCP) server. Enables AI assistants like **Cursor**, **ChatGPT**, **Claude**, and any MCP-compatible client to manage your WordPress site through natural language.

## What is MCP?

The [Model Context Protocol](https://modelcontextprotocol.io) is an open standard that lets AI applications interact with external tools and data sources. This plugin implements the **Streamable HTTP transport** (stateless, JSON responses) so any MCP client can connect via a single HTTP endpoint.

## Requirements

- **Cloudways hosting** (plugin silently deactivates on other hosts)
- WordPress 5.9+
- PHP 7.4+
- HTTPS enabled (required in production)

## Installation

This is a **single-file must-use (MU) plugin**. MU-plugins load automatically and cannot be disabled from the admin panel.

1. Upload `cw-mcp.php` to `wp-content/mu-plugins/cw-mcp.php`
2. Visit your WordPress admin panel — the plugin is already active
3. Go to **Settings → Cloudways MCP** to get your API key and endpoint URL

That's it. One file, zero configuration.

## Configuration

### 1. Generate an API Key

Navigate to **Settings → Cloudways MCP** in wp-admin:

1. Click **Generate API Key**
2. Choose which WordPress user to bind the key to (determines permissions)
3. Set an expiry period
4. **Copy the key immediately** — it's only shown once

### 2. Connect Your AI Tool

#### Cursor IDE

Create or edit `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "my-wordpress-site": {
      "url": "https://your-site.com/wp-json/cw-mcp/v1/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_API_KEY_HERE"
      }
    }
  }
}
```

#### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "my-wordpress-site": {
      "transport": "streamable-http",
      "url": "https://your-site.com/wp-json/cw-mcp/v1/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_API_KEY_HERE"
      }
    }
  }
}
```

#### Any MCP Client

```
POST https://your-site.com/wp-json/cw-mcp/v1/mcp
Authorization: Bearer YOUR_API_KEY_HERE
Content-Type: application/json
```

## 33 MCP Tools

| Tool | Description | Capability |
|------|-------------|------------|
| `wp_get_posts` | List/search posts | read |
| `wp_get_post` | Get single post | read |
| `wp_create_post` | Create post | edit_posts |
| `wp_update_post` | Update post | edit_posts |
| `wp_delete_post` | Delete/trash post | delete_posts |
| `wp_get_pages` | List pages | read |
| `wp_create_page` | Create page | edit_pages |
| `wp_update_page` | Update page | edit_pages |
| `wp_delete_page` | Delete/trash page | delete_pages |
| `wp_get_media` | List media | read |
| `wp_upload_media` | Upload file (base64) | upload_files |
| `wp_delete_media` | Delete media | upload_files |
| `wp_get_comments` | List comments | read |
| `wp_create_comment` | Add comment | moderate_comments |
| `wp_update_comment` | Update comment | moderate_comments |
| `wp_delete_comment` | Delete comment | moderate_comments |
| `wp_get_users` | List users | list_users |
| `wp_get_plugins` | List plugins | read |
| `wp_activate_plugin` | Activate plugin | activate_plugins |
| `wp_deactivate_plugin` | Deactivate plugin | activate_plugins |
| `wp_get_themes` | List themes | read |
| `wp_activate_theme` | Switch theme | switch_themes |
| `wp_get_categories` | List categories | read |
| `wp_create_category` | Create category | manage_categories |
| `wp_get_tags` | List tags | read |
| `wp_create_tag` | Create tag | manage_categories |
| `wp_get_option` | Read option (allowlisted) | read |
| `wp_update_option` | Update option (allowlisted) | manage_options |
| `wp_list_allowed_options` | List accessible options | read |
| `wp_get_menus` | List nav menus | read |
| `wp_get_site_info` | Site info & stats | read |
| `wp_get_site_health` | Site health diagnostics | manage_options |
| `wp_search` | Search all content | read |

## 6 MCP Resources

| URI | Description |
|-----|-------------|
| `wordpress://site/info` | Site metadata |
| `wordpress://posts/recent` | 10 most recent posts |
| `wordpress://posts/{id}` | Single post by ID |
| `wordpress://pages/{id}` | Single page by ID |
| `wordpress://plugins/active` | Active plugins list |
| `wordpress://theme/active` | Active theme info |

## Security Checklist (All Implemented)

| # | Feature | Priority |
|---|---------|:--------:|
| 1 | HTTPS enforcement (hard block) | P0 |
| 2 | API keys stored as SHA-256 hashes | P0 |
| 3 | Role-bound API keys (admin, editor, author) | P0 |
| 4 | Per-tool WordPress capability checks | P0 |
| 5 | Options allowlist (prevents reading secrets) | P0 |
| 6 | Replay protection (timestamp + nonce) | P1 |
| 7 | Audit logging (custom DB table, 30-day auto-prune) | P1 |
| 8 | Per-tool enable/disable toggles in admin | P1 |
| 9 | Multiple API keys with different roles | P1 |
| 10 | Rate limiting (configurable requests/window) | P1 |
| 11 | Sensitive data redaction in audit logs | P1 |
| 12 | IP allowlisting (single IP + CIDR) | P2 |
| 13 | Key expiry & rotation | P2 |
| 14 | Destructive operation confirmation mode | P2 |
| 15 | Hidden from REST API discovery index | P2 |

## Cloudways-Only Enforcement

The plugin checks multiple signals to verify it's running on Cloudways:

1. Application path structure (`/home/*/applications/*/public_html`)
2. Cloudways system directories (`/opt/cloudways`, `/etc/cw`)
3. Cloudways agent process marker

For local development/testing, add to `wp-config.php`:

```php
define( 'CW_MCP_FORCE_ENABLE', true );
```

## Per-Site Identification

Each site gets a unique UUID stored in `wp_options`. The MCP server includes this in `initialize` responses so AI clients always know which site they're connected to.

## Testing

```bash
# Initialize
curl -X POST https://your-site.com/wp-json/cw-mcp/v1/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'

# List tools
curl -X POST https://your-site.com/wp-json/cw-mcp/v1/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_KEY" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

# Call a tool
curl -X POST https://your-site.com/wp-json/cw-mcp/v1/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_KEY" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"wp_get_site_info","arguments":{}}}'
```

Or use the MCP Inspector:

```bash
npx -y @modelcontextprotocol/inspector
```

## License

GPL-2.0-or-later
