# Port Scanner MCP Server

An MCP (Model Context Protocol) server that provides network port scanning capabilities using nmap. This server is designed for defensive security purposes, network discovery, and security assessment.

## Features

- **Port Scanning**: Scan specified ports on target hosts with customizable port lists
- **Network Discovery**: Discover live hosts on network segments
- **Service Detection**: Identify services and versions running on open ports
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **JSON Output**: All results returned in structured JSON format
- **No Root Required**: Uses TCP connect scans that don't require elevated privileges

## Default Ports

The server scans these ports by default if no custom ports are specified:
- 22 (SSH)
- 23 (Telnet)
- 80 (HTTP)
- 443 (HTTPS)
- 8080 (HTTP Alternative)
- 3000 (Development Server)

## Tools Available

### `scan_ports`
Scan specified ports on target hosts using nmap.

**Parameters:**
- `targets` (required): Array of IP addresses or hostnames to scan
- `ports` (optional): Array of port numbers (defaults to [22, 23, 80, 443, 8080, 3000])
- `scan_type` (optional): "tcp", "udp", or "both" (default: "tcp")
- `service_detection` (optional): Enable service version detection (default: true)
- `os_detection` (optional): Enable OS detection (default: false, not available without root)

### `network_discovery`
Discover live hosts on a network segment.

**Parameters:**
- `network` (required): Network range in CIDR notation (e.g., "192.168.1.0/24")
- `ping_scan` (optional): Use ping scan for host discovery (default: true)

### `service_scan`
Perform detailed service enumeration on a specific port.

**Parameters:**
- `target` (required): IP address or hostname to scan
- `port` (required): Port number to examine in detail

## Installation

### Using Claude Code (Recommended)

Install the MCP server directly from npm:

```bash
claude mcp add port-scanner npx @zibdie/port-scanner-mcp@latest
```

### Manual Installation

1. Install the package globally:
```bash
npm install -g @zibdie/port-scanner-mcp
```

2. Add to your Claude Code configuration manually in your `.claude.json`:
```json
{
  "mcp": {
    "servers": {
      "port-scanner": {
        "command": "@zibdie/port-scanner-mcp"
      }
    }
  }
}
```

## Prerequisites

### All Platforms
- Node.js (version 24 or higher)
- nmap installed on the system

### Windows

**Using Chocolatey (Recommended):**
```powershell
# Install Chocolatey first if you haven't: https://chocolatey.org/install
choco install nmap
```

**Using winget:**
```powershell
winget install Insecure.Nmap
```

**Manual Installation:**
Download and install from [https://nmap.org/download.html](https://nmap.org/download.html)

### macOS

**Using Homebrew (Recommended):**
```bash
# Install Homebrew first if you haven't: https://brew.sh
brew install nmap
```

**Manual Installation:**
Download and install from [https://nmap.org/download.html](https://nmap.org/download.html)

### Linux

**Ubuntu/Debian (using apt-get):**
```bash
sudo apt-get update
sudo apt-get install nmap
```

**CentOS/RHEL/Fedora:**
```bash
# CentOS/RHEL 7 and older
sudo yum install nmap

# CentOS/RHEL 8+ and Fedora
sudo dnf install nmap
```

**Arch Linux:**
```bash
sudo pacman -S nmap
```

## Usage with Claude Code

After installation, use the `/mcp` command to see available tools, then invoke them directly:

### Scanning Default Ports
```
Use the scan_ports tool to scan 192.168.1.1 and google.com for default ports
```

### Custom Port Scan
```
Use scan_ports to scan 192.168.1.100 for ports 21, 22, 80, 443, and 8080 with service detection
```

### Network Discovery
```
Use network_discovery to find all devices on the 192.168.1.0/24 network
```

### Detailed Service Scan
```
Use service_scan to analyze port 80 on 192.168.1.100 in detail
```

## API Usage Examples

If using the MCP server programmatically:

### Scanning Default Ports
```json
{
  "tool": "scan_ports",
  "arguments": {
    "targets": ["192.168.1.1", "google.com"]
  }
}
```

### Custom Port Scan
```json
{
  "tool": "scan_ports",
  "arguments": {
    "targets": ["192.168.1.100"],
    "ports": [21, 22, 80, 443, 8080],
    "service_detection": true
  }
}
```

### Network Discovery
```json
{
  "tool": "network_discovery",
  "arguments": {
    "network": "192.168.1.0/24"
  }
}
```

### Detailed Service Scan
```json
{
  "tool": "service_scan",
  "arguments": {
    "target": "192.168.1.100",
    "port": 80
  }
}
```

## Troubleshooting

### Windows Issues
- Ensure nmap is in your PATH environment variable
- On Windows, nmap might require running as Administrator for some scan types
- If you get "command not found" errors, restart your terminal after installing nmap

### Permission Issues
- The server uses TCP connect scans (`-sT`) which don't require root/administrator privileges
- OS detection and UDP scans are disabled as they require elevated privileges
- If you need advanced scanning features, run Claude Code as administrator/root

### Firewall Issues
- Windows Defender and antivirus software may flag nmap usage
- Add exceptions for nmap.exe and node.exe if needed
- Corporate firewalls may block outbound scans

## Security Notice

This tool is intended for defensive security purposes only:
- Network security assessment
- Vulnerability discovery on owned systems
- Network inventory and monitoring
- Penetration testing with proper authorization

Always ensure you have proper authorization before scanning networks or systems you do not own.

## Output Format

All scan results are returned in JSON format with the following structure:

```json
[
  {
    "host": "192.168.1.100",
    "ports": [
      {
        "port": 22,
        "protocol": "tcp",
        "state": "open",
        "service": "ssh",
        "version": "OpenSSH 8.2"
      }
    ],
    "hostInfo": {
      "hostname": "server.local",
      "macAddress": "00:11:22:33:44:55",
      "vendor": "Dell Inc."
    }
  }
]
```

## Contributing

This is an open-source project. Feel free to contribute by:
- Reporting bugs
- Suggesting features
- Submitting pull requests

## License

MIT License - see LICENSE file for details.