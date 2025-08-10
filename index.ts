#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
  ToolSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { spawn } from 'child_process';
import { promisify } from 'util';

interface ScanResult {
  host: string;
  ports: PortInfo[];
  hostInfo?: {
    hostname?: string;
    osGuess?: string;
    macAddress?: string;
    vendor?: string;
  };
}

interface PortInfo {
  port: number;
  protocol: 'tcp' | 'udp';
  state: 'open' | 'closed' | 'filtered';
  service?: string;
  version?: string;
}

class PortScannerMCPServer {
  private server: Server;
  private defaultPorts = [22, 23, 80, 443, 8080, 3000];

  constructor() {
    this.server = new Server(
      {
        name: 'port-scanner-mcp-server',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolHandlers();
  }

  private setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'scan_ports',
            description: 'Scan specified ports on target hosts using nmap',
            inputSchema: {
              type: 'object',
              properties: {
                targets: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'IP addresses or hostnames to scan',
                },
                ports: {
                  type: 'array',
                  items: { type: 'number' },
                  description: 'Ports to scan (defaults to 22,23,80,443,8080,3000)',
                },
                scan_type: {
                  type: 'string',
                  enum: ['tcp', 'udp', 'both'],
                  default: 'tcp',
                  description: 'Type of port scan to perform',
                },
                service_detection: {
                  type: 'boolean',
                  default: true,
                  description: 'Enable service version detection',
                },
                os_detection: {
                  type: 'boolean',
                  default: false,
                  description: 'Enable OS detection (requires root privileges)',
                },
              },
              required: ['targets'],
            },
          } as Tool,
          {
            name: 'network_discovery',
            description: 'Discover live hosts on a network segment',
            inputSchema: {
              type: 'object',
              properties: {
                network: {
                  type: 'string',
                  description: 'Network range in CIDR notation (e.g., 192.168.1.0/24)',
                },
                ping_scan: {
                  type: 'boolean',
                  default: true,
                  description: 'Use ping scan for host discovery',
                },
              },
              required: ['network'],
            },
          } as Tool,
          {
            name: 'service_scan',
            description: 'Perform detailed service enumeration on specific ports',
            inputSchema: {
              type: 'object',
              properties: {
                target: {
                  type: 'string',
                  description: 'IP address or hostname to scan',
                },
                port: {
                  type: 'number',
                  description: 'Port number to examine in detail',
                },
              },
              required: ['target', 'port'],
            },
          } as Tool,
        ],
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      try {
        switch (request.params.name) {
          case 'scan_ports':
            return await this.handlePortScan(request.params.arguments);
          case 'network_discovery':
            return await this.handleNetworkDiscovery(request.params.arguments);
          case 'service_scan':
            return await this.handleServiceScan(request.params.arguments);
          default:
            throw new Error(`Unknown tool: ${request.params.name}`);
        }
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: `Error: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    });
  }

  private async executeNmap(args: string[]): Promise<string> {
    return new Promise((resolve, reject) => {
      const nmap = spawn('nmap', args);
      let stdout = '';
      let stderr = '';

      nmap.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      nmap.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      nmap.on('close', (code) => {
        if (code === 0) {
          resolve(stdout);
        } else {
          let errorMessage = `nmap exited with code ${code}: ${stderr}`;
          if (stderr.includes('requires root privileges')) {
            errorMessage += '\n\nSuggestion: This scan type requires elevated privileges. Try using TCP connect scan (-sT) or run as root if authorized.';
          }
          reject(new Error(errorMessage));
        }
      });

      nmap.on('error', (error) => {
        reject(new Error(`Failed to execute nmap: ${error.message}`));
      });
    });
  }

  private parseNmapOutput(output: string): ScanResult[] {
    const results: ScanResult[] = [];
    const lines = output.split('\n');
    let currentHost: ScanResult | null = null;

    for (const line of lines) {
      const trimmedLine = line.trim();
      
      // Host detection
      const hostMatch = trimmedLine.match(/^Nmap scan report for (.+)$/);
      if (hostMatch) {
        if (currentHost) {
          results.push(currentHost);
        }
        currentHost = {
          host: hostMatch[1],
          ports: [],
          hostInfo: {},
        };
        continue;
      }

      // Port information
      const portMatch = trimmedLine.match(/^(\d+)\/(tcp|udp)\s+(\w+)\s*(.*)$/);
      if (portMatch && currentHost) {
        const [, portNum, protocol, state, serviceInfo] = portMatch;
        const portInfo: PortInfo = {
          port: parseInt(portNum),
          protocol: protocol as 'tcp' | 'udp',
          state: state as 'open' | 'closed' | 'filtered',
        };

        if (serviceInfo) {
          const serviceParts = serviceInfo.split(/\s+/);
          if (serviceParts[0]) {
            portInfo.service = serviceParts[0];
          }
          if (serviceParts.length > 1) {
            portInfo.version = serviceParts.slice(1).join(' ');
          }
        }

        currentHost.ports.push(portInfo);
        continue;
      }

      // MAC address and vendor
      const macMatch = trimmedLine.match(/^MAC Address: ([A-Fa-f0-9:]{17})\s*\((.+)\)$/);
      if (macMatch && currentHost) {
        currentHost.hostInfo!.macAddress = macMatch[1];
        currentHost.hostInfo!.vendor = macMatch[2];
        continue;
      }

      // OS detection
      const osMatch = trimmedLine.match(/^Running: (.+)$/);
      if (osMatch && currentHost) {
        currentHost.hostInfo!.osGuess = osMatch[1];
        continue;
      }
    }

    if (currentHost) {
      results.push(currentHost);
    }

    return results;
  }

  private async handlePortScan(args: any) {
    const targets = args.targets as string[];
    const ports = args.ports || this.defaultPorts;
    const scanType = args.scan_type || 'tcp';
    const serviceDetection = args.service_detection !== false;
    const osDetection = args.os_detection || false;

    const nmapArgs = ['-oN', '-']; // Output to stdout

    // Port specification
    nmapArgs.push('-p', ports.join(','));

    // Scan type
    if (scanType === 'tcp' || scanType === 'both') {
      nmapArgs.push('-sT'); // TCP connect scan (doesn't require root)
    }
    if (scanType === 'udp' || scanType === 'both') {
      // UDP scan requires root, skip or warn user
      console.warn('UDP scan requires root privileges, skipping UDP scan');
    }

    // Service detection
    if (serviceDetection) {
      nmapArgs.push('-sV');
    }

    // OS detection requires root, skip if not available
    if (osDetection) {
      console.warn('OS detection requires root privileges, skipping OS detection');
    }

    // Add targets
    nmapArgs.push(...targets);

    try {
      const output = await this.executeNmap(nmapArgs);
      const results = this.parseNmapOutput(output);

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(results, null, 2),
          },
        ],
      };
    } catch (error) {
      throw new Error(`Port scan failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private async handleNetworkDiscovery(args: any) {
    const network = args.network as string;
    const pingScan = args.ping_scan !== false;

    const nmapArgs = ['-oN', '-'];

    if (pingScan) {
      nmapArgs.push('-sn'); // Ping scan only
    } else {
      nmapArgs.push('-Pn'); // Skip ping
    }

    nmapArgs.push(network);

    try {
      const output = await this.executeNmap(nmapArgs);
      const results = this.parseNmapOutput(output);

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(results, null, 2),
          },
        ],
      };
    } catch (error) {
      throw new Error(`Network discovery failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private async handleServiceScan(args: any) {
    const target = args.target as string;
    const port = args.port as number;

    const nmapArgs = [
      '-oN', '-',
      '-sT', // TCP connect scan (no root required)
      '-sV', // Service version detection
      '-sC', // Default scripts
      '-p', port.toString(),
      target
    ];

    try {
      const output = await this.executeNmap(nmapArgs);
      const results = this.parseNmapOutput(output);

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(results, null, 2),
          },
        ],
      };
    } catch (error) {
      throw new Error(`Service scan failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
  }
}

const server = new PortScannerMCPServer();
server.run().catch((error) => {
  console.error('Server error:', error);
  process.exit(1);
});