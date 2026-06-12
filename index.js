#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import fetch from 'node-fetch';
import https from 'https';
import crypto from 'crypto';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Load environment variables from .env file
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const envPath = join(__dirname, '../.env');

try {
  const envFile = readFileSync(envPath, 'utf8');
  const envVars = envFile.split('\n').filter(line => line.includes('=') && !line.trim().startsWith('#'));
  for (const line of envVars) {
    const [key, ...values] = line.split('=');
    // Validate key is a valid environment variable name (alphanumeric and underscore only)
    if (key && values.length > 0 && /^[A-Z_][A-Z0-9_]*$/.test(key.trim())) {
      // Remove surrounding quotes if present and trim
      let value = values.join('=').trim();
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      // Real environment variables take precedence over the .env file
      if (!(key.trim() in process.env)) {
        process.env[key.trim()] = value;
      }
    }
  }
} catch (error) {
  console.error('Warning: Could not load .env file:', error.message);
}

export class ProxmoxServer {
  constructor() {
    this.server = new Server(
      {
        name: 'proxmox-server',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );
    
    this.proxmoxHost = process.env.PROXMOX_HOST;
    if (!this.proxmoxHost) {
      throw new Error('PROXMOX_HOST environment variable is required');
    }
    this.proxmoxUser = process.env.PROXMOX_USER || 'root@pam';
    // Token name doubling (e.g. "root@pam!mcpserver") is a common misconfiguration:
    // PROXMOX_USER must be user@realm only; the token name goes in PROXMOX_TOKEN_NAME.
    if (!/^[^@!\s]+@[^@!\s]+$/.test(this.proxmoxUser)) {
      throw new Error(
        `Invalid PROXMOX_USER "${this.proxmoxUser}". Expected user@realm (e.g. root@pam) with no '!'. ` +
        `Put the API token name in PROXMOX_TOKEN_NAME, not in PROXMOX_USER.`
      );
    }
    this.proxmoxTokenName = process.env.PROXMOX_TOKEN_NAME || 'mcpserver';
    this.proxmoxTokenValue = process.env.PROXMOX_TOKEN_VALUE;
    if (!this.proxmoxTokenValue) {
      throw new Error('PROXMOX_TOKEN_VALUE environment variable is required');
    }
    this.proxmoxPort = process.env.PROXMOX_PORT || '8006';
    this.allowElevated = process.env.PROXMOX_ALLOW_ELEVATED === 'true';

    // TLS verification is on by default. Opt out with PROXMOX_VERIFY_SSL=false
    // (or the legacy-compatible PROXMOX_ALLOW_SELF_SIGNED=true).
    const verifySslEnv = (process.env.PROXMOX_VERIFY_SSL || '').toLowerCase();
    const allowSelfSigned =
      verifySslEnv === 'false' ||
      (process.env.PROXMOX_ALLOW_SELF_SIGNED || '').toLowerCase() === 'true';
    this.verifySsl = !allowSelfSigned;
    if (!this.verifySsl) {
      console.error('Warning: TLS certificate verification is disabled (PROXMOX_VERIFY_SSL=false / PROXMOX_ALLOW_SELF_SIGNED=true).');
    }
    this.httpsAgent = new https.Agent({
      rejectUnauthorized: this.verifySsl
    });

    this.fetch = fetch;
    
    this.setupToolHandlers();
  }

  // Input validation methods for security
  validateNodeName(node) {
    if (!node || typeof node !== 'string') {
      throw new Error('Node name is required and must be a string');
    }
    // Only allow alphanumeric, hyphens, and underscores
    if (!/^[a-zA-Z0-9\-_]+$/.test(node)) {
      throw new Error('Invalid node name format. Only alphanumeric, hyphens, and underscores allowed');
    }
    if (node.length > 64) {
      throw new Error('Node name too long (max 64 characters)');
    }
    return node;
  }

  validateVMID(vmid) {
    if (!vmid) {
      throw new Error('VM ID is required');
    }
    const id = parseInt(vmid, 10);
    if (isNaN(id) || id < 100 || id > 999999999) {
      throw new Error('Invalid VM ID. Must be a number between 100 and 999999999');
    }
    return id.toString();
  }

  validateStorageName(storage) {
    if (!storage || typeof storage !== 'string') {
      throw new Error('Storage name is required and must be a string');
    }
    // Proxmox storage IDs: alphanumeric, hyphens, underscores, dots
    if (!/^[a-zA-Z0-9\-_.]+$/.test(storage)) {
      throw new Error('Invalid storage name format. Only alphanumeric, hyphens, underscores, and dots allowed');
    }
    if (storage.length > 64) {
      throw new Error('Storage name too long (max 64 characters)');
    }
    return storage;
  }

  validateSnapshotName(snapname) {
    if (!snapname || typeof snapname !== 'string') {
      throw new Error('Snapshot name is required and must be a string');
    }
    // Proxmox snapshot names: alphanumeric, hyphens, underscores
    if (!/^[a-zA-Z0-9\-_]+$/.test(snapname)) {
      throw new Error('Invalid snapshot name format. Only alphanumeric, hyphens, and underscores allowed');
    }
    if (snapname.length > 40) {
      throw new Error('Snapshot name too long (max 40 characters)');
    }
    return snapname;
  }

  validateDiskName(disk, type) {
    if (!disk || typeof disk !== 'string') {
      throw new Error('Disk name is required and must be a string');
    }

    if (disk === 'rootfs' || disk === 'efidisk0' || disk === 'tpmstate0') {
      if (type === 'qemu' && disk === 'rootfs') {
        throw new Error('Invalid disk name "rootfs" for a QEMU VM. Use scsiN, virtioN, sataN, ideN, efidisk0, tpmstate0, or unusedN');
      }
      if (type === 'lxc' && disk !== 'rootfs') {
        throw new Error(`Invalid disk name "${disk}" for an LXC container. Use rootfs, mp0-255, or unusedN`);
      }
      return disk;
    }

    const match = disk.match(/^(scsi|virtio|sata|ide|mp|unused)(\d+)$/);
    if (!match) {
      throw new Error('Invalid disk name format. Expected: scsi0-30, virtio0-15, sata0-5, ide0-3, efidisk0, tpmstate0, rootfs, mp0-255, or unusedN');
    }

    if (type === 'qemu' && match[1] === 'mp') {
      throw new Error(`Invalid disk name "${disk}" for a QEMU VM. Mount points (mpN) are LXC-only; use scsiN, virtioN, sataN, or ideN`);
    }
    if (type === 'lxc' && ['scsi', 'virtio', 'sata', 'ide'].includes(match[1])) {
      throw new Error(`Invalid disk name "${disk}" for an LXC container. Use rootfs, mp0-255, or unusedN`);
    }

    const [, prefix, numStr] = match;
    const num = parseInt(numStr, 10);
    if (!Number.isFinite(num) || num < 0) {
      throw new Error('Invalid disk number');
    }

    const maxByPrefix = {
      scsi: 30,
      virtio: 15,
      sata: 5,
      ide: 3,
      mp: 255,
      unused: Number.POSITIVE_INFINITY,
    };

    const max = maxByPrefix[prefix];
    if (Number.isFinite(max) && num > max) {
      throw new Error(`Disk number out of range for ${prefix} (max: ${prefix}${max})`);
    }

    return disk;
  }

  validateNetworkName(net) {
    if (!net || typeof net !== 'string') {
      throw new Error('Network interface name is required and must be a string');
    }
    const match = net.match(/^net(\d{1,2})$/);
    if (!match) {
      throw new Error('Invalid network interface name. Expected: net0-31');
    }
    const num = parseInt(match[1], 10);
    if (!Number.isFinite(num) || num < 0 || num > 31) {
      throw new Error('Network interface number out of range (max: net31)');
    }
    return `net${num}`;
  }

  validateBridgeName(bridge) {
    if (!bridge || typeof bridge !== 'string') {
      throw new Error('Bridge name is required and must be a string');
    }
    // Proxmox bridge identifiers may also contain dots, e.g. vmbr0.100.
    if (!/^[a-zA-Z0-9._-]+$/.test(bridge)) {
      throw new Error('Invalid bridge name format. Only alphanumeric, periods, hyphens, and underscores allowed');
    }
    if (bridge.length > 32) {
      throw new Error('Bridge name too long (max 32 characters)');
    }
    return bridge;
  }

  validateMountPoint(mp) {
    if (!mp || typeof mp !== 'string') {
      throw new Error('Mount point name is required and must be a string');
    }
    if (mp === 'rootfs') {
      return mp;
    }
    const match = mp.match(/^mp(\d{1,3})$/);
    if (!match) {
      throw new Error('Invalid mount point name. Expected: mp0-255 or rootfs');
    }
    const num = parseInt(match[1], 10);
    if (!Number.isFinite(num) || num < 0 || num > 255) {
      throw new Error('Mount point number out of range (max: mp255)');
    }
    return `mp${num}`;
  }

  validateCommand(command) {
    if (!command || typeof command !== 'string') {
      throw new Error('Command is required and must be a string');
    }

    // The QEMU guest agent executes the command directly (no shell), so shell
    // metacharacters are not dangerous here. Block only control characters.
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(command)) {
      throw new Error('Command contains control characters, which are not allowed');
    }

    // Limit command length
    if (command.length > 1000) {
      throw new Error('Command exceeds maximum allowed length (1000 characters)');
    }

    return command;
  }

  validateMacAddr(macaddr) {
    if (typeof macaddr !== 'string' || !/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/.test(macaddr)) {
      throw new Error(`Invalid MAC address "${macaddr}". Expected format XX:XX:XX:XX:XX:XX`);
    }
    return macaddr;
  }

  validateVlanTag(vlan) {
    const tag = Number(vlan);
    if (!Number.isInteger(tag) || tag < 1 || tag > 4094) {
      throw new Error(`Invalid VLAN tag "${vlan}". Must be an integer between 1 and 4094`);
    }
    return tag;
  }

  validateIPConfig(ip) {
    if (typeof ip !== 'string') {
      throw new Error('IP must be a string');
    }
    if (ip === 'dhcp' || ip === 'auto' || ip === 'manual') {
      return ip;
    }
    // IPv4 CIDR
    if (/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(ip)) {
      const [addr, prefix] = ip.split('/');
      if (addr.split('.').every(o => Number(o) <= 255) && Number(prefix) <= 32) {
        return ip;
      }
    }
    // IPv6 CIDR
    if (/^[0-9A-Fa-f:]+\/\d{1,3}$/.test(ip) && ip.includes(':') && Number(ip.split('/')[1]) <= 128) {
      return ip;
    }
    throw new Error(`Invalid IP "${ip}". Expected 'dhcp', 'auto', 'manual', or CIDR notation (e.g. 192.168.1.100/24)`);
  }

  validateGateway(gw) {
    if (typeof gw !== 'string') {
      throw new Error('Gateway must be a string');
    }
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(gw) && gw.split('.').every(o => Number(o) <= 255)) {
      return gw;
    }
    if (/^[0-9A-Fa-f:]+$/.test(gw) && gw.includes(':')) {
      return gw;
    }
    throw new Error(`Invalid gateway "${gw}". Expected an IPv4 or IPv6 address`);
  }

  // Parse a disk size like "8", "8G", "1.5T", "10240M" into integer gigabytes.
  parseDiskSizeGB(size, label = 'size') {
    const match = String(size).trim().match(/^(\d+(?:\.\d+)?)\s*([GgTtMm])?[Bb]?$/);
    if (!match) {
      throw new Error(`Invalid ${label} "${size}". Use a number with optional unit, e.g. "8G", "1.5T", "512M"`);
    }
    const value = parseFloat(match[1]);
    const unit = (match[2] || 'G').toUpperCase();
    const gb = unit === 'T' ? value * 1024 : unit === 'M' ? value / 1024 : value;
    const intGB = Math.ceil(gb);
    if (!Number.isFinite(intGB) || intGB < 1) {
      throw new Error(`Invalid ${label} "${size}". Must resolve to at least 1 GB`);
    }
    return intGB;
  }

  validateUPID(upid) {
    if (!upid || typeof upid !== 'string' || !/^UPID:[A-Za-z0-9._@:-]+$/.test(upid)) {
      throw new Error(`Invalid task UPID "${upid}". Expected a Proxmox task ID starting with "UPID:"`);
    }
    return upid;
  }

  validatePID(pid) {
    const id = Number(pid);
    if (!Number.isInteger(id) || id < 1) {
      throw new Error(`Invalid PID "${pid}". Must be a positive integer`);
    }
    return id;
  }

  generateSecurePassword() {
    // Generate a secure random password using Node.js crypto
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let password = '';

    for (let i = 0; i < 16; i++) {
      password += chars[crypto.randomInt(chars.length)];
    }
    return password;
  }

  async proxmoxRequest(endpoint, method = 'GET', body = null) {
    const baseUrl = `https://${this.proxmoxHost}:${this.proxmoxPort}/api2/json`;
    const url = `${baseUrl}${endpoint}`;

    const headers = {
      'Authorization': `PVEAPIToken=${this.proxmoxUser}!${this.proxmoxTokenName}=${this.proxmoxTokenValue}`,
      'Content-Type': 'application/json'
    };

    const timeoutMs = parseInt(process.env.PROXMOX_TIMEOUT_MS, 10) > 0
      ? parseInt(process.env.PROXMOX_TIMEOUT_MS, 10)
      : 30000;
    const requestController = new AbortController();
    const requestTimeoutId = setTimeout(() => requestController.abort(), timeoutMs);

    const options = {
      method,
      headers,
      agent: this.httpsAgent,
      signal: requestController.signal
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    try {
      const response = await this.fetch(url, options);

      if (!response.ok) {
        const errorText = await response.text();
        if (response.status === 596 && /no such cluster node/i.test(errorText)) {
          const nodeMatch = endpoint.match(/^\/nodes\/([^/]+)/);
          if (nodeMatch) {
            const requestedNode = nodeMatch[1];
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);

            try {
              const nodesResponse = await this.fetch(`${baseUrl}/nodes`, {
                method: 'GET',
                headers,
                agent: this.httpsAgent,
                signal: controller.signal
              });

              if (nodesResponse.ok) {
                const nodesBody = JSON.parse(await nodesResponse.text());
                const knownNodes = (nodesBody.data || [])
                  .map((node) => node?.node)
                  .filter((node) => typeof node === 'string');
                const canonicalNode = knownNodes.find(
                  (node) => node.toLowerCase() === requestedNode.toLowerCase()
                );

                if (canonicalNode && canonicalNode !== requestedNode) {
                  throw new Error(
                    `Proxmox returned 596 proxying to node "${requestedNode}". ` +
                    `Node name does not match a cluster member ` +
                    `(lookup is case-sensitive). ` +
                    `Did you mean "${canonicalNode}"? ` +
                    `Known nodes: ${knownNodes.join(', ')}.`
                  );
                }

                if (!canonicalNode) {
                  throw new Error(
                    `Proxmox returned 596 proxying to node "${requestedNode}". ` +
                    `The node is unknown to the cluster. ` +
                    `Known nodes: ${knownNodes.join(', ')}. ` +
                    `Other 596 causes include proxy timeouts and cert issues.`
                  );
                }
              }
            } catch (lookupError) {
              if (lookupError.message?.startsWith('Proxmox returned 596')) {
                throw lookupError;
              }
            } finally {
              clearTimeout(timeoutId);
            }
          }
        }

        throw new Error(`Proxmox API error: ${response.status} - ${errorText}`);
      }

      const textResponse = await response.text();
      if (!textResponse.trim()) {
        throw new Error('Empty response from Proxmox API');
      }

      const data = JSON.parse(textResponse);
      return data.data;
    } catch (error) {
      if (error.name === 'AbortError' && requestController.signal.aborted) {
        throw new Error(`Proxmox API request timed out after ${timeoutMs}ms (${method} ${endpoint}). Override with PROXMOX_TIMEOUT_MS.`);
      }
      if (error.name === 'SyntaxError') {
        throw new Error(`Failed to parse Proxmox API response: ${error.message}`);
      }
      const isNetworkError =
        ['ECONNREFUSED', 'ETIMEDOUT', 'ENOTFOUND', 'ECONNRESET', 'EHOSTUNREACH']
          .includes(error.code) ||
        error.name === 'FetchError' ||
        (error.name === 'TypeError' && /fetch failed/i.test(error.message));

      if (isNetworkError) {
        throw new Error(`Failed to connect to Proxmox: ${error.message}`);
      }

      throw error;
    } finally {
      clearTimeout(requestTimeoutId);
    }
  }

  setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'proxmox_get_nodes',
          description: 'List all Proxmox cluster nodes with their status and resources',
          inputSchema: {
            type: 'object',
            properties: {}
          }
        },
        {
          name: 'proxmox_get_node_status',
          description: 'Get detailed status information for a specific Proxmox node (read-only)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name (e.g., pve1, proxmox-node2)' }
            },
            required: ['node']
          }
        },
        {
          name: 'proxmox_get_vms',
          description: 'List all virtual machines across the cluster with their status',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Optional: filter by specific node' },
              type: { type: 'string', enum: ['qemu', 'lxc', 'all'], description: 'VM type filter', default: 'all' }
            }
          }
        },
        {
          name: 'proxmox_get_vm_status',
          description: 'Get detailed status information for a specific VM',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' },
              type: { type: 'string', enum: ['qemu', 'lxc'], description: 'VM type', default: 'qemu' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_execute_vm_command',
          description: 'Execute a shell command on a QEMU virtual machine via the QEMU guest agent (QEMU only; the Proxmox REST API has no LXC exec endpoint). Returns a PID; fetch output with proxmox_get_exec_status.',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' },
              command: { type: 'string', description: 'Shell command to execute' },
              type: { type: 'string', enum: ['qemu', 'lxc'], description: 'VM type (only qemu is supported for execution)', default: 'qemu' }
            },
            required: ['node', 'vmid', 'command']
          }
        },
        {
          name: 'proxmox_get_exec_status',
          description: 'Get the status and output of a command previously started with proxmox_execute_vm_command on a QEMU VM (read-only). Returns exited/exitcode/out-data/err-data.',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' },
              pid: { type: 'number', description: 'PID returned by proxmox_execute_vm_command' }
            },
            required: ['node', 'vmid', 'pid']
          }
        },
        {
          name: 'proxmox_get_task_status',
          description: 'Get the status of a Proxmox task by UPID (read-only). Use this to check completion of long-running operations such as create, clone, backup, restore, move-disk, rollback, and delete.',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name the task runs on' },
              upid: { type: 'string', description: 'Task UPID (e.g. UPID:pve1:00001234:...)' }
            },
            required: ['node', 'upid']
          }
        },
        {
          name: 'proxmox_get_task_log',
          description: 'Get the log of a Proxmox task by UPID (read-only), with optional start/limit paging.',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name the task runs on' },
              upid: { type: 'string', description: 'Task UPID (e.g. UPID:pve1:00001234:...)' },
              start: { type: 'number', description: 'Log line offset to start from (default 0)' },
              limit: { type: 'number', description: 'Maximum number of log lines to return (default 50)' }
            },
            required: ['node', 'upid']
          }
        },
        {
          name: 'proxmox_get_storage',
          description: 'List all storage pools and their usage across the cluster',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Optional: filter by specific node' }
            }
          }
        },
        {
          name: 'proxmox_get_cluster_status',
          description: 'Get overall cluster status including nodes and resource usage',
          inputSchema: {
            type: 'object',
            properties: {}
          }
        },
        {
          name: 'proxmox_list_templates',
          description: 'List available LXC container templates on a storage',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name' },
              storage: { type: 'string', description: 'Storage name (e.g., local)', default: 'local' }
            },
            required: ['node']
          }
        },
        {
          name: 'proxmox_create_lxc',
          description: 'Create a new LXC container (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container will be created' },
              vmid: { type: 'string', description: 'Container ID number (must be unique, or use proxmox_get_next_vmid)' },
              ostemplate: { type: 'string', description: 'OS template (e.g., local:vztmpl/debian-12-standard_12.2-1_amd64.tar.gz)' },
              hostname: { type: 'string', description: 'Container hostname' },
              password: { type: 'string', description: 'Root password' },
              memory: { type: 'number', description: 'RAM in MB', default: 512 },
              storage: { type: 'string', description: 'Storage location', default: 'local-lvm' },
              rootfs: { type: 'string', description: 'Root filesystem size in GB', default: '8' }
            },
            required: ['node', 'vmid', 'ostemplate']
          }
        },
        {
          name: 'proxmox_create_vm',
          description: 'Create a new QEMU virtual machine (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM will be created' },
              vmid: { type: 'string', description: 'VM ID number (must be unique, or use proxmox_get_next_vmid)' },
              name: { type: 'string', description: 'VM name' },
              memory: { type: 'number', description: 'RAM in MB', default: 512 },
              cores: { type: 'number', description: 'Number of CPU cores', default: 1 },
              sockets: { type: 'number', description: 'Number of CPU sockets', default: 1 },
              disk_size: { type: 'string', description: 'Disk size (e.g., "8G", "10G")', default: '8G' },
              storage: { type: 'string', description: 'Storage location for disk', default: 'local-lvm' },
              iso: { type: 'string', description: 'ISO image (e.g., "local:iso/alpine-virt-3.19.1-x86_64.iso"), optional' },
              ostype: { type: 'string', description: 'OS type (l26=Linux 2.6+, win10, etc)', default: 'l26' },
              net0: { type: 'string', description: 'Network interface config', default: 'virtio,bridge=vmbr0' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_get_next_vmid',
          description: 'Get the next available VM/Container ID number',
          inputSchema: {
            type: 'object',
            properties: {}
          }
        },
        {
          name: 'proxmox_start_lxc',
          description: 'Start an LXC container (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container is located' },
              vmid: { type: 'string', description: 'Container ID number' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_start_vm',
          description: 'Start a QEMU virtual machine (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_stop_lxc',
          description: 'Stop an LXC container (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container is located' },
              vmid: { type: 'string', description: 'Container ID number' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_stop_vm',
          description: 'Stop a QEMU virtual machine (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_delete_lxc',
          description: 'Delete an LXC container (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container is located' },
              vmid: { type: 'string', description: 'Container ID number to delete' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_delete_vm',
          description: 'Delete a QEMU virtual machine (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number to delete' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_reboot_lxc',
          description: 'Reboot an LXC container (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container is located' },
              vmid: { type: 'string', description: 'Container ID number' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_reboot_vm',
          description: 'Reboot a QEMU virtual machine (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_shutdown_lxc',
          description: 'Gracefully shutdown an LXC container (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container is located' },
              vmid: { type: 'string', description: 'Container ID number' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_shutdown_vm',
          description: 'Gracefully shutdown a QEMU virtual machine (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_pause_vm',
          description: 'Pause a QEMU virtual machine (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_resume_vm',
          description: 'Resume a paused QEMU virtual machine (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_clone_lxc',
          description: 'Clone an LXC container (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container is located' },
              vmid: { type: 'string', description: 'Container ID to clone from' },
              newid: { type: 'string', description: 'New container ID' },
              hostname: { type: 'string', description: 'Hostname for cloned container (optional)' }
            },
            required: ['node', 'vmid', 'newid']
          }
        },
        {
          name: 'proxmox_clone_vm',
          description: 'Clone a QEMU virtual machine (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID to clone from' },
              newid: { type: 'string', description: 'New VM ID' },
              name: { type: 'string', description: 'Name for cloned VM (optional)' }
            },
            required: ['node', 'vmid', 'newid']
          }
        },
        {
          name: 'proxmox_resize_lxc',
          description: 'Resize an LXC container CPU/memory (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container is located' },
              vmid: { type: 'string', description: 'Container ID number' },
              memory: { type: 'number', description: 'Memory in MB (optional)' },
              cores: { type: 'number', description: 'Number of CPU cores (optional)' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_resize_vm',
          description: 'Resize a QEMU VM CPU/memory (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' },
              memory: { type: 'number', description: 'Memory in MB (optional)' },
              cores: { type: 'number', description: 'Number of CPU cores (optional)' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_create_snapshot_lxc',
          description: 'Create a snapshot of an LXC container (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container is located' },
              vmid: { type: 'string', description: 'Container ID number' },
              snapname: { type: 'string', description: 'Snapshot name' }
            },
            required: ['node', 'vmid', 'snapname']
          }
        },
        {
          name: 'proxmox_create_snapshot_vm',
          description: 'Create a snapshot of a QEMU virtual machine (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' },
              snapname: { type: 'string', description: 'Snapshot name' }
            },
            required: ['node', 'vmid', 'snapname']
          }
        },
        {
          name: 'proxmox_list_snapshots_lxc',
          description: 'List all snapshots of an LXC container (read-only)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container is located' },
              vmid: { type: 'string', description: 'Container ID number' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_list_snapshots_vm',
          description: 'List all snapshots of a QEMU virtual machine (read-only)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_rollback_snapshot_lxc',
          description: 'Rollback an LXC container to a snapshot (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container is located' },
              vmid: { type: 'string', description: 'Container ID number' },
              snapname: { type: 'string', description: 'Snapshot name to rollback to' }
            },
            required: ['node', 'vmid', 'snapname']
          }
        },
        {
          name: 'proxmox_rollback_snapshot_vm',
          description: 'Rollback a QEMU virtual machine to a snapshot (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' },
              snapname: { type: 'string', description: 'Snapshot name to rollback to' }
            },
            required: ['node', 'vmid', 'snapname']
          }
        },
        {
          name: 'proxmox_delete_snapshot_lxc',
          description: 'Delete a snapshot of an LXC container (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container is located' },
              vmid: { type: 'string', description: 'Container ID number' },
              snapname: { type: 'string', description: 'Snapshot name to delete' }
            },
            required: ['node', 'vmid', 'snapname']
          }
        },
        {
          name: 'proxmox_delete_snapshot_vm',
          description: 'Delete a snapshot of a QEMU virtual machine (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' },
              snapname: { type: 'string', description: 'Snapshot name to delete' }
            },
            required: ['node', 'vmid', 'snapname']
          }
        },
        {
          name: 'proxmox_create_backup_lxc',
          description: 'Create a backup of an LXC container (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container is located' },
              vmid: { type: 'string', description: 'Container ID number' },
              storage: { type: 'string', description: 'Storage location for backup', default: 'local' },
              mode: { type: 'string', enum: ['snapshot', 'suspend', 'stop'], description: 'Backup mode', default: 'snapshot' },
              compress: { type: 'string', enum: ['none', 'lzo', 'gzip', 'zstd'], description: 'Compression algorithm', default: 'zstd' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_create_backup_vm',
          description: 'Create a backup of a QEMU virtual machine (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' },
              storage: { type: 'string', description: 'Storage location for backup', default: 'local' },
              mode: { type: 'string', enum: ['snapshot', 'suspend', 'stop'], description: 'Backup mode', default: 'snapshot' },
              compress: { type: 'string', enum: ['none', 'lzo', 'gzip', 'zstd'], description: 'Compression algorithm', default: 'zstd' }
            },
            required: ['node', 'vmid']
          }
        },
        {
          name: 'proxmox_list_backups',
          description: 'List all backups on a storage (read-only)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name' },
              storage: { type: 'string', description: 'Storage name', default: 'local' }
            },
            required: ['node']
          }
        },
        {
          name: 'proxmox_restore_backup_lxc',
          description: 'Restore an LXC container from backup (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container will be restored' },
              vmid: { type: 'string', description: 'New container ID for restored container' },
              archive: { type: 'string', description: 'Backup archive path (e.g., local:backup/vzdump-lxc-100-2025_11_06-09_00_00.tar.zst)' },
              storage: { type: 'string', description: 'Storage location for restored container (optional)' },
              overwrite: { type: 'boolean', description: 'Allow overwriting an existing container with this ID (default: false)', default: false }
            },
            required: ['node', 'vmid', 'archive']
          }
        },
        {
          name: 'proxmox_restore_backup_vm',
          description: 'Restore a QEMU virtual machine from backup (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM will be restored' },
              vmid: { type: 'string', description: 'New VM ID for restored VM' },
              archive: { type: 'string', description: 'Backup archive path (e.g., local:backup/vzdump-qemu-100-2025_11_06-09_00_00.vma.zst)' },
              storage: { type: 'string', description: 'Storage location for restored VM (optional)' },
              overwrite: { type: 'boolean', description: 'Allow overwriting an existing VM with this ID (default: false)', default: false }
            },
            required: ['node', 'vmid', 'archive']
          }
        },
        {
          name: 'proxmox_delete_backup',
          description: 'Delete a backup file from storage (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name' },
              storage: { type: 'string', description: 'Storage name (e.g., local)' },
              volume: { type: 'string', description: 'Backup volume ID (e.g., local:backup/vzdump-lxc-100-2025_11_06-09_00_00.tar.zst)' }
            },
            required: ['node', 'storage', 'volume']
          }
        },
        {
          name: 'proxmox_add_disk_vm',
          description: 'Add a new disk to a QEMU virtual machine (requires elevated permissions). Disk naming: scsi0-30, virtio0-15, sata0-5, ide0-3; special disks: efidisk0, tpmstate0, unusedN.',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' },
              disk: { type: 'string', description: 'Disk name (e.g., scsi1, virtio1, sata1, ide1)' },
              storage: { type: 'string', description: 'Storage name (e.g., local-lvm)' },
              size: { type: 'string', description: 'Disk size in GB (e.g., 10)' }
            },
            required: ['node', 'vmid', 'disk', 'storage', 'size']
          }
        },
        {
          name: 'proxmox_add_mountpoint_lxc',
          description: 'Add a mount point to an LXC container (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container is located' },
              vmid: { type: 'string', description: 'Container ID number' },
              mp: { type: 'string', description: 'Mount point name (e.g., mp0, mp1, mp2)' },
              storage: { type: 'string', description: 'Storage name (e.g., local-lvm)' },
              size: { type: 'string', description: 'Mount point size in GB (e.g., 10)' }
            },
            required: ['node', 'vmid', 'mp', 'storage', 'size']
          }
        },
        {
          name: 'proxmox_resize_disk_vm',
          description: 'Resize a QEMU VM disk (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' },
              disk: { type: 'string', description: 'Disk name (e.g., scsi0, virtio0, sata0, ide0)' },
              size: { type: 'string', description: 'New size with + for relative or absolute (e.g., +10G or 50G)' }
            },
            required: ['node', 'vmid', 'disk', 'size']
          }
        },
        {
          name: 'proxmox_resize_disk_lxc',
          description: 'Resize an LXC container disk or mount point (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container is located' },
              vmid: { type: 'string', description: 'Container ID number' },
              disk: { type: 'string', description: 'Disk name (rootfs, mp0, mp1, etc.)' },
              size: { type: 'string', description: 'New size with + for relative or absolute (e.g., +10G or 50G)' }
            },
            required: ['node', 'vmid', 'disk', 'size']
          }
        },
        {
          name: 'proxmox_remove_disk_vm',
          description: 'Remove a disk from a QEMU virtual machine (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' },
              disk: { type: 'string', description: 'Disk name to remove (e.g., scsi1, virtio1, sata1, ide1)' }
            },
            required: ['node', 'vmid', 'disk']
          }
        },
        {
          name: 'proxmox_remove_mountpoint_lxc',
          description: 'Remove a mount point from an LXC container (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container is located' },
              vmid: { type: 'string', description: 'Container ID number' },
              mp: { type: 'string', description: 'Mount point name to remove (e.g., mp0, mp1, mp2)' }
            },
            required: ['node', 'vmid', 'mp']
          }
        },
        {
          name: 'proxmox_move_disk_vm',
          description: 'Move a QEMU VM disk to different storage (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' },
              disk: { type: 'string', description: 'Disk name to move (e.g., scsi0, virtio0, sata0, ide0)' },
              storage: { type: 'string', description: 'Target storage name' },
              delete: { type: 'boolean', description: 'Delete source disk after move (default: false, source is kept)', default: false }
            },
            required: ['node', 'vmid', 'disk', 'storage']
          }
        },
        {
          name: 'proxmox_move_disk_lxc',
          description: 'Move an LXC container disk to different storage (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container is located' },
              vmid: { type: 'string', description: 'Container ID number' },
              disk: { type: 'string', description: 'Disk/volume name to move (rootfs, mp0, mp1, etc.)' },
              storage: { type: 'string', description: 'Target storage name' },
              delete: { type: 'boolean', description: 'Delete source disk after move (default: false, source is kept)', default: false }
            },
            required: ['node', 'vmid', 'disk', 'storage']
          }
        },
        {
          name: 'proxmox_add_network_vm',
          description: 'Add network interface to QEMU VM (requires elevated permissions). Valid interfaces: net0-31. Valid models: virtio (recommended), e1000, rtl8139, vmxnet3. Bridges are typically vmbr0, vmbr1, etc.',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' },
              net: { type: 'string', description: 'Network interface name (net0, net1, net2, etc.)' },
              bridge: { type: 'string', description: 'Bridge name (e.g., vmbr0, vmbr1)' },
              model: { type: 'string', description: 'Network model (virtio, e1000, rtl8139, vmxnet3)', default: 'virtio' },
              macaddr: { type: 'string', description: 'MAC address (XX:XX:XX:XX:XX:XX) - auto-generated if not specified' },
              vlan: { type: 'number', description: 'VLAN tag (1-4094)' },
              firewall: { type: 'boolean', description: 'Enable firewall on this interface' }
            },
            required: ['node', 'vmid', 'net', 'bridge']
          }
        },
        {
          name: 'proxmox_add_network_lxc',
          description: 'Add network interface to LXC container (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container is located' },
              vmid: { type: 'string', description: 'Container ID number' },
              net: { type: 'string', description: 'Network interface name (net0, net1, net2, etc.)' },
              bridge: { type: 'string', description: 'Bridge name (e.g., vmbr0, vmbr1)' },
              ip: { type: 'string', description: 'IP address (dhcp, 192.168.1.100/24, auto)' },
              gw: { type: 'string', description: 'Gateway IP address' },
              firewall: { type: 'boolean', description: 'Enable firewall on this interface' }
            },
            required: ['node', 'vmid', 'net', 'bridge']
          }
        },
        {
          name: 'proxmox_update_network_vm',
          description: 'Update/modify VM network interface configuration (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' },
              net: { type: 'string', description: 'Network interface name to update (net0, net1, net2, etc.)' },
              bridge: { type: 'string', description: 'Bridge name (e.g., vmbr0, vmbr1)' },
              model: { type: 'string', description: 'Network model (virtio, e1000, rtl8139, vmxnet3)' },
              macaddr: { type: 'string', description: 'MAC address (XX:XX:XX:XX:XX:XX)' },
              vlan: { type: 'number', description: 'VLAN tag (1-4094)' },
              firewall: { type: 'boolean', description: 'Enable firewall on this interface' }
            },
            required: ['node', 'vmid', 'net']
          }
        },
        {
          name: 'proxmox_update_network_lxc',
          description: 'Update/modify LXC network interface configuration (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container is located' },
              vmid: { type: 'string', description: 'Container ID number' },
              net: { type: 'string', description: 'Network interface name to update (net0, net1, net2, etc.)' },
              bridge: { type: 'string', description: 'Bridge name (e.g., vmbr0, vmbr1)' },
              ip: { type: 'string', description: 'IP address (dhcp, 192.168.1.100/24, auto)' },
              gw: { type: 'string', description: 'Gateway IP address' },
              firewall: { type: 'boolean', description: 'Enable firewall on this interface' }
            },
            required: ['node', 'vmid', 'net']
          }
        },
        {
          name: 'proxmox_remove_network_vm',
          description: 'Remove network interface from QEMU VM (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where VM is located' },
              vmid: { type: 'string', description: 'VM ID number' },
              net: { type: 'string', description: 'Network interface name to remove (net0, net1, net2, etc.)' }
            },
            required: ['node', 'vmid', 'net']
          }
        },
        {
          name: 'proxmox_remove_network_lxc',
          description: 'Remove network interface from LXC container (requires elevated permissions)',
          inputSchema: {
            type: 'object',
            properties: {
              node: { type: 'string', description: 'Node name where container is located' },
              vmid: { type: 'string', description: 'Container ID number' },
              net: { type: 'string', description: 'Network interface name to remove (net0, net1, net2, etc.)' }
            },
            required: ['node', 'vmid', 'net']
          }
        }
      ]
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'proxmox_get_nodes':
            return await this.getNodes();
            
          case 'proxmox_get_node_status':
            return await this.getNodeStatus(args.node);
            
          case 'proxmox_get_vms':
            return await this.getVMs(args.node, args.type);
            
          case 'proxmox_get_vm_status':
            return await this.getVMStatus(args.node, args.vmid, args.type);
            
          case 'proxmox_execute_vm_command':
            return await this.executeVMCommand(args.node, args.vmid, args.command, args.type);

          case 'proxmox_get_exec_status':
            return await this.getExecStatus(args.node, args.vmid, args.pid);

          case 'proxmox_get_task_status':
            return await this.getTaskStatus(args.node, args.upid);

          case 'proxmox_get_task_log':
            return await this.getTaskLog(args.node, args.upid, args.start, args.limit);


          case 'proxmox_get_storage':
            return await this.getStorage(args.node);
            
          case 'proxmox_get_cluster_status':
            return await this.getClusterStatus();

          case 'proxmox_list_templates':
            return await this.listTemplates(args.node, args.storage);

          case 'proxmox_create_lxc':
            return await this.createLXCContainer(args);

          case 'proxmox_create_vm':
            return await this.createVM(args);

          case 'proxmox_get_next_vmid':
            return await this.getNextVMID();

          case 'proxmox_start_lxc':
            return await this.startVM(args.node, args.vmid, 'lxc');

          case 'proxmox_start_vm':
            return await this.startVM(args.node, args.vmid, 'qemu');

          case 'proxmox_stop_lxc':
            return await this.stopVM(args.node, args.vmid, 'lxc');

          case 'proxmox_stop_vm':
            return await this.stopVM(args.node, args.vmid, 'qemu');

          case 'proxmox_delete_lxc':
            return await this.deleteVM(args.node, args.vmid, 'lxc');

          case 'proxmox_delete_vm':
            return await this.deleteVM(args.node, args.vmid, 'qemu');

          case 'proxmox_reboot_lxc':
            return await this.rebootVM(args.node, args.vmid, 'lxc');

          case 'proxmox_reboot_vm':
            return await this.rebootVM(args.node, args.vmid, 'qemu');

          case 'proxmox_shutdown_lxc':
            return await this.shutdownVM(args.node, args.vmid, 'lxc');

          case 'proxmox_shutdown_vm':
            return await this.shutdownVM(args.node, args.vmid, 'qemu');

          case 'proxmox_pause_vm':
            return await this.pauseVM(args.node, args.vmid);

          case 'proxmox_resume_vm':
            return await this.resumeVM(args.node, args.vmid);

          case 'proxmox_clone_lxc':
            return await this.cloneVM(args.node, args.vmid, args.newid, args.hostname, 'lxc');

          case 'proxmox_clone_vm':
            return await this.cloneVM(args.node, args.vmid, args.newid, args.name, 'qemu');

          case 'proxmox_resize_lxc':
            return await this.resizeVM(args.node, args.vmid, args.memory, args.cores, 'lxc');

          case 'proxmox_resize_vm':
            return await this.resizeVM(args.node, args.vmid, args.memory, args.cores, 'qemu');

          case 'proxmox_create_snapshot_lxc':
            return await this.createSnapshot(args.node, args.vmid, args.snapname, 'lxc');

          case 'proxmox_create_snapshot_vm':
            return await this.createSnapshot(args.node, args.vmid, args.snapname, 'qemu');

          case 'proxmox_list_snapshots_lxc':
            return await this.listSnapshots(args.node, args.vmid, 'lxc');

          case 'proxmox_list_snapshots_vm':
            return await this.listSnapshots(args.node, args.vmid, 'qemu');

          case 'proxmox_rollback_snapshot_lxc':
            return await this.rollbackSnapshot(args.node, args.vmid, args.snapname, 'lxc');

          case 'proxmox_rollback_snapshot_vm':
            return await this.rollbackSnapshot(args.node, args.vmid, args.snapname, 'qemu');

          case 'proxmox_delete_snapshot_lxc':
            return await this.deleteSnapshot(args.node, args.vmid, args.snapname, 'lxc');

          case 'proxmox_delete_snapshot_vm':
            return await this.deleteSnapshot(args.node, args.vmid, args.snapname, 'qemu');

          case 'proxmox_create_backup_lxc':
            return await this.createBackup(args.node, args.vmid, args.storage, args.mode, args.compress, 'lxc');

          case 'proxmox_create_backup_vm':
            return await this.createBackup(args.node, args.vmid, args.storage, args.mode, args.compress, 'qemu');

          case 'proxmox_list_backups':
            return await this.listBackups(args.node, args.storage);

          case 'proxmox_restore_backup_lxc':
            return await this.restoreBackup(args.node, args.vmid, args.archive, args.storage, 'lxc', args.overwrite);

          case 'proxmox_restore_backup_vm':
            return await this.restoreBackup(args.node, args.vmid, args.archive, args.storage, 'qemu', args.overwrite);

          case 'proxmox_delete_backup':
            return await this.deleteBackup(args.node, args.storage, args.volume);

          case 'proxmox_add_disk_vm':
            return await this.addDiskVM(args.node, args.vmid, args.disk, args.storage, args.size);

          case 'proxmox_add_mountpoint_lxc':
            return await this.addMountPointLXC(args.node, args.vmid, args.mp, args.storage, args.size);

          case 'proxmox_resize_disk_vm':
            return await this.resizeDiskVM(args.node, args.vmid, args.disk, args.size);

          case 'proxmox_resize_disk_lxc':
            return await this.resizeDiskLXC(args.node, args.vmid, args.disk, args.size);

          case 'proxmox_remove_disk_vm':
            return await this.removeDiskVM(args.node, args.vmid, args.disk);

          case 'proxmox_remove_mountpoint_lxc':
            return await this.removeMountPointLXC(args.node, args.vmid, args.mp);

          case 'proxmox_move_disk_vm':
            return await this.moveDiskVM(args.node, args.vmid, args.disk, args.storage, args.delete);

          case 'proxmox_move_disk_lxc':
            return await this.moveDiskLXC(args.node, args.vmid, args.disk, args.storage, args.delete);

          case 'proxmox_add_network_vm':
            return await this.addNetworkVM(args.node, args.vmid, args.net, args.bridge, args.model, args.macaddr, args.vlan, args.firewall);

          case 'proxmox_add_network_lxc':
            return await this.addNetworkLXC(args.node, args.vmid, args.net, args.bridge, args.ip, args.gw, args.firewall);

          case 'proxmox_update_network_vm':
            return await this.updateNetworkVM(args.node, args.vmid, args.net, args.bridge, args.model, args.macaddr, args.vlan, args.firewall);

          case 'proxmox_update_network_lxc':
            return await this.updateNetworkLXC(args.node, args.vmid, args.net, args.bridge, args.ip, args.gw, args.firewall);

          case 'proxmox_remove_network_vm':
            return await this.removeNetworkVM(args.node, args.vmid, args.net);

          case 'proxmox_remove_network_lxc':
            return await this.removeNetworkLXC(args.node, args.vmid, args.net);

          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: `Error: ${error.message}`
            }
          ],
          isError: true
        };
      }
    });
  }

  async getNodes() {
    const nodes = await this.proxmoxRequest('/nodes');
    
    let output = '**Proxmox Cluster Nodes**\n\n';

    for (const node of nodes) {
      const uptime = node.uptime ? this.formatUptime(node.uptime) : 'N/A';
      const cpuUsage = node.cpu ? `${(node.cpu * 100).toFixed(1)}%` : 'N/A';
      const memUsage = node.mem && node.maxmem ?
        `${this.formatBytes(node.mem)} / ${this.formatBytes(node.maxmem)} (${((node.mem / node.maxmem) * 100).toFixed(1)}%)` : 'N/A';

      output += `**${node.node}**\n`;
      output += `   • Status: ${node.status}\n`;
      output += `   • Uptime: ${uptime}\n`;
      output += `   • CPU: ${cpuUsage}\n`;
      output += `   • Memory: ${memUsage}\n`;
      output += `   • Load: ${node.loadavg?.[0]?.toFixed(2) || 'N/A'}\n\n`;
    }
    
    return {
      content: [{ type: 'text', text: output }]
    };
  }

  async getNodeStatus(node) {
    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);

      const status = await this.proxmoxRequest(`/nodes/${safeNode}/status`);

      let output = `**Node ${safeNode} Status**\n\n`;
      output += `• **Status**: ${status.uptime ? 'Online' : 'Offline'}\n`;
      output += `• **Uptime**: ${status.uptime ? this.formatUptime(status.uptime) : 'N/A'}\n`;
      output += `• **Load Average**: ${status.loadavg?.join(', ') || 'N/A'}\n`;
      output += `• **CPU Usage**: ${status.cpu ? `${(status.cpu * 100).toFixed(1)}%` : 'N/A'}\n`;
      output += `• **Memory**: ${status.memory ?
        `${this.formatBytes(status.memory.used)} / ${this.formatBytes(status.memory.total)} (${((status.memory.used / status.memory.total) * 100).toFixed(1)}%)` : 'N/A'}\n`;
      output += `• **Root Disk**: ${status.rootfs ?
        `${this.formatBytes(status.rootfs.used)} / ${this.formatBytes(status.rootfs.total)} (${((status.rootfs.used / status.rootfs.total) * 100).toFixed(1)}%)` : 'N/A'}\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to get node status**\n\nError: ${error.message}`
        }],
        isError: true
      };
    }
  }

  async getVMs(nodeFilter = null, typeFilter = 'all') {
    let vms = [];
    const unreachableNodes = [];

    if (nodeFilter) {
      const safeNodeFilter = this.validateNodeName(nodeFilter);
      const nodeVMs = await this.proxmoxRequest(`/nodes/${safeNodeFilter}/qemu`);
      const nodeLXCs = await this.proxmoxRequest(`/nodes/${safeNodeFilter}/lxc`);

      if (typeFilter === 'all' || typeFilter === 'qemu') {
        vms.push(...nodeVMs.map(vm => ({ ...vm, type: 'qemu', node: safeNodeFilter })));
      }
      if (typeFilter === 'all' || typeFilter === 'lxc') {
        vms.push(...nodeLXCs.map(vm => ({ ...vm, type: 'lxc', node: safeNodeFilter })));
      }
    } else {
      const nodes = await this.proxmoxRequest('/nodes');

      for (const node of nodes) {
        try {
          if (typeFilter === 'all' || typeFilter === 'qemu') {
            const nodeVMs = await this.proxmoxRequest(`/nodes/${node.node}/qemu`);
            vms.push(...nodeVMs.map(vm => ({ ...vm, type: 'qemu', node: node.node })));
          }

          if (typeFilter === 'all' || typeFilter === 'lxc') {
            const nodeLXCs = await this.proxmoxRequest(`/nodes/${node.node}/lxc`);
            vms.push(...nodeLXCs.map(vm => ({ ...vm, type: 'lxc', node: node.node })));
          }
        } catch (error) {
          unreachableNodes.push({ node: node.node, message: error.message });
        }
      }
    }

    let output = '**Virtual Machines**\n\n';
    
    if (vms.length === 0) {
      output += 'No virtual machines found.\n';
    } else {
      for (const vm of vms.sort((a, b) => parseInt(a.vmid) - parseInt(b.vmid))) {
        const uptime = vm.uptime ? this.formatUptime(vm.uptime) : 'N/A';
        const cpuUsage = vm.cpu ? `${(vm.cpu * 100).toFixed(1)}%` : 'N/A';
        const memUsage = vm.mem && vm.maxmem ?
          `${this.formatBytes(vm.mem)} / ${this.formatBytes(vm.maxmem)}` : 'N/A';

        output += `**${vm.name || `VM-${vm.vmid}`}** (ID: ${vm.vmid})\n`;
        output += `   • Node: ${vm.node}\n`;
        output += `   • Status: ${vm.status}\n`;
        output += `   • Type: ${vm.type.toUpperCase()}\n`;
        if (vm.status === 'running') {
          output += `   • Uptime: ${uptime}\n`;
          output += `   • CPU: ${cpuUsage}\n`;
          output += `   • Memory: ${memUsage}\n`;
          if (vm.maxdisk) {
            output += `   • Root FS: ${this.formatBytes(vm.disk || 0)} / ${this.formatBytes(vm.maxdisk)} (${(((vm.disk || 0) / vm.maxdisk) * 100).toFixed(1)}%)\n`;
          }
          if (vm.maxswap) {
            output += `   • Swap: ${this.formatBytes(vm.swap || 0)} / ${this.formatBytes(vm.maxswap)} (${(((vm.swap || 0) / vm.maxswap) * 100).toFixed(1)}%)\n`;
          }
        }
        output += '\n';
      }
    }

    for (const failed of unreachableNodes) {
      output += `Note: node ${failed.node} unreachable, its VMs are not listed (${failed.message})\n`;
    }

    return {
      content: [{ type: 'text', text: output }]
    };
  }

  async getVMStatus(node, vmid, type = 'qemu') {
    try {
      // Validate inputs
      if (type !== 'qemu' && type !== 'lxc') {
        throw new Error(`Invalid VM type "${type}". Must be 'qemu' or 'lxc'`);
      }
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);

      const vmStatus = await this.proxmoxRequest(`/nodes/${safeNode}/${type}/${safeVMID}/status/current`);

      let output = `**${vmStatus.name || `VM-${safeVMID}`}** (ID: ${safeVMID})\n\n`;
      output += `• **Node**: ${safeNode}\n`;
    output += `• **Status**: ${vmStatus.status}\n`;
    output += `• **Type**: ${type.toUpperCase()}\n`;
    
    if (vmStatus.status === 'running') {
      output += `• **Uptime**: ${vmStatus.uptime ? this.formatUptime(vmStatus.uptime) : 'N/A'}\n`;
      output += `• **CPU Usage**: ${vmStatus.cpu ? `${(vmStatus.cpu * 100).toFixed(1)}%` : 'N/A'}\n`;
      output += `• **Memory**: ${vmStatus.mem && vmStatus.maxmem ?
        `${this.formatBytes(vmStatus.mem)} / ${this.formatBytes(vmStatus.maxmem)} (${((vmStatus.mem / vmStatus.maxmem) * 100).toFixed(1)}%)` : 'N/A'}\n`;
      if (vmStatus.maxdisk) {
        output += `• **Root FS**: ${this.formatBytes(vmStatus.disk || 0)} / ${this.formatBytes(vmStatus.maxdisk)} (${((( vmStatus.disk || 0) / vmStatus.maxdisk) * 100).toFixed(1)}%)\n`;
      }
      if (vmStatus.maxswap) {
        output += `• **Swap**: ${this.formatBytes(vmStatus.swap || 0)} / ${this.formatBytes(vmStatus.maxswap)} (${(((vmStatus.swap || 0) / vmStatus.maxswap) * 100).toFixed(1)}%)\n`;
      }
      output += `• **Disk Read**: ${vmStatus.diskread ? this.formatBytes(vmStatus.diskread) : 'N/A'}\n`;
      output += `• **Disk Write**: ${vmStatus.diskwrite ? this.formatBytes(vmStatus.diskwrite) : 'N/A'}\n`;
      output += `• **Network In**: ${vmStatus.netin ? this.formatBytes(vmStatus.netin) : 'N/A'}\n`;
      output += `• **Network Out**: ${vmStatus.netout ? this.formatBytes(vmStatus.netout) : 'N/A'}\n`;
    }

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{ type: 'text', text: `Failed to get VM status: ${error.message}` }],
        isError: true
      };
    }
  }

  async executeVMCommand(node, vmid, command, type = 'qemu') {
    // The Proxmox REST API has no LXC exec endpoint (pct exec is CLI-only),
    // so reject LXC before the permission gate: elevation would not help.
    if (type === 'lxc') {
      return {
        content: [{
          type: 'text',
          text: `**LXC command execution is not supported by the Proxmox API**\n\nThe REST API has no exec endpoint for LXC containers; \`pct exec\` is CLI-only.\nTo run a command in container ${vmid}, use a shell on the node instead:\n\n\`pct exec ${vmid} -- ${command}\``
        }],
        isError: true
      };
    }

    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**VM Command Execution Requires Elevated Permissions**\n\nTo execute commands on VMs, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file and ensure your API token has appropriate VM permissions.\n\n**Current permissions**: Basic (VM listing only)\n**Requested command**: \`${command}\``
        }]
      };
    }

    try {
      // Validate inputs to prevent injection attacks
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeCommand = this.validateCommand(command);

      // QEMU guest agent exec takes the command as an array (no shell). If the
      // input contains whitespace, run it through /bin/sh -c so quoting and
      // arguments behave as the caller expects.
      const commandParts = /\s/.test(safeCommand)
        ? ['/bin/sh', '-c', safeCommand]
        : [safeCommand];

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/qemu/${safeVMID}/agent/exec`, 'POST', {
        command: commandParts
      });

      let output = `**Command submitted to VM ${safeVMID} via guest agent**\n\n`;
      output += `**Command**: \`${safeCommand}\`\n`;
      output += `**PID**: ${result?.pid ?? 'N/A'}\n\n`;
      if (result?.pid) {
        output += `Call \`proxmox_get_exec_status\` with node "${safeNode}", vmid "${safeVMID}" and pid ${result.pid} to retrieve the exit code and output.`;
      }

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to execute command on VM ${vmid}**\n\nError: ${error.message}\n\nNote: Make sure the VM has the QEMU guest agent installed and running.`
        }],
        isError: true
      };
    }
  }

  async getExecStatus(node, vmid, pid) {
    try {
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safePID = this.validatePID(pid);

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/qemu/${safeVMID}/agent/exec-status?pid=${safePID}`);

      let output = `**Exec status for PID ${safePID} on VM ${safeVMID}**\n\n`;
      output += `• **Exited**: ${result.exited ? 'yes' : 'no (still running)'}\n`;
      if (result.exited) {
        output += `• **Exit code**: ${result.exitcode ?? 'N/A'}\n`;
        if (result.signal !== undefined && result.signal !== null) {
          output += `• **Signal**: ${result.signal}\n`;
        }
      }
      if (result['out-data']) {
        output += `\n**stdout**:\n\`\`\`\n${result['out-data']}\n\`\`\`\n`;
      }
      if (result['err-data']) {
        output += `\n**stderr**:\n\`\`\`\n${result['err-data']}\n\`\`\`\n`;
      }
      if (!result['out-data'] && !result['err-data']) {
        output += `\nNo output captured${result.exited ? '' : ' yet; call again once the command has exited'}.\n`;
      }
      if (result['out-truncated'] || result['err-truncated']) {
        output += `\nNote: output was truncated by the guest agent.\n`;
      }

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to get exec status**\n\nError: ${error.message}`
        }],
        isError: true
      };
    }
  }

  async getTaskStatus(node, upid) {
    try {
      const safeNode = this.validateNodeName(node);
      const safeUPID = this.validateUPID(upid);

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/tasks/${encodeURIComponent(safeUPID)}/status`);

      let output = `**Task status**\n\n`;
      output += `• **UPID**: ${safeUPID}\n`;
      output += `• **Type**: ${result.type || 'N/A'}\n`;
      output += `• **Status**: ${result.status || 'N/A'}\n`;
      if (result.status === 'stopped') {
        output += `• **Exit status**: ${result.exitstatus || 'N/A'}\n`;
      }
      if (result.starttime) {
        output += `• **Started**: ${new Date(result.starttime * 1000).toLocaleString()}\n`;
      }
      if (result.status === 'running') {
        output += `\nThe task is still running; call proxmox_get_task_status again to re-check, or proxmox_get_task_log for progress.\n`;
      }

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to get task status**\n\nError: ${error.message}`
        }],
        isError: true
      };
    }
  }

  async getTaskLog(node, upid, start, limit) {
    try {
      const safeNode = this.validateNodeName(node);
      const safeUPID = this.validateUPID(upid);

      const params = new URLSearchParams();
      if (start !== undefined) {
        const startNum = Number(start);
        if (!Number.isInteger(startNum) || startNum < 0) {
          throw new Error(`Invalid start "${start}". Must be a non-negative integer`);
        }
        params.set('start', String(startNum));
      }
      if (limit !== undefined) {
        const limitNum = Number(limit);
        if (!Number.isInteger(limitNum) || limitNum < 1) {
          throw new Error(`Invalid limit "${limit}". Must be a positive integer`);
        }
        params.set('limit', String(limitNum));
      }

      const query = params.toString() ? `?${params.toString()}` : '';
      const result = await this.proxmoxRequest(`/nodes/${safeNode}/tasks/${encodeURIComponent(safeUPID)}/log${query}`);

      let output = `**Task log for ${safeUPID}**\n\n`;
      if (!result || result.length === 0) {
        output += 'No log lines returned.\n';
      } else {
        output += '```\n';
        for (const line of result) {
          output += `${line.t ?? ''}\n`;
        }
        output += '```\n';
      }

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to get task log**\n\nError: ${error.message}`
        }],
        isError: true
      };
    }
  }

  async getStorage(nodeFilter = null) {
    let storages = [];
    const unreachableNodes = [];

    if (nodeFilter) {
      const safeNodeFilter = this.validateNodeName(nodeFilter);
      storages = await this.proxmoxRequest(`/nodes/${safeNodeFilter}/storage`);
      storages = storages.map(storage => ({ ...storage, node: safeNodeFilter }));
    } else {
      const nodes = await this.proxmoxRequest('/nodes');

      for (const node of nodes) {
        try {
          const nodeStorages = await this.proxmoxRequest(`/nodes/${node.node}/storage`);
          storages.push(...nodeStorages.map(storage => ({ ...storage, node: node.node })));
        } catch (error) {
          unreachableNodes.push({ node: node.node, message: error.message });
        }
      }
    }

    let output = '**Storage Pools**\n\n';
    
    if (storages.length === 0) {
      output += 'No storage found.\n';
    } else {
      const uniqueStorages = [];
      const seen = new Set();
      
      for (const storage of storages) {
        const key = `${storage.storage}-${storage.node}`;
        if (!seen.has(key)) {
          seen.add(key);
          uniqueStorages.push(storage);
        }
      }
      
      for (const storage of uniqueStorages.sort((a, b) => a.storage.localeCompare(b.storage))) {
        const usagePercent = storage.total && storage.used ?
          ((storage.used / storage.total) * 100).toFixed(1) : 'N/A';

        output += `**${storage.storage}**\n`;
        output += `   • Node: ${storage.node}\n`;
        output += `   • Type: ${storage.type || 'N/A'}\n`;
        output += `   • Content: ${storage.content || 'N/A'}\n`;
        if (storage.total && storage.used) {
          output += `   • Usage: ${this.formatBytes(storage.used)} / ${this.formatBytes(storage.total)} (${usagePercent}%)\n`;
        }
        output += `   • Status: ${storage.enabled ? 'Enabled' : 'Disabled'}\n\n`;
      }
    }

    for (const failed of unreachableNodes) {
      output += `Note: node ${failed.node} unreachable, its storage is not listed (${failed.message})\n`;
    }

    return {
      content: [{ type: 'text', text: output }]
    };
  }

  async getClusterStatus() {
    try {
      const nodes = await this.proxmoxRequest('/nodes');
      
      // Try to get cluster status, but fall back gracefully if permissions are insufficient
      let clusterStatus = null;
      if (this.allowElevated) {
        try {
          clusterStatus = await this.proxmoxRequest('/cluster/status');
        } catch (error) {
          // Ignore cluster status errors for elevated permissions
        }
      }
      
      let output = '**Proxmox Cluster Status**\n\n';

      // Cluster overview
      const onlineNodes = nodes.filter(n => n.status === 'online').length;
      const totalNodes = nodes.length;

      output += `**Cluster Health**: ${onlineNodes === totalNodes ? 'Healthy' : 'Warning'}\n`;
      output += `**Nodes**: ${onlineNodes}/${totalNodes} online\n`;

      if (Array.isArray(clusterStatus)) {
        const clusterInfo = clusterStatus.find(item => item.type === 'cluster');
        if (clusterInfo) {
          output += `**Cluster**: ${clusterInfo.name || 'N/A'} (quorate: ${clusterInfo.quorate ? 'yes' : 'no'})\n`;
        }
      }
      output += `\n`;

      if (this.allowElevated) {
        // Resource summary (only available with elevated permissions)
        let totalCpu = 0, usedCpu = 0;
        let totalMem = 0, usedMem = 0;
        
        for (const node of nodes) {
          if (node.status === 'online') {
            totalCpu += node.maxcpu || 0;
            usedCpu += (node.cpu || 0) * (node.maxcpu || 0);
            totalMem += node.maxmem || 0;
            usedMem += node.mem || 0;
          }
        }
        
        const cpuPercent = totalCpu > 0 ? ((usedCpu / totalCpu) * 100).toFixed(1) : 'N/A';
        const memPercent = totalMem > 0 ? ((usedMem / totalMem) * 100).toFixed(1) : 'N/A';
        
        output += `**Resource Usage**:\n`;
        output += `• CPU: ${cpuPercent}% (${usedCpu.toFixed(1)}/${totalCpu} cores)\n`;
        output += `• Memory: ${memPercent}% (${this.formatBytes(usedMem)}/${this.formatBytes(totalMem)})\n\n`;
      } else {
        output += `**Limited Information**: Resource usage requires elevated permissions\n\n`;
      }
      
      // Node status
      output += `**Node Details**:\n`;
      for (const node of nodes.sort((a, b) => a.node.localeCompare(b.node))) {
        output += `${node.node} - ${node.status}\n`;
      }
      
      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{ 
          type: 'text', 
          text: `**Failed to get cluster status**\n\nError: ${error.message}` 
        }],
        isError: true
      };
    }
  }

  async listTemplates(node, storage = 'local') {
    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeStorage = this.validateStorageName(storage);

      const templates = await this.proxmoxRequest(`/nodes/${safeNode}/storage/${safeStorage}/content?content=vztmpl`);

      let output = '**Available LXC Templates**\n\n';

      if (!templates || templates.length === 0) {
        output += `No templates found on storage \`${safeStorage}\`.\n\n`;
        output += `**Tip**: Download templates in Proxmox:\n`;
        output += `1. Go to your node → Storage → ${safeStorage}\n`;
        output += `2. Click "CT Templates"\n`;
        output += `3. Download a template (e.g., Debian, Ubuntu)\n`;
      } else {
        for (const template of templates) {
          const size = template.size ? this.formatBytes(template.size) : 'N/A';
          output += `• **${template.volid}**\n`;
          output += `  Size: ${size}\n\n`;
        }
      }

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to list templates**\n\nError: ${error.message}\n\n**Note**: Make sure the storage exists and contains LXC templates.`
        }],
        isError: true
      };
    }
  }

  async createLXCContainer(args) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Container Creation Requires Elevated Permissions**\n\nTo create containers, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file and ensure your API token has VM.Allocate permissions.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(args.node);
      const safeVMID = this.validateVMID(args.vmid);

      // Generate secure password if not provided
      const generatedPassword = args.password || this.generateSecurePassword();
      const isPasswordGenerated = !args.password;

      // Build the request body
      const rootfsGB = this.parseDiskSizeGB(args.rootfs ?? 8, 'rootfs size');
      const body = {
        vmid: safeVMID,
        ostemplate: args.ostemplate,
        hostname: args.hostname || `ct${safeVMID}`,
        password: generatedPassword,
        memory: args.memory || 512,
        storage: args.storage || 'local-lvm',
        rootfs: `${args.storage || 'local-lvm'}:${rootfsGB}`
      };

      // Make the API request
      const result = await this.proxmoxRequest(`/nodes/${safeNode}/lxc`, 'POST', body);

      let output = `**LXC Container Creation Started**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Hostname**: ${body.hostname}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += `• **Template**: ${args.ostemplate}\n`;
      output += `• **Memory**: ${body.memory} MB\n`;
      output += `• **Storage**: ${body.storage}\n`;

      if (isPasswordGenerated) {
        output += `• **Generated Password**: \`${generatedPassword}\`\n`;
        output += `  **SAVE THIS PASSWORD** - it will not be shown again!\n`;
      }

      output += this.formatTaskLine(result);
      output += `**Next steps**:\n`;
      output += `1. Wait a moment for container to be created\n`;
      output += `2. Start it with \`proxmox_start_lxc\`\n`;
      output += `3. View status with \`proxmox_get_vm_status\`\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to create container**\n\nError: ${error.message}\n\n**Common issues**:\n- VM ID already in use\n- Invalid template path\n- Insufficient permissions\n- Storage doesn't exist`
        }],
        isError: true
      };
    }
  }

  async createVM(args) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**VM Creation Requires Elevated Permissions**\n\nTo create VMs, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file and ensure your API token has VM.Allocate permissions.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(args.node);
      const safeVMID = this.validateVMID(args.vmid);

      // Build the request body for QEMU VM creation
      const body = {
        vmid: safeVMID,
        name: args.name || `vm${safeVMID}`,
        memory: args.memory || 512,
        cores: args.cores || 1,
        sockets: args.sockets || 1,
        ostype: args.ostype || 'l26',
        net0: args.net0 || 'virtio,bridge=vmbr0'
      };

      // Add disk configuration
      // Format: storage:size (size in integer GB, no suffix)
      const storage = args.storage || 'local-lvm';
      const diskSizeGB = this.parseDiskSizeGB(args.disk_size || '8G', 'disk_size');
      body.scsi0 = `${storage}:${diskSizeGB}`;

      // Add ISO if provided
      if (args.iso) {
        body.ide2 = `${args.iso},media=cdrom`;
        body.boot = 'order=ide2;scsi0';
      }

      // Make the API request
      const result = await this.proxmoxRequest(`/nodes/${safeNode}/qemu`, 'POST', body);

      let output = `**QEMU VM Creation Started**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Name**: ${body.name}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += `• **Memory**: ${body.memory} MB\n`;
      output += `• **CPU**: ${body.sockets} socket(s), ${body.cores} core(s)\n`;
      output += `• **Disk**: ${body.scsi0}\n`;
      output += `• **Network**: ${body.net0}\n`;
      if (args.iso) {
        output += `• **ISO**: ${args.iso}\n`;
      }
      output += this.formatTaskLine(result);
      output += `**Next steps**:\n`;
      output += `1. Wait a moment for VM to be created\n`;
      output += `2. Start it with \`proxmox_start_vm\`\n`;
      output += `3. View status with \`proxmox_get_vm_status\`\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to create VM**\n\nError: ${error.message}\n\n**Common issues**:\n- VM ID already in use\n- Invalid ISO path\n- Insufficient permissions\n- Storage doesn't exist`
        }],
        isError: true
      };
    }
  }

  async startVM(node, vmid, type = 'lxc') {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**VM Control Requires Elevated Permissions**\n\nTo start/stop VMs, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/${type}/${safeVMID}/status/start`, 'POST', {});

      let output = `**VM/Container Start Command Sent**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Type**: ${type.toUpperCase()}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += this.formatTaskLine(result);
      output += `**Tip**: Use \`proxmox_get_vm_status\` to check if it's running.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to start VM/Container**\n\nError: ${error.message}`
        }],
        isError: true
      };
    }
  }

  async stopVM(node, vmid, type = 'lxc') {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**VM Control Requires Elevated Permissions**\n\nTo start/stop VMs, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/${type}/${safeVMID}/status/stop`, 'POST', {});

      let output = `**VM/Container Stop Command Sent**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Type**: ${type.toUpperCase()}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += this.formatTaskLine(result);
      output += `**Tip**: Use \`proxmox_get_vm_status\` to confirm it's stopped.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to stop VM/Container**\n\nError: ${error.message}`
        }],
        isError: true
      };
    }
  }

  async getNextVMID() {
    try {
      const result = await this.proxmoxRequest('/cluster/nextid');
      return {
        content: [{ type: 'text', text: `**Next Available VM/Container ID**: ${result}` }]
      };
    } catch (error) {
      return {
        content: [{ type: 'text', text: `**Failed to get next VMID**\n\nError: ${error.message}` }],
        isError: true
      };
    }
  }

  async deleteVM(node, vmid, type = 'lxc') {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**VM/Container Deletion Requires Elevated Permissions**\n\nTo delete VMs/containers, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/${type}/${safeVMID}`, 'DELETE');

      let output = `**VM/Container Deletion Started**\n\n`;
      output += `• **VM/Container ID**: ${safeVMID}\n`;
      output += `• **Type**: ${type.toUpperCase()}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += this.formatTaskLine(result);
      output += `**Note**: Deletion may take a moment to complete.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to delete VM/Container**\n\nError: ${error.message}\n\n**Note**: Make sure the VM/container is stopped first.`
        }],
        isError: true
      };
    }
  }

  async rebootVM(node, vmid, type = 'lxc') {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**VM Reboot Requires Elevated Permissions**\n\nTo reboot VMs/containers, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/${type}/${safeVMID}/status/reboot`, 'POST', {});

      let output = `**VM/Container Reboot Command Sent**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Type**: ${type.toUpperCase()}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += this.formatTaskLine(result);
      output += `**Tip**: The VM/container will restart momentarily.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to reboot VM/Container**\n\nError: ${error.message}`
        }],
        isError: true
      };
    }
  }

  async shutdownVM(node, vmid, type = 'lxc') {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**VM Shutdown Requires Elevated Permissions**\n\nTo shutdown VMs/containers, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/${type}/${safeVMID}/status/shutdown`, 'POST', {});

      let output = `**VM/Container Shutdown Command Sent**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Type**: ${type.toUpperCase()}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += this.formatTaskLine(result);
      output += `**Note**: This is a graceful shutdown. Use \`proxmox_stop_vm\` for forceful stop.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to shutdown VM/Container**\n\nError: ${error.message}`
        }],
        isError: true
      };
    }
  }

  async pauseVM(node, vmid) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**VM Pause Requires Elevated Permissions**\n\nTo pause VMs, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/qemu/${safeVMID}/status/suspend`, 'POST', {});

      let output = `**VM Pause Command Sent**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Type**: QEMU\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += this.formatTaskLine(result);
      output += `**Note**: VM is now paused. Use \`proxmox_resume_vm\` to resume.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to pause VM**\n\nError: ${error.message}\n\n**Note**: Pause is only available for QEMU VMs, not LXC containers.`
        }],
        isError: true
      };
    }
  }

  async resumeVM(node, vmid) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**VM Resume Requires Elevated Permissions**\n\nTo resume VMs, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/qemu/${safeVMID}/status/resume`, 'POST', {});

      let output = `**VM Resume Command Sent**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Type**: QEMU\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += this.formatTaskLine(result);
      output += `**Note**: VM is now resuming from paused state.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to resume VM**\n\nError: ${error.message}\n\n**Note**: Resume is only available for QEMU VMs, not LXC containers.`
        }],
        isError: true
      };
    }
  }

  async cloneVM(node, vmid, newid, nameOrHostname, type = 'lxc') {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**VM Clone Requires Elevated Permissions**\n\nTo clone VMs/containers, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeNewID = this.validateVMID(newid);

      const body = {
        newid: safeNewID
      };

      // For LXC, use 'hostname', for QEMU use 'name'
      if (type === 'lxc') {
        body.hostname = nameOrHostname || `clone-${safeNewID}`;
      } else {
        body.name = nameOrHostname || `clone-${safeNewID}`;
      }

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/${type}/${safeVMID}/clone`, 'POST', body);

      let output = `**VM/Container Clone Started**\n\n`;
      output += `• **Source VM ID**: ${safeVMID}\n`;
      output += `• **New VM ID**: ${safeNewID}\n`;
      output += `• **New Name**: ${nameOrHostname || `clone-${safeNewID}`}\n`;
      output += `• **Type**: ${type.toUpperCase()}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += this.formatTaskLine(result);
      output += `**Note**: Clone operation may take several minutes. Check task status in Proxmox.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to clone VM/Container**\n\nError: ${error.message}\n\n**Common issues**:\n- New VM ID already in use\n- Insufficient storage space\n- Source VM is running (some storage types require stopped VM)`
        }],
        isError: true
      };
    }
  }

  async resizeVM(node, vmid, memory, cores, type = 'lxc') {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**VM Resize Requires Elevated Permissions**\n\nTo resize VMs/containers, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    // Build body with only provided parameters
    const body = {};
    if (memory !== undefined) {
      body.memory = memory;
    }
    if (cores !== undefined) {
      body.cores = cores;
    }

    if (Object.keys(body).length === 0) {
      return {
        content: [{
          type: 'text',
          text: `**No Resize Parameters Provided**\n\nPlease specify at least one parameter:\n- \`memory\`: Memory in MB\n- \`cores\`: Number of CPU cores`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/${type}/${safeVMID}/config`, 'PUT', body);

      let output = `**VM/Container Resize Command Sent**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Type**: ${type.toUpperCase()}\n`;
      output += `• **Node**: ${safeNode}\n`;
      if (memory !== undefined) {
        output += `• **New Memory**: ${memory} MB\n`;
      }
      if (cores !== undefined) {
        output += `• **New Cores**: ${cores}\n`;
      }
      output += this.formatTaskLine(result);
      output += `**Note**: Some changes may require a reboot to take effect.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to resize VM/Container**\n\nError: ${error.message}\n\n**Common issues**:\n- Memory/CPU values exceed node capacity\n- VM is locked or in use\n- Invalid parameter values`
        }],
        isError: true
      };
    }
  }

  async createSnapshot(node, vmid, snapname, type = 'lxc') {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Snapshot Creation Requires Elevated Permissions**\n\nTo create snapshots, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeSnapname = this.validateSnapshotName(snapname);

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/${type}/${safeVMID}/snapshot`, 'POST', {
        snapname: safeSnapname
      });

      let output = `**Snapshot Creation Started**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Snapshot Name**: ${safeSnapname}\n`;
      output += `• **Type**: ${type.toUpperCase()}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += this.formatTaskLine(result);
      output += `**Tip**: Use \`proxmox_list_snapshots_${type === 'lxc' ? 'lxc' : 'vm'}\` to view all snapshots.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to create snapshot**\n\nError: ${error.message}\n\n**Common issues**:\n- Snapshot name already exists\n- Insufficient disk space\n- VM is locked or in use`
        }],
        isError: true
      };
    }
  }

  async listSnapshots(node, vmid, type = 'lxc') {
    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);

      const snapshots = await this.proxmoxRequest(`/nodes/${safeNode}/${type}/${safeVMID}/snapshot`);

      let output = `**Snapshots for ${type.toUpperCase()} ${safeVMID}**\n\n`;

      if (!snapshots || snapshots.length === 0) {
        output += `No snapshots found.\n\n`;
        output += `**Tip**: Create a snapshot with \`proxmox_create_snapshot_${type === 'lxc' ? 'lxc' : 'vm'}\`.\n`;
      } else {
        // Filter out 'current' pseudo-snapshot that Proxmox includes
        const realSnapshots = snapshots.filter(snap => snap.name !== 'current');

        if (realSnapshots.length === 0) {
          output += `No snapshots found.\n\n`;
          output += `**Tip**: Create a snapshot with \`proxmox_create_snapshot_${type === 'lxc' ? 'lxc' : 'vm'}\`.\n`;
        } else {
          for (const snapshot of realSnapshots) {
            output += `• **${snapshot.name}**\n`;
            if (snapshot.description) {
              output += `  Description: ${snapshot.description}\n`;
            }
            if (snapshot.snaptime) {
              const date = new Date(snapshot.snaptime * 1000);
              output += `  Created: ${date.toLocaleString()}\n`;
            }
            output += `\n`;
          }
          output += `**Total**: ${realSnapshots.length} snapshot(s)\n`;
        }
      }

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to list snapshots**\n\nError: ${error.message}`
        }],
        isError: true
      };
    }
  }

  async rollbackSnapshot(node, vmid, snapname, type = 'lxc') {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Snapshot Rollback Requires Elevated Permissions**\n\nTo rollback snapshots, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeSnapname = this.validateSnapshotName(snapname);

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/${type}/${safeVMID}/snapshot/${safeSnapname}/rollback`, 'POST', {});

      let output = `**Snapshot Rollback Started**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Snapshot Name**: ${safeSnapname}\n`;
      output += `• **Type**: ${type.toUpperCase()}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += this.formatTaskLine(result);
      output += `**Warning**: This will restore the VM/container to the state of the snapshot.\n`;
      output += `**Tip**: Any changes made after the snapshot was created will be lost.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to rollback snapshot**\n\nError: ${error.message}\n\n**Common issues**:\n- Snapshot doesn't exist\n- VM is running (stop it first)\n- VM is locked or in use`
        }],
        isError: true
      };
    }
  }

  async deleteSnapshot(node, vmid, snapname, type = 'lxc') {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Snapshot Deletion Requires Elevated Permissions**\n\nTo delete snapshots, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeSnapname = this.validateSnapshotName(snapname);

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/${type}/${safeVMID}/snapshot/${safeSnapname}`, 'DELETE');

      let output = `**Snapshot Deletion Started**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Snapshot Name**: ${safeSnapname}\n`;
      output += `• **Type**: ${type.toUpperCase()}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += this.formatTaskLine(result);
      output += `**Note**: Snapshot deletion may take a moment to complete.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to delete snapshot**\n\nError: ${error.message}\n\n**Common issues**:\n- Snapshot doesn't exist\n- VM is locked or in use\n- Insufficient permissions`
        }],
        isError: true
      };
    }
  }

  async createBackup(node, vmid, storage = 'local', mode = 'snapshot', compress = 'zstd', type = 'lxc') {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Backup Creation Requires Elevated Permissions**\n\nTo create backups, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeStorage = this.validateStorageName(storage);

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/vzdump`, 'POST', {
        vmid: safeVMID,
        storage: safeStorage,
        mode: mode,
        // vzdump accepts 0|1|gzip|lzo|zstd; the schema exposes the friendlier 'none'
        compress: compress === 'none' ? 0 : compress
      });

      let output = `**Backup Creation Started**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Type**: ${type.toUpperCase()}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += `• **Storage**: ${safeStorage}\n`;
      output += `• **Mode**: ${mode}\n`;
      output += `• **Compression**: ${compress}\n`;
      output += this.formatTaskLine(result);
      output += `**Tip**: Backup runs in the background. Use \`proxmox_list_backups\` to view all backups.\n`;
      output += `**Note**: Backup modes:\n`;
      output += `  - snapshot: Quick backup using snapshots (recommended)\n`;
      output += `  - suspend: Suspends VM during backup\n`;
      output += `  - stop: Stops VM during backup\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to create backup**\n\nError: ${error.message}\n\n**Common issues**:\n- Insufficient disk space on storage\n- VM is locked or in use\n- Invalid storage name\n- Insufficient permissions`
        }],
        isError: true
      };
    }
  }

  async listBackups(node, storage = 'local') {
    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeStorage = this.validateStorageName(storage);

      const backups = await this.proxmoxRequest(`/nodes/${safeNode}/storage/${safeStorage}/content?content=backup`);

      let output = `**Backups on ${safeStorage}**\n\n`;

      if (!backups || backups.length === 0) {
        output += `No backups found on storage \`${safeStorage}\`.\n\n`;
        output += `**Tip**: Create a backup with \`proxmox_create_backup_lxc\` or \`proxmox_create_backup_vm\`.\n`;
      } else {
        // Sort by creation time (newest first)
        backups.sort((a, b) => (b.ctime || 0) - (a.ctime || 0));

        for (const backup of backups) {
          // Parse backup filename to extract VM type and ID
          const filename = backup.volid.split('/').pop();
          const match = filename.match(/vzdump-(lxc|qemu)-(\d+)-/);
          const vmType = match ? match[1].toUpperCase() : 'UNKNOWN';
          const vmId = match ? match[2] : 'N/A';

          output += `• **${filename}**\n`;
          output += `  VM ID: ${vmId} (${vmType})\n`;
          output += `  Size: ${backup.size ? this.formatBytes(backup.size) : 'N/A'}\n`;
          if (backup.ctime) {
            const date = new Date(backup.ctime * 1000);
            output += `  Created: ${date.toLocaleString()}\n`;
          }
          output += `  Volume: ${backup.volid}\n`;
          output += `\n`;
        }
        output += `**Total**: ${backups.length} backup(s)\n`;
      }

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to list backups**\n\nError: ${error.message}\n\n**Common issues**:\n- Storage doesn't exist\n- Storage is not accessible\n- Insufficient permissions`
        }],
        isError: true
      };
    }
  }

  async restoreBackup(node, vmid, archive, storage, type = 'lxc', overwrite = false) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Backup Restore Requires Elevated Permissions**\n\nTo restore backups, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);

      const body = {
        vmid: safeVMID,
        archive: archive
      };

      // 'restore' is only a valid parameter for LXC creation; POST /nodes/{node}/qemu
      // rejects unknown params, so QEMU restores send just vmid + archive.
      if (type === 'lxc') {
        body.restore = 1;
      }

      // Only force-overwrite an existing guest when explicitly requested.
      if (overwrite === true) {
        body.force = 1;
      }

      if (storage) {
        body.storage = this.validateStorageName(storage);
      }

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/${type}`, 'POST', body);

      let output = `**Backup Restore Started**\n\n`;
      output += `• **New VM ID**: ${safeVMID}\n`;
      output += `• **Type**: ${type.toUpperCase()}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += `• **Archive**: ${archive}\n`;
      if (storage) {
        output += `• **Storage**: ${body.storage}\n`;
      }
      output += this.formatTaskLine(result);
      output += `**Note**: Restore operation may take several minutes depending on backup size.\n`;
      output += `**Tip**: Use \`proxmox_get_vm_status\` to check the restored VM status after completion.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to restore backup**\n\nError: ${error.message}\n\n**Common issues**:\n- VM ID already in use\n- Backup archive doesn't exist\n- Insufficient storage space\n- Invalid archive path\n- Insufficient permissions`
        }],
        isError: true
      };
    }
  }

  async deleteBackup(node, storage, volume) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Backup Deletion Requires Elevated Permissions**\n\nTo delete backups, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeStorage = this.validateStorageName(storage);

      const encodedVolume = encodeURIComponent(volume);
      const result = await this.proxmoxRequest(`/nodes/${safeNode}/storage/${safeStorage}/content/${encodedVolume}`, 'DELETE');

      let output = `**Backup Deletion Started**\n\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += `• **Storage**: ${safeStorage}\n`;
      output += `• **Volume**: ${volume}\n`;
      output += this.formatTaskLine(result);
      output += `**Note**: Backup file will be permanently deleted from storage.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to delete backup**\n\nError: ${error.message}\n\n**Common issues**:\n- Backup doesn't exist\n- Invalid volume path\n- Backup is in use\n- Insufficient permissions`
        }],
        isError: true
      };
    }
  }

  async addDiskVM(node, vmid, disk, storage, size) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Disk Management Requires Elevated Permissions**\n\nTo add disks to VMs, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeDisk = this.validateDiskName(disk, 'qemu');
      const safeStorage = this.validateStorageName(storage);
      const sizeGB = this.parseDiskSizeGB(size, 'disk size');

      const body = {
        [safeDisk]: `${safeStorage}:${sizeGB}`
      };

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/qemu/${safeVMID}/config`, 'PUT', body);

      let output = `**VM Disk Addition Started**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += `• **Disk**: ${safeDisk}\n`;
      output += `• **Storage**: ${safeStorage}\n`;
      output += `• **Size**: ${sizeGB} GB\n`;
      output += this.formatTaskLine(result);
      output += `**Note**: The VM may need to be stopped for this operation depending on configuration.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to add disk to VM**\n\nError: ${error.message}\n\n**Common issues**:\n- Disk name already in use\n- VM is running (may need to be stopped)\n- Invalid disk name format\n- Insufficient storage space\n- Storage doesn't exist`
        }],
        isError: true
      };
    }
  }

  async addMountPointLXC(node, vmid, mp, storage, size) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Disk Management Requires Elevated Permissions**\n\nTo add mount points to containers, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeMp = this.validateMountPoint(mp);
      const safeStorage = this.validateStorageName(storage);
      const sizeGB = this.parseDiskSizeGB(size, 'mount point size');

      const body = {
        [safeMp]: `${safeStorage}:${sizeGB}`
      };

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/lxc/${safeVMID}/config`, 'PUT', body);

      let output = `**LXC Mount Point Addition Started**\n\n`;
      output += `• **Container ID**: ${safeVMID}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += `• **Mount Point**: ${safeMp}\n`;
      output += `• **Storage**: ${safeStorage}\n`;
      output += `• **Size**: ${sizeGB} GB\n`;
      output += this.formatTaskLine(result);
      output += `**Note**: The container may need to be stopped for this operation.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to add mount point to container**\n\nError: ${error.message}\n\n**Common issues**:\n- Mount point name already in use\n- Container is running (may need to be stopped)\n- Invalid mount point name\n- Insufficient storage space\n- Storage doesn't exist`
        }],
        isError: true
      };
    }
  }

  async resizeDiskVM(node, vmid, disk, size) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Disk Management Requires Elevated Permissions**\n\nTo resize VM disks, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeDisk = this.validateDiskName(disk, 'qemu');

      const body = {
        disk: safeDisk,
        size: size
      };

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/qemu/${safeVMID}/resize`, 'PUT', body);

      let output = `**VM Disk Resize Started**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += `• **Disk**: ${safeDisk}\n`;
      output += `• **New Size**: ${size}\n`;
      output += this.formatTaskLine(result);
      output += `**Size format examples**:\n`;
      output += `  - +10G: Add 10GB to current size\n`;
      output += `  - 50G: Set absolute size to 50GB\n\n`;
      output += `**Note**: Disks can only be expanded, not shrunk. Some configurations allow online resizing.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to resize VM disk**\n\nError: ${error.message}\n\n**Common issues**:\n- Disk doesn't exist\n- Trying to shrink disk (not supported)\n- Insufficient storage space\n- Invalid size format\n- VM is locked or in use`
        }],
        isError: true
      };
    }
  }

  async resizeDiskLXC(node, vmid, disk, size) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Disk Management Requires Elevated Permissions**\n\nTo resize LXC disks, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeDisk = this.validateDiskName(disk, 'lxc');

      const body = {
        disk: safeDisk,
        size: size
      };

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/lxc/${safeVMID}/resize`, 'PUT', body);

      let output = `**LXC Disk Resize Started**\n\n`;
      output += `• **Container ID**: ${safeVMID}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += `• **Disk**: ${safeDisk}\n`;
      output += `• **New Size**: ${size}\n`;
      output += this.formatTaskLine(result);
      output += `**Size format examples**:\n`;
      output += `  - +10G: Add 10GB to current size\n`;
      output += `  - 50G: Set absolute size to 50GB\n\n`;
      output += `**Valid disk names**: rootfs, mp0, mp1, mp2, etc.\n\n`;
      output += `**Note**: Disks can only be expanded, not shrunk. Container may need to be stopped.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to resize LXC disk**\n\nError: ${error.message}\n\n**Common issues**:\n- Disk doesn't exist\n- Trying to shrink disk (not supported)\n- Insufficient storage space\n- Invalid size format\n- Container is locked or in use`
        }],
        isError: true
      };
    }
  }

  async removeDiskVM(node, vmid, disk) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Disk Management Requires Elevated Permissions**\n\nTo remove disks from VMs, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeDisk = this.validateDiskName(disk, 'qemu');

      const body = {
        delete: safeDisk
      };

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/qemu/${safeVMID}/config`, 'PUT', body);

      let output = `**VM Disk Removal Started**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += `• **Disk**: ${safeDisk}\n`;
      output += this.formatTaskLine(result);
      output += `**Warning**: This will permanently delete the disk and all its data.\n`;
      output += `**Note**: The VM should be stopped for this operation.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to remove disk from VM**\n\nError: ${error.message}\n\n**Common issues**:\n- Disk doesn't exist\n- VM is running (must be stopped)\n- Cannot remove boot disk\n- VM is locked or in use`
        }],
        isError: true
      };
    }
  }

  async removeMountPointLXC(node, vmid, mp) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Disk Management Requires Elevated Permissions**\n\nTo remove mount points from containers, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeMp = this.validateMountPoint(mp);

      const body = {
        delete: safeMp
      };

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/lxc/${safeVMID}/config`, 'PUT', body);

      let output = `**LXC Mount Point Removal Started**\n\n`;
      output += `• **Container ID**: ${safeVMID}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += `• **Mount Point**: ${safeMp}\n`;
      output += this.formatTaskLine(result);
      output += `**Warning**: This will permanently delete the mount point and all its data.\n`;
      output += `**Note**: The container should be stopped for this operation.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to remove mount point from container**\n\nError: ${error.message}\n\n**Common issues**:\n- Mount point doesn't exist\n- Container is running (must be stopped)\n- Cannot remove rootfs\n- Container is locked or in use`
        }],
        isError: true
      };
    }
  }

  async moveDiskVM(node, vmid, disk, storage, deleteSource = false) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Disk Management Requires Elevated Permissions**\n\nTo move VM disks, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeDisk = this.validateDiskName(disk, 'qemu');
      const safeStorage = this.validateStorageName(storage);

      const body = {
        disk: safeDisk,
        storage: safeStorage,
        delete: deleteSource ? 1 : 0
      };

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/qemu/${safeVMID}/move_disk`, 'POST', body);

      let output = `**VM Disk Move Started**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += `• **Disk**: ${safeDisk}\n`;
      output += `• **Target Storage**: ${safeStorage}\n`;
      output += `• **Delete Source**: ${deleteSource ? 'Yes' : 'No'}\n`;
      output += this.formatTaskLine(result);
      output += `**Note**: Disk move operation may take several minutes depending on disk size.\n`;
      output += `**Tip**: The VM should be stopped for this operation in most configurations.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to move VM disk**\n\nError: ${error.message}\n\n**Common issues**:\n- Disk doesn't exist\n- Target storage doesn't exist\n- Insufficient space on target storage\n- VM is running (may need to be stopped)\n- VM is locked or in use`
        }],
        isError: true
      };
    }
  }

  async moveDiskLXC(node, vmid, disk, storage, deleteSource = false) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Disk Management Requires Elevated Permissions**\n\nTo move LXC disks, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeDisk = this.validateDiskName(disk, 'lxc');
      const safeStorage = this.validateStorageName(storage);

      const body = {
        volume: safeDisk,
        storage: safeStorage,
        delete: deleteSource ? 1 : 0
      };

      const result = await this.proxmoxRequest(`/nodes/${safeNode}/lxc/${safeVMID}/move_volume`, 'POST', body);

      let output = `**LXC Disk Move Started**\n\n`;
      output += `• **Container ID**: ${safeVMID}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += `• **Volume**: ${safeDisk}\n`;
      output += `• **Target Storage**: ${safeStorage}\n`;
      output += `• **Delete Source**: ${deleteSource ? 'Yes' : 'No'}\n`;
      output += this.formatTaskLine(result);
      output += `**Valid volumes**: rootfs, mp0, mp1, mp2, etc.\n\n`;
      output += `**Note**: Volume move operation may take several minutes depending on volume size.\n`;
      output += `**Tip**: The container should be stopped for this operation.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to move LXC volume**\n\nError: ${error.message}\n\n**Common issues**:\n- Volume doesn't exist\n- Target storage doesn't exist\n- Insufficient space on target storage\n- Container is running (may need to be stopped)\n- Container is locked or in use`
        }],
        isError: true
      };
    }
  }

  async addNetworkVM(node, vmid, net, bridge, model = 'virtio', macaddr, vlan, firewall) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Network Management Requires Elevated Permissions**\n\nTo add VM network interfaces, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeNet = this.validateNetworkName(net);
      const safeBridge = this.validateBridgeName(bridge);

      const safeModel = model || 'virtio';
      if (!['virtio', 'e1000', 'rtl8139', 'vmxnet3'].includes(safeModel)) {
        throw new Error(`Invalid network model "${safeModel}". Valid models: virtio, e1000, rtl8139, vmxnet3`);
      }

      // Build network configuration string (validate each part to prevent
      // comma-injection into the config string)
      let netConfig = `${safeModel},bridge=${safeBridge}`;

      if (macaddr) {
        netConfig += `,macaddr=${this.validateMacAddr(macaddr)}`;
      }

      if (vlan !== undefined && vlan !== null) {
        netConfig += `,tag=${this.validateVlanTag(vlan)}`;
      }

      if (firewall) {
        netConfig += `,firewall=1`;
      }

      const body = {
        [safeNet]: netConfig
      };

      await this.proxmoxRequest(`/nodes/${safeNode}/qemu/${safeVMID}/config`, 'PUT', body);

      let output = `**VM Network Interface Added**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += `• **Interface**: ${safeNet}\n`;
      output += `• **Bridge**: ${safeBridge}\n`;
      output += `• **Model**: ${safeModel}\n`;
      if (macaddr) output += `• **MAC Address**: ${macaddr}\n`;
      if (vlan !== undefined && vlan !== null) output += `• **VLAN Tag**: ${vlan}\n`;
      if (firewall) output += `• **Firewall**: Enabled\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to add VM network interface**\n\nError: ${error.message}\n\n**Common issues**:\n- Network interface already exists\n- Bridge doesn't exist\n- Invalid MAC address format\n- Invalid VLAN tag (must be 1-4094)\n- VM is locked or in use`
        }],
        isError: true
      };
    }
  }

  async addNetworkLXC(node, vmid, net, bridge, ip, gw, firewall) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Network Management Requires Elevated Permissions**\n\nTo add LXC network interfaces, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeNet = this.validateNetworkName(net);
      const safeBridge = this.validateBridgeName(bridge);

      // Extract interface number (e.g., net0 -> 0, net1 -> 1)
      const netNum = safeNet.replace('net', '');

      // Build network configuration string (validate each part to prevent
      // comma-injection into the config string)
      let netConfig = `name=eth${netNum},bridge=${safeBridge}`;

      if (ip) {
        netConfig += `,ip=${this.validateIPConfig(ip)}`;
      }

      if (gw) {
        netConfig += `,gw=${this.validateGateway(gw)}`;
      }

      if (firewall) {
        netConfig += `,firewall=1`;
      }

      const body = {
        [safeNet]: netConfig
      };

      await this.proxmoxRequest(`/nodes/${safeNode}/lxc/${safeVMID}/config`, 'PUT', body);

      let output = `**LXC Network Interface Added**\n\n`;
      output += `• **Container ID**: ${safeVMID}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += `• **Interface**: ${safeNet} (eth${netNum})\n`;
      output += `• **Bridge**: ${safeBridge}\n`;
      if (ip) output += `• **IP Address**: ${ip}\n`;
      if (gw) output += `• **Gateway**: ${gw}\n`;
      if (firewall) output += `• **Firewall**: Enabled\n`;
      output += `\n**Valid interfaces**: net0, net1, net2, etc.\n`;
      output += `**Valid bridges**: vmbr0, vmbr1, vmbr2, etc.\n`;
      output += `**IP formats**: dhcp, 192.168.1.100/24, auto\n\n`;
      output += `**Tip**: Use DHCP for automatic IP assignment or specify static IP with CIDR notation.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to add LXC network interface**\n\nError: ${error.message}\n\n**Common issues**:\n- Network interface already exists\n- Bridge doesn't exist\n- Invalid IP address format\n- Invalid gateway address\n- Container is locked or in use`
        }],
        isError: true
      };
    }
  }

  async updateNetworkVM(node, vmid, net, bridge, model, macaddr, vlan, firewall) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Network Management Requires Elevated Permissions**\n\nTo update VM network interfaces, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeNet = this.validateNetworkName(net);

      // Get current VM configuration
      const config = await this.proxmoxRequest(`/nodes/${safeNode}/qemu/${safeVMID}/config`, 'GET');

      if (!config[safeNet]) {
        return {
          content: [{
            type: 'text',
            text: `**Network interface ${safeNet} does not exist**\n\nPlease add the interface first using proxmox_add_network_vm.\n\n**Existing interfaces**: ${Object.keys(config).filter(k => k.startsWith('net')).join(', ') || 'None'}`
          }],
          isError: true
        };
      }

      // Parse current configuration
      const currentConfig = config[safeNet];
      const configParts = {};
      currentConfig.split(',').forEach(part => {
        const [key, value] = part.split('=');
        configParts[key] = value;
      });

      // Update only provided parameters
      if (model !== undefined) {
        if (!['virtio', 'e1000', 'rtl8139', 'vmxnet3'].includes(model)) {
          throw new Error(`Invalid network model "${model}". Valid models: virtio, e1000, rtl8139, vmxnet3`);
        }
        // QEMU stores the MAC as the value of the model key (e.g. virtio=BC:24:...),
        // so read it from the old model entry and carry it into the new one.
        const models = ['virtio', 'e1000', 'rtl8139', 'vmxnet3'];
        const oldModel = models.find(m => m in configParts);
        const mac = configParts.macaddr || (oldModel ? configParts[oldModel] : '');
        models.forEach(m => delete configParts[m]);
        configParts[model] = mac || '';
      }

      if (bridge !== undefined) {
        const safeBridge = this.validateBridgeName(bridge);
        configParts.bridge = safeBridge;
      }

      if (macaddr !== undefined) {
        configParts.macaddr = this.validateMacAddr(macaddr);
      }

      if (vlan !== undefined && vlan !== null) {
        configParts.tag = this.validateVlanTag(vlan);
      } else if (vlan === null) {
        delete configParts.tag;
      }

      if (firewall !== undefined) {
        if (firewall) {
          configParts.firewall = '1';
        } else {
          delete configParts.firewall;
        }
      }

      // Rebuild configuration string
      const netConfig = Object.entries(configParts)
        .map(([key, value]) => value ? `${key}=${value}` : key)
        .join(',');

      const body = {
        [safeNet]: netConfig
      };

      await this.proxmoxRequest(`/nodes/${safeNode}/qemu/${safeVMID}/config`, 'PUT', body);

      let output = `**VM Network Interface Updated**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += `• **Interface**: ${safeNet}\n`;
      output += `• **New Configuration**: ${netConfig}\n\n`;
      output += `**Changes applied**:\n`;
      if (bridge !== undefined) output += `- Bridge: ${bridge}\n`;
      if (model !== undefined) output += `- Model: ${model}\n`;
      if (macaddr !== undefined) output += `- MAC Address: ${macaddr}\n`;
      if (vlan !== undefined) output += `- VLAN Tag: ${vlan !== null ? vlan : 'Removed'}\n`;
      if (firewall !== undefined) output += `- Firewall: ${firewall ? 'Enabled' : 'Disabled'}\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to update VM network interface**\n\nError: ${error.message}\n\n**Common issues**:\n- Network interface doesn't exist\n- Bridge doesn't exist\n- Invalid MAC address format\n- Invalid VLAN tag (must be 1-4094)\n- VM is locked or in use`
        }],
        isError: true
      };
    }
  }

  async updateNetworkLXC(node, vmid, net, bridge, ip, gw, firewall) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Network Management Requires Elevated Permissions**\n\nTo update LXC network interfaces, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeNet = this.validateNetworkName(net);
      const safeBridge = bridge !== undefined ? this.validateBridgeName(bridge) : undefined;

      // Get current container configuration
      const config = await this.proxmoxRequest(`/nodes/${safeNode}/lxc/${safeVMID}/config`, 'GET');

      if (!config[safeNet]) {
        return {
          content: [{
            type: 'text',
            text: `**Network interface ${safeNet} does not exist**\n\nPlease add the interface first using proxmox_add_network_lxc.\n\n**Existing interfaces**: ${Object.keys(config).filter(k => k.startsWith('net')).join(', ') || 'None'}`
          }],
          isError: true
        };
      }

      // Parse current configuration
      const currentConfig = config[safeNet];
      const configParts = {};
      currentConfig.split(',').forEach(part => {
        const [key, value] = part.split('=');
        configParts[key] = value;
      });

      // Update only provided parameters
      if (bridge !== undefined) {
        configParts.bridge = safeBridge;
      }

      if (ip !== undefined) {
        configParts.ip = this.validateIPConfig(ip);
      }

      if (gw !== undefined) {
        configParts.gw = this.validateGateway(gw);
      }

      if (firewall !== undefined) {
        if (firewall) {
          configParts.firewall = '1';
        } else {
          delete configParts.firewall;
        }
      }

      // Rebuild configuration string
      const netConfig = Object.entries(configParts)
        .map(([key, value]) => `${key}=${value}`)
        .join(',');

      const body = {
        [safeNet]: netConfig
      };

      await this.proxmoxRequest(`/nodes/${safeNode}/lxc/${safeVMID}/config`, 'PUT', body);

      let output = `**LXC Network Interface Updated**\n\n`;
      output += `• **Container ID**: ${safeVMID}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += `• **Interface**: ${safeNet}\n`;
      output += `• **New Configuration**: ${netConfig}\n\n`;
      output += `**Changes applied**:\n`;
      if (bridge !== undefined) output += `- Bridge: ${bridge}\n`;
      if (ip !== undefined) output += `- IP Address: ${ip}\n`;
      if (gw !== undefined) output += `- Gateway: ${gw}\n`;
      if (firewall !== undefined) output += `- Firewall: ${firewall ? 'Enabled' : 'Disabled'}\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to update LXC network interface**\n\nError: ${error.message}\n\n**Common issues**:\n- Network interface doesn't exist\n- Bridge doesn't exist\n- Invalid IP address format\n- Invalid gateway address\n- Container is locked or in use`
        }],
        isError: true
      };
    }
  }

  async removeNetworkVM(node, vmid, net) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Network Management Requires Elevated Permissions**\n\nTo remove VM network interfaces, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeNet = this.validateNetworkName(net);

      const body = {
        delete: safeNet
      };

      await this.proxmoxRequest(`/nodes/${safeNode}/qemu/${safeVMID}/config`, 'PUT', body);

      let output = `**VM Network Interface Removed**\n\n`;
      output += `• **VM ID**: ${safeVMID}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += `• **Interface Removed**: ${safeNet}\n\n`;
      output += `**Note**: The network interface has been removed from the VM configuration.\n`;
      output += `**Tip**: If the VM is running, you may need to restart it for changes to take effect.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to remove VM network interface**\n\nError: ${error.message}\n\n**Common issues**:\n- Network interface doesn't exist\n- VM is locked or in use\n- Invalid interface name`
        }],
        isError: true
      };
    }
  }

  async removeNetworkLXC(node, vmid, net) {
    if (!this.allowElevated) {
      return {
        content: [{
          type: 'text',
          text: `**Network Management Requires Elevated Permissions**\n\nTo remove LXC network interfaces, set \`PROXMOX_ALLOW_ELEVATED=true\` in your .env file.\n\n**Current permissions**: Basic (read-only)`
        }]
      };
    }

    try {
      // Validate inputs
      const safeNode = this.validateNodeName(node);
      const safeVMID = this.validateVMID(vmid);
      const safeNet = this.validateNetworkName(net);

      const body = {
        delete: safeNet
      };

      await this.proxmoxRequest(`/nodes/${safeNode}/lxc/${safeVMID}/config`, 'PUT', body);

      let output = `**LXC Network Interface Removed**\n\n`;
      output += `• **Container ID**: ${safeVMID}\n`;
      output += `• **Node**: ${safeNode}\n`;
      output += `• **Interface Removed**: ${safeNet}\n\n`;
      output += `**Note**: The network interface has been removed from the container configuration.\n`;
      output += `**Tip**: If the container is running, you may need to restart it for changes to take effect.\n`;

      return {
        content: [{ type: 'text', text: output }]
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `**Failed to remove LXC network interface**\n\nError: ${error.message}\n\n**Common issues**:\n- Network interface doesn't exist\n- Container is locked or in use\n- Invalid interface name`
        }],
        isError: true
      };
    }
  }

  // Render a task line only when the API actually returned a UPID.
  // Synchronous config calls return null and get no task line.
  formatTaskLine(result) {
    if (typeof result === 'string' && result.startsWith('UPID:')) {
      return `• **Task UPID**: ${result}\n\nCheck completion with \`proxmox_get_task_status\`.\n`;
    }
    return '';
  }

  formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (days > 0) {
      return `${days}d ${hours}h ${minutes}m`;
    } else if (hours > 0) {
      return `${hours}h ${minutes}m`;
    } else {
      return `${minutes}m`;
    }
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Proxmox MCP server running on stdio');
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const server = new ProxmoxServer();
  server.run().catch(console.error);
}
