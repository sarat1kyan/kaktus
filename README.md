# Linux System Hardening Tool

An enterprise-grade automated security hardening tool for Red Hat and Debian-based Linux distributions. This tool implements security best practices from CIS Benchmarks, DISA STIG, NIST guidelines, and OWASP recommendations.

## Features

### Core Capabilities

- **Multi-Distribution Support**: RHEL 7/8/9, CentOS, Debian 10/11/12, Ubuntu LTS
- **Comprehensive Security Modules**:
  - User and group security hardening
  - SSH server hardening
  - Kernel parameter tuning (sysctl)
  - File permissions and ownership fixes
  - Firewall configuration (iptables/nftables/firewalld/ufw)
  - Service and package management
  - Audit logging (auditd) configuration
  - SELinux/AppArmor hardening
  - Automatic security updates configuration

### Safety Features

- **Dry-Run Mode**: Preview all changes before applying
- **Impact Analysis**: Detailed assessment of changes before execution
- **Backup & Rollback**: Automatic backups with easy rollback capability
- **Service Detection**: Automatically detects running services to avoid disruption
- **Network Safety**: Maintains SSH access to prevent lockouts

### Enterprise Features

- **Modular Architecture**: Enable/disable specific hardening modules
- **Configuration Profiles**: JSON/YAML support for reusable policies
- **Comprehensive Reporting**: Detailed audit and action reports
- **Logging**: Full activity logging for compliance
- **Non-Interactive Mode**: Suitable for automation

## Installation

### Prerequisites

- Python 3.6 or higher
- Root/sudo access
- Supported Linux distribution

### Quick Install

Go for QuickInstallGuide.md

### Quick Run

```bash
# Clone or download the tool
git clone https://github.com/sarat1kyan/kaktus.git
chmod +x kaktus.py

# Quick Run dependencies (if any)
pip3 install pyyaml  # Only if using YAML configs
```

## Usage

### Basic Commands

```bash
# Perform security audit only
sudo ./kaktus.py --audit-only

# Run in dry-run mode (recommended first run)
sudo ./kaktus.py --dry-run

# Apply hardening interactively
sudo ./kaktus.py

# Apply hardening non-interactively
sudo ./kaktus.py --non-interactive

# Generate audit report
sudo ./kaktus.py --audit-only --report audit_report.json
```

### Advanced Usage

```bash
# Use custom configuration
sudo ./kaktus.py --config custom_hardening.yaml

# Run specific modules only
sudo ./kaktus.py --modules ssh,firewall,kernel

# List available backups
sudo ./kaktus.py --list-backups

# Rollback to previous state
sudo ./kaktus.py --rollback 20240115_143022_pre_hardening
```

## Configuration

### Configuration File Format

Create a YAML or JSON configuration file to customize the tool's behavior:

**YAML Example (hardening_config.yaml):**
```yaml
modules:
  user_security:
    enabled: true
  ssh:
    enabled: true
    config:
      permit_root_login: false
      password_authentication: false
  kernel:
    enabled: true
  file_permissions:
    enabled: true
  firewall:
    enabled: true
    config:
      default_policy: drop
      allowed_ports:
        - 22
        - 443
  services:
    enabled: true
  auditd:
    enabled: true
  selinux:
    enabled: true

options:
  create_backup: true
  interactive: false
  report_format: json
```

**JSON Example (hardening_config.json):**
```json
{
  "modules": {
    "user_security": {"enabled": true},
    "ssh": {
      "enabled": true,
      "config": {
        "permit_root_login": false,
        "password_authentication": false
      }
    },
    "kernel": {"enabled": true},
    "file_permissions": {"enabled": true},
    "firewall": {"enabled": true},
    "services": {"enabled": true},
    "auditd": {"enabled": true},
    "selinux": {"enabled": true}
  },
  "options": {
    "create_backup": true,
    "interactive": false,
    "report_format": "json"
  }
}
```

## Security Modules

### 1. User Security Module
- Checks for empty passwords
- Identifies non-root users with UID 0
- Configures password aging policies
- Sets secure umask values
- Disables unnecessary system accounts

### 2. SSH Hardening Module
- Disables root login
- Enforces key-based authentication
- Configures secure ciphers and algorithms
- Sets connection timeouts
- Limits authentication attempts

### 3. Kernel Hardening Module
- Disables IP forwarding
- Prevents ICMP redirects
- Enables TCP SYN cookies
- Configures ASLR (Address Space Layout Randomization)
- Sets secure sysctl parameters

### 4. File Permissions Module
- Fixes permissions on critical system files
- Removes world-writable permissions
- Identifies and fixes unowned files
- Secures configuration files

### 5. Firewall Module
- Automatically detects firewall type
- Configures restrictive default policies
- Maintains SSH access
- Supports firewalld, ufw, and iptables

### 6. Service Hardening Module
- Disables unnecessary services
- Removes development tools on production systems
- Configures automatic security updates
- Manages service dependencies

### 7. Audit Module
- Installs and configures auditd
- Sets comprehensive audit rules
- Monitors authentication changes
- Tracks administrative actions
- Configures log rotation

### 8. MAC Module (SELinux/AppArmor)
- Enables mandatory access controls
- Sets enforcing mode
- Configures security contexts
- Manages security policies

## Impact Analysis

Before applying changes, the tool provides detailed impact analysis:

```
============================================================
IMPACT ANALYSIS
============================================================
Total changes to be made: 47
Files to be modified: 23
Requires reboot: Yes

HIGH IMPACT CHANGES:
  - Set SELinux to enforcing mode
    Impact: SELinux will enforce security policies (requires reboot if disabled)

MEDIUM IMPACT CHANGES:
  - Applied SSH hardening configuration
  - Configured firewalld with restrictive rules

SERVICES AFFECTED:
  - Disabled service: telnet
  - Disabled service: rsh
```

## Backup and Rollback

The tool automatically creates backups before making changes:

```bash
# List all backups
sudo ./kaktus.py --list-backups

# Output:
Available backups:
  20240115_143022_pre_hardening - pre_hardening (20240115_143022)
  20240115_145533_ssh_hardening - ssh_hardening (20240115_145533)

# Rollback to specific backup
sudo ./kaktus.py --rollback 20240115_143022_pre_hardening
```

## Reports

The tool generates comprehensive JSON reports containing:

- System information
- Audit results with severity levels
- Actions taken during hardening
- Statistics and summary
- Timestamp and metadata

Example report structure:
```json
{
  "metadata": {
    "tool_version": "1.0.0",
    "timestamp": "2024-01-15T14:30:22",
    "hostname": "prod-server-01",
    "distro": {
      "type": "ubuntu",
      "name": "Ubuntu",
      "version": "22.04",
      "codename": "jammy"
    }
  },
  "audit_summary": {
    "total_checks": 89,
    "passed": 67,
    "failed": 18,
    "warnings": 4
  },
  "audit_results": [...],
  "actions_taken": [...],
  "statistics": {
    "critical_issues": 2,
    "high_issues": 7,
    "medium_issues": 9,
    "low_issues": 0
  }
}
```

## Best Practices

1. **Always run audit first**: Use `--audit-only` to understand current security posture
2. **Test with dry-run**: Use `--dry-run` before applying changes
3. **Review impact analysis**: Carefully review the impact analysis before proceeding
4. **Maintain SSH access**: Ensure you have console access or out-of-band management
5. **Test in non-production**: Always test on non-production systems first
6. **Keep backups**: The tool creates backups, but maintain system-level backups too
7. **Document changes**: Keep the generated reports for compliance and documentation

## Troubleshooting

### Common Issues

1. **SSH Lockout Prevention**
   - The tool maintains current SSH session
   - Always test SSH configuration changes with a secondary connection
   - Keep console access available

2. **SELinux Issues**
   - Some changes require relabeling (touch /.autorelabel && reboot)
   - Check audit logs: `ausearch -m avc -ts recent`

3. **Service Disruptions**
   - Review services before disabling
   - Check service dependencies
   - Monitor logs after hardening

### Debug Mode

Enable verbose logging:
```bash
export LOG_LEVEL=DEBUG
sudo ./kaktus.py --dry-run
```

## Compliance Mapping

The tool implements controls from:

- **CIS Benchmarks**: Level 1 and Level 2 controls
- **DISA STIG**: CAT I, II, and III findings
- **NIST 800-53**: Security controls for federal systems
- **NIST 800-171**: Protecting CUI in non-federal systems
- **OWASP**: Server hardening guidelines

## Directory Structure

```
/var/log/kaktus/      # Logs
/var/backups/kaktus/  # Backup files
/etc/kaktus/          # Configuration
/etc/kaktus/profiles/ # Security profiles
```

## Security Considerations

- The tool requires root access - protect it accordingly
- Backup files may contain sensitive information
- Logs contain details of system configuration
- Configuration files should be protected (chmod 600)

## Contributing

When contributing to this tool:

1. Test on multiple distributions
2. Ensure backward compatibility
3. Document new features
4. Follow existing code style
5. Add appropriate error handling

## License

[Specify your license here]

## Support

For issues, questions, or contributions:
- GitHub: [your-repo-url]
- Email: [your-email]
- Documentation: [docs-url]

## Changelog

### Version 2.1.0 Stable
- Initial release
- Support for RHEL/CentOS/Debian/Ubuntu
- Eight security modules
- Backup and rollback functionality
- Comprehensive reporting
- Dry-run and impact analysis