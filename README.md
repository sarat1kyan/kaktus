---

# 🛡️ Kaktus: Linux System Hardening Tool

An **enterprise-grade automated security hardening tool** for Red Hat- and Debian-based Linux distributions. Kaktus integrates best practices from **CIS Benchmarks**, **DISA STIG**, **NIST 800-53/171**, and **OWASP**, offering powerful, auditable, and safe system security.

---

## 💨 Quick Start Guide

### 🚀 5-Minute Quick Start

1. **Installation**  
   ```bash
   # Download the tool
   git clone https://github.com/sarat1kyan/kaktus.git
   cd kaktus

   # Run installer (requires root)
   sudo ./install.sh
   ```

2. **First Audit** *(Recommended)*  
   Always start with an audit to understand your system’s current security posture:  
   ```bash
   sudo kaktus --audit-only
   ```

3. **Test Run**  
   Use dry-run mode to preview changes without applying them:  
   ```bash
   sudo kaktus --dry-run
   ```

4. **Apply Hardening**  
   When ready, apply the hardening configurations:  
   ```bash
   sudo kaktus
   ```

### 📋 Pre-flight Checklist

- Backup your system — always have a full system backup  
- Console access — ensure out-of-band access (not just SSH)  
- Test environment — validate on non-production systems first  
- Review services — know which daemons your system needs  
- Document current state — save existing configurations  

### 🛡️ Common Use Cases

**Production Web Server**  
```bash
sudo kaktus --modules ssh,firewall,kernel,services
```

**Database Server**  
(*Exclude firewall if using custom DB ports*)  
```bash
sudo kaktus --modules user_security,ssh,kernel,file_permissions,auditd
```

**Development Environment**  
```bash
sudo kaktus --config /etc/kaktus/profiles/development.yaml
```

**Compliance Audit**  
Generate a detailed report without making changes:  
```bash
sudo kaktus --audit-only --report compliance_audit.json
```

### ⚡ Quick Commands

```bash
# Preview what would change
sudo kaktus --dry-run | grep "Would"

# Harden only SSH & firewall
sudo kaktus --modules ssh,firewall

# Non-interactive mode for automation
sudo kaktus --non-interactive --config production.yaml

# List backups
sudo kaktus --list-backups

# Roll back
sudo kaktus --rollback 20240115_143022_pre_hardening
```

### 🔍 Understanding Output

**Audit Results** use color-coded severity:  
🔴 CRITICAL | 🟠 HIGH | 🟡 MEDIUM | 🔵 LOW | ⚪ INFO  

**Impact Analysis** highlights high-impact changes, e.g.:  
```
HIGH IMPACT CHANGES:
  - Set SELinux to enforcing mode (requires reboot)
```

---

## 🚀 Features

### ✅ Core Capabilities
- **Multi-Distro Support**: RHEL 7/8/9, CentOS, Debian 10/11/12, Ubuntu LTS  
- **Security Modules**: user/group, SSH, sysctl, file perms, firewall, services, auditd, SELinux/AppArmor, updates  

### 🛑 Safety-First Design
- Dry-Run Mode  
- Impact Analysis  
- Backup & Rollback  
- Service-Aware  
- Network Safety  

### 🏢 Enterprise-Ready
- Modular Architecture  
- JSON/YAML Config Profiles  
- Audit Reporting  
- Full Logging  
- Automation-Friendly  

---

## 📦 Installation

### Prerequisites
- Python 3.6+  
- Root/sudo access  
- Supported Linux distro  

### Quick Install
```bash
git clone https://github.com/sarat1kyan/kaktus.git
chmod +x kaktus.py
pip3 install pyyaml  # for YAML configs
```

---

## ⚙️ Usage

### 🧪 Basic Commands
```bash
sudo ./kaktus.py --audit-only
sudo ./kaktus.py --dry-run
sudo ./kaktus.py             # interactive
sudo ./kaktus.py --non-interactive
sudo ./kaktus.py --audit-only --report audit_report.json
```

### 🧩 Advanced Usage
```bash
sudo ./kaktus.py --config hardening.yaml
sudo ./kaktus.py --modules ssh,firewall,kernel
sudo ./kaktus.py --list-backups
sudo ./kaktus.py --rollback 20240115_143022_pre_hardening
```

---

## 🛠️ Configuration

### YAML Example
```yaml
modules:
  ssh:
    enabled: true
    config:
      permit_root_login: false
      password_authentication: false
options:
  create_backup: true
  interactive: false
  report_format: json
```

### JSON Example
```json
{
  "modules": {
    "ssh": { "enabled": true, "config": { "permit_root_login": false } }
  },
  "options": { "create_backup": true, "interactive": false }
}
```

---

## 🔒 Security Modules Overview

| Module         | Highlights                                                          |
| -------------- | ------------------------------------------------------------------- |
| User Security  | UID 0 checks, umask, password aging, disable system accounts        |
| SSH Hardening  | Disable root login, key auth, strong ciphers, timeouts             |
| Kernel (sysctl)| Harden TCP/IP, ASLR, ICMP redirect protection                       |
| File Perms     | Fix critical file perms, remove world-writable                      |
| Firewall       | Auto-detect & configure iptables/nftables/firewalld/ufw             |
| Services       | Disable unneeded services, prune dev tools                          |
| Auditd         | Install + configure comprehensive audit rules                       |
| SELinux/AppArmor| Enforce MAC, manage policies                                       |

---

## 📊 Impact Analysis

```text
============================================================
IMPACT ANALYSIS
============================================================
Total changes: 47
Modified files: 23
Reboot required: Yes

HIGH IMPACT:
  - SELinux set to enforcing mode

MEDIUM IMPACT:
  - SSH hardened
  - firewalld rules applied

Services impacted:
  - telnet (disabled)
  - rsh (disabled)
```

---

## 🧬 Backup & Rollback

```bash
sudo ./kaktus.py --list-backups
sudo ./kaktus.py --rollback <backup_id>
```
Backups live in `/var/backups/kaktus/`.

---

## 📑 Reports

Generates JSON with metadata, audit summary, actions, and stats:
```json
{
  "metadata": { "tool_version": "1.0.0", ... },
  "audit_summary": { "passed": 67, "failed": 18 },
  "actions_taken": [...],
  "statistics": { "critical_issues": 2, ... }
}
```

---

## 🧠 Best Practices

- Start with `--audit-only`  
- Always run `--dry-run`  
- Review impact analysis  
- Test in non-production  
- Maintain backups & docs  

---

## 🧯 Troubleshooting

- **SSH Lockouts**: SSH preserved; test with second session  
- **SELinux Warnings**: `touch /.autorelabel && reboot`; check `ausearch`  
- **Service Issues**: Review deps; monitor logs  
- **Debug Mode**:  
  ```bash
  export LOG_LEVEL=DEBUG
  sudo ./kaktus.py --dry-run
  ```

---

## ✅ Compliance Mapping

- CIS Benchmarks (Lvl 1 & 2)  
- DISA STIG (CAT I–III)  
- NIST 800-53/171  
- OWASP server guidelines  

---

## 📁 Directory Structure

```
/var/log/kaktus/       – Logs  
/var/backups/kaktus/   – Backups  
/etc/kaktus/           – Config  
/etc/kaktus/profiles/  – Profiles  
```

---

## 🔐 Security Considerations

- Requires root — protect accordingly  
- Backups/configs may include sensitive data  
- Logs detail system state  

---

## 🤝 Contributing

- Test on all supported distros  
- Maintain backward compatibility  
- Follow existing style & add tests  
- Document every change  

---

## 📜 License

MIT - License

---

## 📌 Changelog

**v2.1.0 – Stable**  
- Initial release  
- Support for RHEL/CentOS/Debian/Ubuntu  
- Eight security modules  
- Backup & rollback  
- Full audit reporting  
- Dry-run & impact analysis  

---
