# Linux Hardening Tool - Quick Start Guide

## 🚀 5-Minute Quick Start

### 1. Installation

```bash
# Download the tool
git clone https://github.com/sarat1kyan/kaktus.git
cd kaktus

# Run installer (requires root)
sudo ./install.sh
```

### 2. First Audit (Recommended)

Always start with an audit to understand your system's current security posture:

```bash
sudo kaktus --audit-only
```

### 3. Test Run

Use dry-run mode to see what changes would be made:

```bash
sudo kaktus --dry-run
```

### 4. Apply Hardening

When ready, apply the hardening configurations:

```bash
sudo kaktus
```

## 📋 Pre-flight Checklist

Before running the hardening tool:

- [ ] **Backup your system** - Always have a full system backup
- [ ] **Console access** - Ensure you have out-of-band access (not just SSH)
- [ ] **Test environment** - Test on non-production systems first
- [ ] **Review services** - Know which services your system needs
- [ ] **Document current state** - Save current configurations

## 🛡️ Common Use Cases

### Production Web Server

Focus on network security and service hardening:

```bash
sudo kaktus --modules ssh,firewall,kernel,services
```

### Database Server

Exclude firewall module if using specific database ports:

```bash
sudo kaktus --modules user_security,ssh,kernel,file_permissions,auditd
```

### Development Environment

Use a relaxed configuration:

```bash
sudo kaktus --config /etc/kaktus/profiles/development.yaml
```

### Compliance Audit

Generate a detailed report without making changes:

```bash
sudo kaktus --audit-only --report compliance_audit.json
```

## ⚡ Quick Commands

### Check what would change
```bash
sudo kaktus --dry-run | grep "Would"
```

### Apply specific modules only
```bash
sudo kaktus --modules ssh,firewall
```

### Non-interactive mode (for automation)
```bash
sudo kaktus --non-interactive --config production.yaml
```

### List and manage backups
```bash
# List all backups
sudo kaktus --list-backups

# Rollback to specific backup
sudo kaktus --rollback 20240115_143022_pre_hardening
```

## 🔍 Understanding Output

### Audit Results

The tool uses color-coded severity levels:

- 🔴 **CRITICAL** - Immediate action required (e.g., empty passwords)
- 🟠 **HIGH** - Important security issues (e.g., disabled firewall)
- 🟡 **MEDIUM** - Should be addressed (e.g., weak permissions)
- 🔵 **LOW** - Minor issues (e.g., unnecessary packages)
- ⚪ **INFO** - Informational only

### Impact Analysis

Before applying changes, review the impact:

```
HIGH IMPACT CHANGES:
  - Set SELinux to enforcing mode