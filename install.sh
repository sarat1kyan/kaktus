#!/bin/bash
# Linux Hardening Tool - Installation Script
# This script sets up the Linux Hardening Tool on your system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/linux-hardening-tool"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/linux-hardening-tool"
LOG_DIR="/var/log/linux-hardening-tool"
BACKUP_DIR="/var/backups/linux-hardening-tool"
TOOL_NAME="linux-hardening-tool"
SCRIPT_NAME="linux-hardening-tool.py"

# Functions
print_status() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This installation script must be run as root"
        exit 1
    fi
}

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        print_error "Cannot detect Linux distribution"
        exit 1
    fi
    
    print_status "Detected: $OS $VER"
}

check_python() {
    print_status "Checking Python version..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
        
        if [[ $PYTHON_MAJOR -ge 3 ]] && [[ $PYTHON_MINOR -ge 6 ]]; then
            print_status "Python $PYTHON_VERSION found"
        else
            print_error "Python 3.6+ required, found $PYTHON_VERSION"
            exit 1
        fi
    else
        print_error "Python 3 not found"
        exit 1
    fi
}

install_dependencies() {
    print_status "Installing dependencies..."
    
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y python3-pip python3-yaml
            ;;
        rhel|centos|fedora|rocky|almalinux)
            yum install -y python3-pip python3-pyyaml || dnf install -y python3-pip python3-pyyaml
            ;;
        *)
            print_warning "Unknown distribution, skipping dependency installation"
            ;;
    esac
    
    # Install Python dependencies
    pip3 install --quiet pyyaml || print_warning "Failed to install PyYAML"
}

create_directories() {
    print_status "Creating directories..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR/profiles"
    mkdir -p "$LOG_DIR"
    mkdir -p "$BACKUP_DIR"
    
    # Set permissions
    chmod 755 "$INSTALL_DIR"
    chmod 755 "$CONFIG_DIR"
    chmod 700 "$LOG_DIR"
    chmod 700 "$BACKUP_DIR"
}

install_tool() {
    print_status "Installing Linux Hardening Tool..."
    
    # Copy main script
    if [ -f "$SCRIPT_NAME" ]; then
        cp "$SCRIPT_NAME" "$INSTALL_DIR/"
        chmod 755 "$INSTALL_DIR/$SCRIPT_NAME"
    else
        print_error "Script $SCRIPT_NAME not found in current directory"
        exit 1
    fi
    
    # Create symlink
    ln -sf "$INSTALL_DIR/$SCRIPT_NAME" "$BIN_DIR/$TOOL_NAME"
    
    # Copy configuration files if they exist
    if [ -f "enterprise_hardening.yaml" ]; then
        cp enterprise_hardening.yaml "$CONFIG_DIR/profiles/"
        print_status "Copied enterprise configuration profile"
    fi
    
    # Create default config
    cat > "$CONFIG_DIR/default.yaml" << 'EOF'
# Default Linux Hardening Tool Configuration
modules:
  user_security:
    enabled: true
  ssh:
    enabled: true
  kernel:
    enabled: true
  file_permissions:
    enabled: true
  firewall:
    enabled: true
  services:
    enabled: true
  auditd:
    enabled: true
  selinux:
    enabled: true

options:
  create_backup: true
  interactive: true
  report_format: json
EOF
    
    chmod 644 "$CONFIG_DIR/default.yaml"
}

create_systemd_timer() {
    print_status "Creating systemd timer for scheduled audits..."
    
    # Create service file
    cat > /etc/systemd/system/linux-hardening-audit.service << EOF
[Unit]
Description=Linux Hardening Tool Security Audit
After=network.target

[Service]
Type=oneshot
ExecStart=$BIN_DIR/$TOOL_NAME --audit-only --report $LOG_DIR/audit-\$(date +\%Y\%m\%d-\%H\%M\%S).json
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Create timer file
    cat > /etc/systemd/system/linux-hardening-audit.timer << EOF
[Unit]
Description=Weekly Linux Hardening Tool Security Audit
Requires=linux-hardening-audit.service

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
EOF

    # Reload systemd
    systemctl daemon-reload
    
    print_status "Created systemd timer (disabled by default)"
    print_status "To enable weekly audits: systemctl enable --now linux-hardening-audit.timer"
}

create_completion() {
    print_status "Creating bash completion..."
    
    cat > /etc/bash_completion.d/linux-hardening-tool << 'EOF'
# Bash completion for linux-hardening-tool
_linux_hardening_tool() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    opts="--help --version --config --dry-run --audit-only --non-interactive --report --rollback --list-backups --modules"
    
    case "${prev}" in
        --config)
            COMPREPLY=( $(compgen -f -- ${cur}) )
            return 0
            ;;
        --report)
            COMPREPLY=( $(compgen -f -- ${cur}) )
            return 0
            ;;
        --rollback)
            # List available backups
            if [ -d /var/backups/linux-hardening-tool ]; then
                COMPREPLY=( $(compgen -W "$(ls /var/backups/linux-hardening-tool)" -- ${cur}) )
            fi
            return 0
            ;;
        --modules)
            COMPREPLY=( $(compgen -W "user_security ssh kernel file_permissions firewall services auditd selinux" -- ${cur}) )
            return 0
            ;;
        *)
            ;;
    esac
    
    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
}

complete -F _linux_hardening_tool linux-hardening-tool
EOF
}

verify_installation() {
    print_status "Verifying installation..."
    
    # Check if tool is accessible
    if command -v $TOOL_NAME &> /dev/null; then
        print_status "Tool installed successfully"
        
        # Show version
        $TOOL_NAME --version
    else
        print_error "Installation verification failed"
        exit 1
    fi
    
    # Check directories
    for dir in "$CONFIG_DIR" "$LOG_DIR" "$BACKUP_DIR"; do
        if [ -d "$dir" ]; then
            print_status "Directory exists: $dir"
        else
            print_error "Directory missing: $dir"
        fi
    done
}

print_summary() {
    echo
    echo "=========================================="
    echo "Linux Hardening Tool Installation Complete"
    echo "=========================================="
    echo
    echo "Installation locations:"
    echo "  - Tool: $INSTALL_DIR/$SCRIPT_NAME"
    echo "  - Binary: $BIN_DIR/$TOOL_NAME"
    echo "  - Config: $CONFIG_DIR"
    echo "  - Logs: $LOG_DIR"
    echo "  - Backups: $BACKUP_DIR"
    echo
    echo "Quick start:"
    echo "  - Run audit: sudo $TOOL_NAME --audit-only"
    echo "  - Dry run: sudo $TOOL_NAME --dry-run"
    echo "  - Apply hardening: sudo $TOOL_NAME"
    echo
    echo "Configuration:"
    echo "  - Default: $CONFIG_DIR/default.yaml"
    echo "  - Profiles: $CONFIG_DIR/profiles/"
    echo
    echo "For weekly audits, enable the systemd timer:"
    echo "  sudo systemctl enable --now linux-hardening-audit.timer"
    echo
}

main() {
    echo "Linux Hardening Tool Installer v1.0"
    echo "===================================="
    echo
    
    # Checks
    check_root
    detect_distro
    check_python
    
    # Installation
    install_dependencies
    create_directories
    install_tool
    create_systemd_timer
    create_completion
    
    # Verification
    verify_installation
    
    # Summary
    print_summary
}

# Handle uninstall
uninstall() {
    print_status "Uninstalling Linux Hardening Tool..."
    
    # Stop and disable timer if exists
    systemctl stop linux-hardening-audit.timer 2>/dev/null || true
    systemctl disable linux-hardening-audit.timer 2>/dev/null || true
    
    # Remove files and directories
    rm -f "$BIN_DIR/$TOOL_NAME"
    rm -rf "$INSTALL_DIR"
    rm -f /etc/systemd/system/linux-hardening-audit.service
    rm -f /etc/systemd/system/linux-hardening-audit.timer
    rm -f /etc/bash_completion.d/linux-hardening-tool
    
    # Ask about config and data
    read -p "Remove configuration files? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
    fi
    
    read -p "Remove log files? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$LOG_DIR"
    fi
    
    read -p "Remove backup files? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$BACKUP_DIR"
    fi
    
    systemctl daemon-reload
    
    print_status "Uninstallation complete"
}

# Parse arguments
case "${1:-}" in
    uninstall|--uninstall|-u)
        uninstall
        ;;
    *)
        main
        ;;
esac