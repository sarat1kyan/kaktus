#!/bin/bash

# Enhanced Linux System Hardening Tool v2.0 - Installation Script
# =================================================================
# 
# This script installs the Enhanced Linux Hardening Tool and its dependencies
# Supports: RHEL, CentOS, Fedora, Debian, Ubuntu, SUSE, Arch Linux
#
# Usage: 
#   curl -sSL https://raw.githubusercontent.com/yourusername/enhanced-linux-hardening-tool/main/install.sh | sudo bash
#   or
#   chmod +x install.sh && sudo ./install.sh
#
# Author: Security Team
# License: GPL v3.0

set -euo pipefail  # Exit on error, undefined variables, pipe failures

# =============================================================================
# CONFIGURATION AND CONSTANTS
# =============================================================================

readonly TOOL_NAME="Enhanced Linux Hardening Tool"
readonly TOOL_VERSION="2.0.0"
readonly TOOL_REPO="https://github.com/yourusername/enhanced-linux-hardening-tool"
readonly INSTALL_DIR="/opt/linux-hardening-tool"
readonly BIN_DIR="/usr/local/bin"
readonly CONFIG_DIR="/etc/linux-hardening-tool"
readonly LOG_DIR="/var/log/linux-hardening-tool"
readonly SERVICE_DIR="/etc/systemd/system"
readonly PYTHON_MIN_VERSION="3.8"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# Installation options (can be overridden by environment variables)
INSTALL_TYPE="${INSTALL_TYPE:-full}"           # full, minimal, dev
PYTHON_CMD="${PYTHON_CMD:-}"                   # Auto-detect if empty
SKIP_DEPS="${SKIP_DEPS:-false}"               # Skip system dependencies
ENABLE_SERVICE="${ENABLE_SERVICE:-true}"       # Enable systemd service
CREATE_SYMLINK="${CREATE_SYMLINK:-true}"      # Create /usr/local/bin symlink
INSTALL_PROFILES="${INSTALL_PROFILES:-true}"  # Install default profiles

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

print_header() {
    echo -e "${PURPLE}"
    echo "=============================================================================="
    echo "$1"
    echo "=============================================================================="
    echo -e "${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        echo "Usage: sudo $0"
        exit 1
    fi
}

# Detect Linux distribution
detect_distribution() {
    local distro=""
    local version=""
    
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        distro="${ID,,}"  # Convert to lowercase
        version="${VERSION_ID:-unknown}"
    elif [[ -f /etc/redhat-release ]]; then
        if grep -q "CentOS" /etc/redhat-release; then
            distro="centos"
        elif grep -q "Red Hat" /etc/redhat-release; then
            distro="rhel"
        elif grep -q "Fedora" /etc/redhat-release; then
            distro="fedora"
        fi
        version=$(grep -oE '[0-9]+' /etc/redhat-release | head -1)
    elif [[ -f /etc/debian_version ]]; then
        distro="debian"
        version=$(cat /etc/debian_version)
    else
        print_error "Unsupported or undetected Linux distribution"
        exit 1
    fi
    
    echo "${distro}:${version}"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Compare version numbers
version_greater_equal() {
    printf '%s\n' "$1" "$2" | sort -V | head -n1 | grep -q "^$2$"
}

# Get Python command
get_python_command() {
    local python_cmd=""
    local python_version=""
    
    # Try different Python commands
    for cmd in python3.11 python3.10 python3.9 python3.8 python3 python; do
        if command_exists "$cmd"; then
            python_version=$($cmd -c "import sys; print('.'.join(map(str, sys.version_info[:2])))" 2>/dev/null || echo "0.0")
            if version_greater_equal "$python_version" "$PYTHON_MIN_VERSION"; then
                python_cmd="$cmd"
                break
            fi
        fi
    done
    
    if [[ -z "$python_cmd" ]]; then
        print_error "Python ${PYTHON_MIN_VERSION}+ not found"
        print_status "Please install Python ${PYTHON_MIN_VERSION} or later"
        exit 1
    fi
    
    echo "$python_cmd"
}

# Install system dependencies based on distribution
install_system_dependencies() {
    local distro_info
    distro_info=$(detect_distribution)
    local distro="${distro_info%:*}"
    local version="${distro_info#*:}"
    
    print_status "Installing system dependencies for $distro $version..."
    
    case "$distro" in
        "ubuntu"|"debian")
            apt-get update
            apt-get install -y \
                python3 \
                python3-pip \
                python3-dev \
                python3-venv \
                build-essential \
                libssl-dev \
                libffi-dev \
                libsqlite3-dev \
                curl \
                wget \
                git \
                rsyslog \
                systemd \
                sudo \
                openssh-server \
                iptables \
                net-tools \
                procps \
                psmisc \
                lsof \
                strace \
                tcpdump \
                nmap \
                aide \
                rkhunter \
                chkrootkit \
                auditd \
                fail2ban
            ;;
        "rhel"|"centos"|"fedora"|"rocky"|"almalinux")
            local pkg_manager=""
            if command_exists dnf; then
                pkg_manager="dnf"
            elif command_exists yum; then
                pkg_manager="yum"
            else
                print_error "No package manager found (dnf/yum)"
                exit 1
            fi
            
            $pkg_manager update -y
            $pkg_manager install -y \
                python3 \
                python3-pip \
                python3-devel \
                gcc \
                gcc-c++ \
                make \
                openssl-devel \
                libffi-devel \
                sqlite-devel \
                curl \
                wget \
                git \
                rsyslog \
                systemd \
                sudo \
                openssh-server \
                iptables \
                net-tools \
                procps-ng \
                psmisc \
                lsof \
                strace \
                tcpdump \
                nmap \
                aide \
                rkhunter \
                audit \
                fail2ban \
                epel-release
            ;;
        "suse"|"opensuse"|"opensuse-leap"|"opensuse-tumbleweed")
            zypper refresh
            zypper install -y \
                python3 \
                python3-pip \
                python3-devel \
                gcc \
                gcc-c++ \
                make \
                libopenssl-devel \
                libffi-devel \
                sqlite3-devel \
                curl \
                wget \
                git \
                rsyslog \
                systemd \
                sudo \
                openssh \
                iptables \
                net-tools \
                procps \
                psmisc \
                lsof \
                strace \
                tcpdump \
                nmap \
                aide \
                audit \
                fail2ban
            ;;
        "arch"|"manjaro")
            pacman -Sy --noconfirm \
                python \
                python-pip \
                base-devel \
                openssl \
                libffi \
                sqlite \
                curl \
                wget \
                git \
                rsyslog \
                systemd \
                sudo \
                openssh \
                iptables \
                net-tools \
                procps-ng \
                psmisc \
                lsof \
                strace \
                tcpdump \
                nmap \
                aide \
                audit \
                fail2ban
            ;;
        "alpine")
            apk update
            apk add \
                python3 \
                py3-pip \
                python3-dev \
                build-base \
                openssl-dev \
                libffi-dev \
                sqlite-dev \
                curl \
                wget \
                git \
                rsyslog \
                openrc \
                sudo \
                openssh \
                iptables \
                net-tools \
                procps \
                psmisc \
                lsof \
                strace \
                tcpdump \
                nmap \
                aide \
                audit
            ;;
        *)
            print_warning "Unsupported distribution: $distro"
            print_status "Attempting to continue with Python dependencies only..."
            ;;
    esac
    
    print_success "System dependencies installed successfully"
}

# Install Python dependencies
install_python_dependencies() {
    local python_cmd="$1"
    local pip_cmd="${python_cmd} -m pip"
    
    print_status "Installing Python dependencies..."
    
    # Upgrade pip first
    $pip_cmd install --upgrade pip setuptools wheel
    
    # Install based on installation type
    case "$INSTALL_TYPE" in
        "minimal")
            print_status "Installing minimal dependencies..."
            $pip_cmd install psutil netifaces aiofiles PyYAML requests cryptography
            ;;
        "dev")
            print_status "Installing development dependencies..."
            if [[ -f "requirements.txt" ]]; then
                $pip_cmd install -r requirements.txt
            else
                # Fallback to manual installation
                $pip_cmd install \
                    psutil netifaces aiofiles PyYAML requests cryptography \
                    paramiko Jinja2 matplotlib plotly \
                    pytest pytest-asyncio pytest-cov black flake8 mypy bandit
            fi
            ;;
        "full"|*)
            print_status "Installing full dependencies..."
            if [[ -f "requirements.txt" ]]; then
                # Install core dependencies first
                $pip_cmd install psutil netifaces aiofiles PyYAML requests cryptography
                # Then install optional dependencies (ignore failures)
                $pip_cmd install -r requirements.txt || print_warning "Some optional dependencies failed to install"
            else
                # Fallback installation
                $pip_cmd install \
                    psutil netifaces aiofiles PyYAML requests cryptography \
                    paramiko Jinja2 MarkupSafe zxcvbn matplotlib plotly \
                    structlog memory-profiler orjson
            fi
            ;;
    esac
    
    print_success "Python dependencies installed successfully"
}

# Create directory structure
create_directories() {
    print_status "Creating directory structure..."
    
    local directories=(
        "$INSTALL_DIR"
        "$INSTALL_DIR/config"
        "$INSTALL_DIR/profiles"
        "$INSTALL_DIR/backups"
        "$INSTALL_DIR/cache"
        "$INSTALL_DIR/reports"
        "$INSTALL_DIR/logs"
        "$CONFIG_DIR"
        "$CONFIG_DIR/profiles"
        "$LOG_DIR"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        chmod 755 "$dir"
    done
    
    # Set appropriate permissions for sensitive directories
    chmod 700 "$INSTALL_DIR/backups"
    chmod 700 "$INSTALL_DIR/cache"
    chmod 750 "$LOG_DIR"
    
    print_success "Directory structure created"
}

# Download and install the tool
install_hardening_tool() {
    print_status "Installing Enhanced Linux Hardening Tool..."
    
    # If we're in the source directory, copy files
    if [[ -f "enhanced_hardening_tool.py" ]]; then
        print_status "Installing from local source..."
        cp enhanced_hardening_tool.py "$INSTALL_DIR/"
        [[ -f "requirements.txt" ]] && cp requirements.txt "$INSTALL_DIR/"
        [[ -f "README.md" ]] && cp README.md "$INSTALL_DIR/"
        [[ -f "LICENSE" ]] && cp LICENSE "$INSTALL_DIR/"
        [[ -d "config" ]] && cp -r config/* "$INSTALL_DIR/config/"
        [[ -d "profiles" ]] && cp -r profiles/* "$INSTALL_DIR/profiles/"
    else
        # Download from repository
        print_status "Downloading from repository..."
        cd "$INSTALL_DIR"
        
        if command_exists git; then
            git clone "$TOOL_REPO" temp_repo
            mv temp_repo/* .
            rm -rf temp_repo
        else
            # Fallback to wget/curl
            local download_url="${TOOL_REPO}/archive/main.tar.gz"
            if command_exists wget; then
                wget -O tool.tar.gz "$download_url"
            elif command_exists curl; then
                curl -L -o tool.tar.gz "$download_url"
            else
                print_error "No download tool available (git, wget, or curl)"
                exit 1
            fi
            
            tar -xzf tool.tar.gz --strip-components=1
            rm tool.tar.gz
        fi
    fi
    
    # Make main script executable
    chmod +x "$INSTALL_DIR/enhanced_hardening_tool.py"
    
    print_success "Tool files installed successfully"
}

# Create configuration files
create_configuration() {
    print_status "Creating configuration files..."
    
    # Main configuration file
    cat > "$CONFIG_DIR/config.yaml" << 'EOF'
# Enhanced Linux Hardening Tool Configuration
# ===========================================

# Module Configuration
modules:
  user_security:
    enabled: true
    priority: high
  ssh_hardening:
    enabled: true
    priority: high
  kernel_hardening:
    enabled: true
    priority: high
  firewall:
    enabled: true
    priority: medium
  file_permissions:
    enabled: true
    priority: medium
  services:
    enabled: true
    priority: low
  audit_logging:
    enabled: true
    priority: medium
  network_security:
    enabled: true
    priority: medium

# Compliance Framework Settings
compliance:
  frameworks: [cis, nist]
  generate_compliance_report: true
  compliance_level: recommended

# Execution Settings
execution:
  parallel_execution: true
  max_workers: 4
  timeout_seconds: 300
  retry_failed_actions: true
  create_backup_before_changes: true

# Reporting Settings
reporting:
  formats: [html, json, csv]
  include_system_info: true
  include_compliance_mapping: true
  executive_summary: true
  output_directory: /opt/linux-hardening-tool/reports

# Security Settings
security:
  verify_actions: true
  rollback_on_failure: true
  require_confirmation: true

# Logging Settings
logging:
  level: INFO
  file: /var/log/linux-hardening-tool/hardening.log
  max_size: 10MB
  backup_count: 5
EOF

    # Create systemd service file
    if [[ "$ENABLE_SERVICE" == "true" ]] && command_exists systemctl; then
        cat > "$SERVICE_DIR/linux-hardening.service" << EOF
[Unit]
Description=Enhanced Linux System Hardening Tool
Documentation=$TOOL_REPO
After=network.target

[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/enhanced_hardening_tool.py --audit --config $CONFIG_DIR/config.yaml
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

        # Create timer for scheduled runs
        cat > "$SERVICE_DIR/linux-hardening.timer" << 'EOF'
[Unit]
Description=Run Linux Hardening Tool weekly
Requires=linux-hardening.service

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
EOF

        systemctl daemon-reload
        print_success "Systemd service created"
    fi
    
    print_success "Configuration files created"
}

# Install default hardening profiles
install_profiles() {
    if [[ "$INSTALL_PROFILES" != "true" ]]; then
        return
    fi
    
    print_status "Installing default hardening profiles..."
    
    # Server profile
    cat > "$CONFIG_DIR/profiles/server.yaml" << 'EOF'
name: "Production Server Profile"
description: "High-security configuration for production servers"

modules:
  user_security:
    enabled: true
    priority: high
    settings:
      password_max_age: 90
      failed_login_attempts: 3
      disable_unused_accounts: true
      
  ssh_hardening:
    enabled: true
    priority: critical
    settings:
      disable_root_login: true
      key_based_auth_only: true
      disable_password_auth: true
      
  kernel_hardening:
    enabled: true
    priority: high
    settings:
      enable_aslr: true
      disable_core_dumps: true
      network_hardening: true
      
  firewall:
    enabled: true
    priority: high
    settings:
      default_policy: drop
      allow_ssh: true
      
compliance:
  frameworks: [cis, nist, pci_dss]
  level: high
  
execution:
  parallel: true
  max_workers: 8
  backup_before_changes: true
EOF

    # Workstation profile
    cat > "$CONFIG_DIR/profiles/workstation.yaml" << 'EOF'
name: "Workstation Profile"
description: "Balanced security for desktop/laptop systems"

modules:
  user_security:
    enabled: true
    priority: high
    settings:
      password_max_age: 180
      failed_login_attempts: 5
      
  ssh_hardening:
    enabled: false
    priority: low
    
  kernel_hardening:
    enabled: true
    priority: medium
    settings:
      enable_aslr: true
      network_hardening: false
      
  firewall:
    enabled: true
    priority: medium
    settings:
      default_policy: drop
      allow_common_services: true
      
compliance:
  frameworks: [cis]
  level: medium
EOF

    # Container profile
    cat > "$CONFIG_DIR/profiles/container.yaml" << 'EOF'
name: "Container Profile"
description: "Optimized for containerized environments"

modules:
  user_security:
    enabled: true
    priority: high
    settings:
      minimal_users: true
      
  ssh_hardening:
    enabled: false
    priority: low
    
  kernel_hardening:
    enabled: true
    priority: high
    settings:
      container_optimized: true
      
  firewall:
    enabled: false
    priority: low
    
compliance:
  frameworks: [cis]
  level: high
EOF

    print_success "Default profiles installed"
}

# Create symbolic link
create_symlink() {
    if [[ "$CREATE_SYMLINK" == "true" ]]; then
        print_status "Creating symbolic link..."
        ln -sf "$INSTALL_DIR/enhanced_hardening_tool.py" "$BIN_DIR/linux-hardening-tool"
        chmod +x "$BIN_DIR/linux-hardening-tool"
        print_success "Symbolic link created: $BIN_DIR/linux-hardening-tool"
    fi
}

# Set file permissions
set_permissions() {
    print_status "Setting file permissions..."
    
    # Tool files
    chown -R root:root "$INSTALL_DIR"
    find "$INSTALL_DIR" -type f -name "*.py" -exec chmod 755 {} \;
    find "$INSTALL_DIR" -type f -name "*.yaml" -exec chmod 644 {} \;
    find "$INSTALL_DIR" -type f -name "*.yml" -exec chmod 644 {} \;
    
    # Configuration files
    chown -R root:root "$CONFIG_DIR"
    chmod -R 644 "$CONFIG_DIR"
    
    # Log directory
    chown root:adm "$LOG_DIR" 2>/dev/null || chown root:root "$LOG_DIR"
    chmod 750 "$LOG_DIR"
    
    print_success "File permissions set"
}

# Perform post-installation setup
post_install_setup() {
    print_status "Performing post-installation setup..."
    
    # Enable and start services if requested
    if [[ "$ENABLE_SERVICE" == "true" ]] && command_exists systemctl; then
        systemctl enable linux-hardening.timer
        systemctl start linux-hardening.timer
        print_success "Scheduled hardening enabled (weekly)"
    fi
    
    # Create initial backup point
    if command_exists "$INSTALL_DIR/enhanced_hardening_tool.py"; then
        print_status "Creating initial system backup..."
        "$INSTALL_DIR/enhanced_hardening_tool.py" --dry-run --status >/dev/null 2>&1 || true
    fi
    
    # Update system package databases
    print_status "Updating system package databases..."
    local distro_info
    distro_info=$(detect_distribution)
    local distro="${distro_info%:*}"
    
    case "$distro" in
        "ubuntu"|"debian")
            apt-get update >/dev/null 2>&1 || true
            ;;
        "rhel"|"centos"|"fedora")
            if command_exists dnf; then
                dnf makecache >/dev/null 2>&1 || true
            elif command_exists yum; then
                yum makecache >/dev/null 2>&1 || true
            fi
            ;;
    esac
    
    print_success "Post-installation setup completed"
}

# Run basic verification
verify_installation() {
    print_status "Verifying installation..."
    
    local errors=0
    
    # Check if main script exists and is executable
    if [[ ! -x "$INSTALL_DIR/enhanced_hardening_tool.py" ]]; then
        print_error "Main script is not executable"
        ((errors++))
    fi
    
    # Check if Python dependencies are available
    local python_cmd
    python_cmd=$(get_python_command)
    
    local required_modules=("psutil" "netifaces" "aiofiles" "yaml" "requests" "cryptography")
    for module in "${required_modules[@]}"; do
        if ! $python_cmd -c "import $module" >/dev/null 2>&1; then
            print_error "Python module '$module' not available"
            ((errors++))
        fi
    done
    
    # Check directory structure
    local directories=("$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR")
    for dir in "${directories[@]}"; do
        if [[ ! -d "$dir" ]]; then
            print_error "Directory '$dir' does not exist"
            ((errors++))
        fi
    done
    
    # Test basic functionality
    if command_exists "$INSTALL_DIR/enhanced_hardening_tool.py"; then
        if ! "$INSTALL_DIR/enhanced_hardening_tool.py" --version >/dev/null 2>&1; then
            print_error "Tool does not execute properly"
            ((errors++))
        fi
    fi
    
    if [[ $errors -eq 0 ]]; then
        print_success "Installation verification passed"
        return 0
    else
        print_error "Installation verification failed with $errors errors"
        return 1
    fi
}

# Display installation summary
show_installation_summary() {
    print_header "Installation Summary"
    
    echo -e "${WHITE}Tool Name:${NC} $TOOL_NAME v$TOOL_VERSION"
    echo -e "${WHITE}Installation Directory:${NC} $INSTALL_DIR"
    echo -e "${WHITE}Configuration Directory:${NC} $CONFIG_DIR"
    echo -e "${WHITE}Log Directory:${NC} $LOG_DIR"
    echo -e "${WHITE}Installation Type:${NC} $INSTALL_TYPE"
    
    if [[ "$CREATE_SYMLINK" == "true" ]]; then
        echo -e "${WHITE}Command:${NC} linux-hardening-tool (or $INSTALL_DIR/enhanced_hardening_tool.py)"
    else
        echo -e "${WHITE}Command:${NC} $INSTALL_DIR/enhanced_hardening_tool.py"
    fi
    
    echo
    echo -e "${CYAN}Quick Start:${NC}"
    echo "  # Show system status"
    echo "  sudo linux-hardening-tool --status"
    echo
    echo "  # Run security audit"
    echo "  sudo linux-hardening-tool --audit --compliance cis"
    echo
    echo "  # Perform hardening (dry run first)"
    echo "  sudo linux-hardening-tool --dry-run"
    echo "  sudo linux-hardening-tool --harden --profile server"
    echo
    echo -e "${CYAN}Configuration:${NC}"
    echo "  Main config: $CONFIG_DIR/config.yaml"
    echo "  Profiles: $CONFIG_DIR/profiles/"
    echo "  Logs: $LOG_DIR/"
    echo
    echo -e "${CYAN}Documentation:${NC}"
    echo "  README: $INSTALL_DIR/README.md"
    echo "  Repository: $TOOL_REPO"
    echo
    
    if [[ "$ENABLE_SERVICE" == "true" ]] && command_exists systemctl; then
        echo -e "${CYAN}Scheduled Hardening:${NC}"
        echo "  Service: systemctl status linux-hardening.timer"
        echo "  Logs: journalctl -u linux-hardening.service"
        echo
    fi
    
    print_success "Installation completed successfully!"
}

# Handle script arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --minimal)
                INSTALL_TYPE="minimal"
                shift
                ;;
            --dev|--development)
                INSTALL_TYPE="dev"
                shift
                ;;
            --skip-deps)
                SKIP_DEPS="true"
                shift
                ;;
            --no-service)
                ENABLE_SERVICE="false"
                shift
                ;;
            --no-symlink)
                CREATE_SYMLINK="false"
                shift
                ;;
            --no-profiles)
                INSTALL_PROFILES="false"
                shift
                ;;
            --python)
                PYTHON_CMD="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Show help message
show_help() {
    cat << EOF
Enhanced Linux System Hardening Tool - Installation Script

Usage: $0 [OPTIONS]

Options:
  --minimal           Install minimal dependencies only
  --dev               Install development dependencies
  --skip-deps         Skip system dependency installation
  --no-service        Don't create systemd service
  --no-symlink        Don't create symbolic link in /usr/local/bin
  --no-profiles       Don't install default profiles
  --python CMD        Use specific Python command
  --help, -h          Show this help message

Environment Variables:
  INSTALL_TYPE        Installation type (full, minimal, dev)
  PYTHON_CMD          Python command to use
  SKIP_DEPS           Skip system dependencies (true/false)
  ENABLE_SERVICE      Enable systemd service (true/false)
  CREATE_SYMLINK      Create symbolic link (true/false)
  INSTALL_PROFILES    Install default profiles (true/false)

Examples:
  # Full installation
  sudo $0
  
  # Minimal installation without service
  sudo $0 --minimal --no-service
  
  # Development installation
  sudo $0 --dev
  
  # Custom Python version
  sudo $0 --python python3.9

EOF
}

# =============================================================================
# MAIN INSTALLATION PROCESS
# =============================================================================

main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    # Show installation header
    print_header "Enhanced Linux System Hardening Tool v$TOOL_VERSION - Installer"
    
    print_status "Starting installation with type: $INSTALL_TYPE"
    
    # Preliminary checks
    check_root
    
    # Detect system information
    local distro_info
    distro_info=$(detect_distribution)
    local distro="${distro_info%:*}"
    local version="${distro_info#*:}"
    print_status "Detected system: $distro $version"
    
    # Get Python command
    if [[ -z "$PYTHON_CMD" ]]; then
        PYTHON_CMD=$(get_python_command)
    fi
    print_status "Using Python: $PYTHON_CMD"
    
    # Install system dependencies
    if [[ "$SKIP_DEPS" != "true" ]]; then
        install_system_dependencies
    else
        print_warning "Skipping system dependency installation"
    fi
    
    # Create directory structure
    create_directories
    
    # Install the hardening tool
    install_hardening_tool
    
    # Install Python dependencies
    install_python_dependencies "$PYTHON_CMD"
    
    # Create configuration files
    create_configuration
    
    # Install default profiles
    install_profiles
    
    # Create symbolic link
    create_symlink
    
    # Set proper permissions
    set_permissions
    
    # Post-installation setup
    post_install_setup
    
    # Verify installation
    if ! verify_installation; then
        print_error "Installation verification failed"
        print_status "Please check the errors above and retry"
        exit 1
    fi
    
    # Show summary
    show_installation_summary
}

# Handle script interruption
trap 'print_error "Installation interrupted"; exit 130' INT TERM

# Run main function with all arguments
main "$@"
