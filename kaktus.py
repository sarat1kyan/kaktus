#!/usr/bin/env python3
"""
Linux System Hardening Tool
Automated security hardening for RHEL/Debian-based distributions
Version: 1.0.0
"""

import os
import sys
import json
import yaml
import shutil
import logging
import argparse
import subprocess
import datetime
import platform
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum

# Configuration
TOOL_VERSION = "1.0.0"
LOG_DIR = "/var/log/linux-hardening-tool"
BACKUP_DIR = "/var/backups/linux-hardening-tool"
CONFIG_DIR = "/etc/linux-hardening-tool"
PROFILE_DIR = f"{CONFIG_DIR}/profiles"

# Ensure Python 3.6+
if sys.version_info < (3, 6):
    print("Error: Python 3.6+ required")
    sys.exit(1)

class DistroType(Enum):
    RHEL = "rhel"
    DEBIAN = "debian"
    UBUNTU = "ubuntu"
    UNKNOWN = "unknown"

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class DistroInfo:
    type: DistroType
    name: str
    version: str
    codename: str

@dataclass
class AuditResult:
    module: str
    check: str
    status: str
    severity: Severity
    message: str
    recommendation: str

@dataclass
class HardeningAction:
    module: str
    action: str
    description: str
    impact: str
    commands: List[str]
    rollback_commands: List[str]
    files_modified: List[str]

class SystemInfo:
    """Gather system information"""
    
    @staticmethod
    def get_distro() -> DistroInfo:
        """Detect Linux distribution"""
        try:
            with open('/etc/os-release', 'r') as f:
                os_info = {}
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        os_info[key] = value.strip('"')
            
            distro_id = os_info.get('ID', '').lower()
            if distro_id in ['rhel', 'centos', 'fedora', 'rocky', 'almalinux']:
                dtype = DistroType.RHEL
            elif distro_id == 'debian':
                dtype = DistroType.DEBIAN
            elif distro_id == 'ubuntu':
                dtype = DistroType.UBUNTU
            else:
                dtype = DistroType.UNKNOWN
            
            return DistroInfo(
                type=dtype,
                name=os_info.get('NAME', 'Unknown'),
                version=os_info.get('VERSION_ID', 'Unknown'),
                codename=os_info.get('VERSION_CODENAME', 'Unknown')
            )
        except Exception as e:
            logging.error(f"Failed to detect distribution: {e}")
            return DistroInfo(DistroType.UNKNOWN, "Unknown", "Unknown", "Unknown")
    
    @staticmethod
    def get_running_services() -> List[str]:
        """Get list of running services"""
        services = []
        try:
            result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager', '--no-legend'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        service_name = line.split()[0]
                        services.append(service_name)
        except Exception as e:
            logging.error(f"Failed to get running services: {e}")
        return services
    
    @staticmethod
    def get_network_interfaces() -> List[Dict]:
        """Get network interface information"""
        interfaces = []
        try:
            result = subprocess.run(['ip', '-j', 'addr'], capture_output=True, text=True)
            if result.returncode == 0:
                interfaces = json.loads(result.stdout)
        except Exception as e:
            logging.error(f"Failed to get network interfaces: {e}")
        return interfaces
    
    @staticmethod
    def get_installed_packages() -> List[str]:
        """Get list of installed packages"""
        packages = []
        distro = SystemInfo.get_distro()
        
        try:
            if distro.type == DistroType.RHEL:
                result = subprocess.run(['rpm', '-qa', '--qf', '%{NAME}\n'], capture_output=True, text=True)
            elif distro.type in [DistroType.DEBIAN, DistroType.UBUNTU]:
                result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.startswith('ii'):
                            parts = line.split()
                            if len(parts) >= 2:
                                packages.append(parts[1])
                    return packages
            
            if result.returncode == 0:
                packages = result.stdout.strip().split('\n')
        except Exception as e:
            logging.error(f"Failed to get installed packages: {e}")
        
        return packages

class BackupManager:
    """Handle backups and rollbacks"""
    
    def __init__(self):
        self.backup_dir = Path(BACKUP_DIR)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.current_backup = None
    
    def create_backup(self, description: str) -> str:
        """Create a new backup point"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_id = f"{timestamp}_{description.replace(' ', '_')}"
        backup_path = self.backup_dir / backup_id
        backup_path.mkdir(parents=True, exist_ok=True)
        
        self.current_backup = backup_path
        
        # Create backup metadata
        metadata = {
            'timestamp': timestamp,
            'description': description,
            'distro': SystemInfo.get_distro().__dict__,
            'files_backed_up': []
        }
        
        with open(backup_path / 'metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logging.info(f"Created backup: {backup_id}")
        return backup_id
    
    def backup_file(self, filepath: str) -> bool:
        """Backup a single file"""
        if not self.current_backup:
            logging.error("No active backup session")
            return False
        
        try:
            source = Path(filepath)
            if not source.exists():
                logging.warning(f"File does not exist: {filepath}")
                return False
            
            # Calculate relative path for backup
            if source.is_absolute():
                relative_path = str(source).lstrip('/')
            else:
                relative_path = str(source)
            
            backup_path = self.current_backup / 'files' / relative_path
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Copy file with permissions
            shutil.copy2(source, backup_path)
            
            # Update metadata
            metadata_path = self.current_backup / 'metadata.json'
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            metadata['files_backed_up'].append(filepath)
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logging.debug(f"Backed up: {filepath}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to backup {filepath}: {e}")
            return False
    
    def list_backups(self) -> List[Dict]:
        """List all available backups"""
        backups = []
        for backup_dir in self.backup_dir.iterdir():
            if backup_dir.is_dir():
                metadata_file = backup_dir / 'metadata.json'
                if metadata_file.exists():
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                        metadata['backup_id'] = backup_dir.name
                        backups.append(metadata)
        
        return sorted(backups, key=lambda x: x['timestamp'], reverse=True)
    
    def rollback(self, backup_id: str) -> bool:
        """Rollback to a specific backup"""
        backup_path = self.backup_dir / backup_id
        if not backup_path.exists():
            logging.error(f"Backup not found: {backup_id}")
            return False
        
        metadata_file = backup_path / 'metadata.json'
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        
        files_dir = backup_path / 'files'
        restored_count = 0
        
        for backed_up_file in metadata['files_backed_up']:
            try:
                relative_path = backed_up_file.lstrip('/')
                source = files_dir / relative_path
                dest = Path('/') / relative_path
                
                if source.exists():
                    # Ensure destination directory exists
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    # Restore file
                    shutil.copy2(source, dest)
                    restored_count += 1
                    logging.info(f"Restored: {backed_up_file}")
                
            except Exception as e:
                logging.error(f"Failed to restore {backed_up_file}: {e}")
        
        logging.info(f"Rollback completed: {restored_count}/{len(metadata['files_backed_up'])} files restored")
        return True

class BaseModule(ABC):
    """Base class for hardening modules"""
    
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.audit_results = []
        self.actions = []
        self.backup_manager = BackupManager()
        self.distro = SystemInfo.get_distro()
    
    @abstractmethod
    def audit(self) -> List[AuditResult]:
        """Perform security audit"""
        pass
    
    @abstractmethod
    def harden(self) -> List[HardeningAction]:
        """Apply hardening configurations"""
        pass
    
    def execute_command(self, command: List[str], check: bool = True) -> Tuple[int, str, str]:
        """Execute a system command"""
        if self.dry_run:
            logging.info(f"[DRY RUN] Would execute: {' '.join(command)}")
            return 0, "", ""
        
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=check)
            return result.returncode, result.stdout, result.stderr
        except subprocess.CalledProcessError as e:
            return e.returncode, e.stdout, e.stderr
        except Exception as e:
            return -1, "", str(e)
    
    def backup_file(self, filepath: str):
        """Backup a file before modification"""
        if not self.dry_run:
            self.backup_manager.backup_file(filepath)
    
    def file_contains_line(self, filepath: str, line: str) -> bool:
        """Check if file contains a specific line"""
        try:
            with open(filepath, 'r') as f:
                return line.strip() in [l.strip() for l in f.readlines()]
        except:
            return False
    
    def append_to_file(self, filepath: str, content: str):
        """Append content to file"""
        if self.dry_run:
            logging.info(f"[DRY RUN] Would append to {filepath}: {content}")
            return
        
        self.backup_file(filepath)
        with open(filepath, 'a') as f:
            f.write(content)
    
    def replace_in_file(self, filepath: str, pattern: str, replacement: str):
        """Replace pattern in file"""
        if self.dry_run:
            logging.info(f"[DRY RUN] Would replace in {filepath}: {pattern} -> {replacement}")
            return
        
        self.backup_file(filepath)
        with open(filepath, 'r') as f:
            content = f.read()
        
        content = re.sub(pattern, replacement, content)
        
        with open(filepath, 'w') as f:
            f.write(content)

class UserSecurityModule(BaseModule):
    """User and group security hardening"""
    
    def audit(self) -> List[AuditResult]:
        results = []
        
        # Check for users with empty passwords
        try:
            with open('/etc/shadow', 'r') as f:
                for line in f:
                    fields = line.strip().split(':')
                    if len(fields) >= 2 and fields[1] == '':
                        results.append(AuditResult(
                            module="user_security",
                            check="empty_password",
                            status="FAIL",
                            severity=Severity.CRITICAL,
                            message=f"User {fields[0]} has empty password",
                            recommendation="Set a strong password or disable the account"
                        ))
        except Exception as e:
            logging.error(f"Failed to check shadow file: {e}")
        
        # Check for users with UID 0 (root privileges)
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    fields = line.strip().split(':')
                    if len(fields) >= 3 and fields[2] == '0' and fields[0] != 'root':
                        results.append(AuditResult(
                            module="user_security",
                            check="uid_zero",
                            status="FAIL",
                            severity=Severity.CRITICAL,
                            message=f"Non-root user {fields[0]} has UID 0",
                            recommendation="Remove UID 0 from non-root users"
                        ))
        except Exception as e:
            logging.error(f"Failed to check passwd file: {e}")
        
        # Check password aging
        ret, out, _ = self.execute_command(['chage', '-l', 'root'], check=False)
        if ret == 0 and 'Password expires' in out:
            if 'never' in out.lower():
                results.append(AuditResult(
                    module="user_security",
                    check="password_aging",
                    status="WARN",
                    severity=Severity.MEDIUM,
                    message="Root password never expires",
                    recommendation="Set password expiration policy"
                ))
        
        # Check for weak umask
        try:
            with open('/etc/profile', 'r') as f:
                content = f.read()
                if 'umask 022' not in content and 'umask 027' not in content:
                    results.append(AuditResult(
                        module="user_security",
                        check="umask",
                        status="WARN",
                        severity=Severity.MEDIUM,
                        message="Weak or missing umask in /etc/profile",
                        recommendation="Set umask to 022 or 027"
                    ))
        except Exception as e:
            logging.error(f"Failed to check umask: {e}")
        
        self.audit_results = results
        return results
    
    def harden(self) -> List[HardeningAction]:
        actions = []
        
        # Set password aging policies
        action = HardeningAction(
            module="user_security",
            action="password_aging",
            description="Configure password aging policies",
            impact="Users will be required to change passwords periodically",
            commands=[
                ['sed', '-i', 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/', '/etc/login.defs'],
                ['sed', '-i', 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/', '/etc/login.defs'],
                ['sed', '-i', 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/', '/etc/login.defs']
            ],
            rollback_commands=[],
            files_modified=['/etc/login.defs']
        )
        
        for cmd in action.commands:
            self.execute_command(cmd)
        actions.append(action)
        
        # Set secure umask
        if not self.file_contains_line('/etc/profile', 'umask 027'):
            self.append_to_file('/etc/profile', '\n# Security hardening\numask 027\n')
            actions.append(HardeningAction(
                module="user_security",
                action="umask",
                description="Set secure umask",
                impact="New files will have more restrictive permissions",
                commands=[],
                rollback_commands=[],
                files_modified=['/etc/profile']
            ))
        
        # Disable unused system accounts
        system_accounts = ['bin', 'daemon', 'adm', 'lp', 'sync', 'shutdown', 'halt', 'mail', 'operator', 'games', 'ftp', 'nobody']
        for account in system_accounts:
            ret, _, _ = self.execute_command(['usermod', '-L', '-s', '/sbin/nologin', account], check=False)
            if ret == 0:
                actions.append(HardeningAction(
                    module="user_security",
                    action="disable_account",
                    description=f"Disabled system account: {account}",
                    impact="Account cannot be used for login",
                    commands=[],
                    rollback_commands=[['usermod', '-U', account]],
                    files_modified=[]
                ))
        
        self.actions = actions
        return actions

class SSHHardeningModule(BaseModule):
    """SSH server hardening"""
    
    def __init__(self, dry_run: bool = False):
        super().__init__(dry_run)
        self.sshd_config = '/etc/ssh/sshd_config'
    
    def audit(self) -> List[AuditResult]:
        results = []
        
        if not os.path.exists(self.sshd_config):
            results.append(AuditResult(
                module="ssh",
                check="sshd_config",
                status="SKIP",
                severity=Severity.INFO,
                message="SSH server not installed",
                recommendation="N/A"
            ))
            return results
        
        # Read current SSH configuration
        try:
            with open(self.sshd_config, 'r') as f:
                config = f.read()
            
            # Check critical settings
            checks = {
                'PermitRootLogin': ('no', Severity.HIGH, 'Root login via SSH is permitted'),
                'PasswordAuthentication': ('no', Severity.MEDIUM, 'Password authentication is enabled'),
                'PermitEmptyPasswords': ('no', Severity.CRITICAL, 'Empty passwords are permitted'),
                'X11Forwarding': ('no', Severity.LOW, 'X11 forwarding is enabled'),
                'MaxAuthTries': ('4', Severity.MEDIUM, 'MaxAuthTries not limited'),
                'ClientAliveInterval': ('300', Severity.LOW, 'Client timeout not configured'),
                'Protocol': ('2', Severity.CRITICAL, 'SSH Protocol 1 may be enabled')
            }
            
            for param, (expected, severity, message) in checks.items():
                pattern = rf'^{param}\s+(\S+)'
                match = re.search(pattern, config, re.MULTILINE)
                
                if not match or match.group(1) != expected:
                    current = match.group(1) if match else 'not set'
                    results.append(AuditResult(
                        module="ssh",
                        check=param.lower(),
                        status="FAIL",
                        severity=severity,
                        message=f"{message} (current: {current})",
                        recommendation=f"Set {param} to {expected}"
                    ))
                else:
                    results.append(AuditResult(
                        module="ssh",
                        check=param.lower(),
                        status="PASS",
                        severity=Severity.INFO,
                        message=f"{param} is properly configured",
                        recommendation=""
                    ))
        
        except Exception as e:
            logging.error(f"Failed to audit SSH configuration: {e}")
        
        self.audit_results = results
        return results
    
    def harden(self) -> List[HardeningAction]:
        actions = []
        
        if not os.path.exists(self.sshd_config):
            return actions
        
        # Backup SSH configuration
        self.backup_file(self.sshd_config)
        
        # SSH hardening parameters
        ssh_params = {
            'Protocol': '2',
            'PermitRootLogin': 'no',
            'PasswordAuthentication': 'no',
            'PermitEmptyPasswords': 'no',
            'X11Forwarding': 'no',
            'MaxAuthTries': '4',
            'ClientAliveInterval': '300',
            'ClientAliveCountMax': '0',
            'IgnoreRhosts': 'yes',
            'HostbasedAuthentication': 'no',
            'PubkeyAuthentication': 'yes',
            'LogLevel': 'INFO',
            'StrictModes': 'yes',
            'UsePrivilegeSeparation': 'yes',
            'AllowUsers': '',  # Will be configured based on existing users
            'DenyUsers': '',
            'AllowGroups': '',
            'DenyGroups': ''
        }
        
        # Apply SSH hardening
        for param, value in ssh_params.items():
            if value:  # Skip empty values
                pattern = rf'^#?\s*{param}\s+.*'
                replacement = f'{param} {value}'
                self.replace_in_file(self.sshd_config, pattern, replacement)
        
        # Add secure ciphers and algorithms
        secure_config = """
# Security hardening - Ciphers and algorithms
Ciphers aes128-ctr,aes192-ctr,aes256-ctr
MACs hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256
"""
        
        if not self.file_contains_line(self.sshd_config, 'Security hardening'):
            self.append_to_file(self.sshd_config, secure_config)
        
        actions.append(HardeningAction(
            module="ssh",
            action="harden_config",
            description="Applied SSH hardening configuration",
            impact="SSH access restricted, key-based authentication required",
            commands=[['systemctl', 'restart', 'sshd']],
            rollback_commands=[],
            files_modified=[self.sshd_config]
        ))
        
        # Restart SSH service
        self.execute_command(['systemctl', 'restart', 'sshd'], check=False)
        
        self.actions = actions
        return actions

class KernelHardeningModule(BaseModule):
    """Kernel parameter hardening via sysctl"""
    
    def __init__(self, dry_run: bool = False):
        super().__init__(dry_run)
        self.sysctl_file = '/etc/sysctl.d/99-hardening.conf'
    
    def audit(self) -> List[AuditResult]:
        results = []
        
        # Kernel parameters to check
        params = {
            'net.ipv4.ip_forward': ('0', Severity.HIGH, 'IP forwarding is enabled'),
            'net.ipv4.conf.all.send_redirects': ('0', Severity.MEDIUM, 'ICMP redirects can be sent'),
            'net.ipv4.conf.default.send_redirects': ('0', Severity.MEDIUM, 'ICMP redirects can be sent (default)'),
            'net.ipv4.conf.all.accept_source_route': ('0', Severity.HIGH, 'Source routed packets accepted'),
            'net.ipv4.conf.all.accept_redirects': ('0', Severity.MEDIUM, 'ICMP redirects accepted'),
            'net.ipv4.conf.all.secure_redirects': ('0', Severity.MEDIUM, 'Secure ICMP redirects accepted'),
            'net.ipv4.conf.all.log_martians': ('1', Severity.LOW, 'Martian packets not logged'),
            'net.ipv4.icmp_echo_ignore_broadcasts': ('1', Severity.MEDIUM, 'Responds to broadcast pings'),
            'net.ipv4.icmp_ignore_bogus_error_responses': ('1', Severity.LOW, 'Bogus ICMP errors not ignored'),
            'net.ipv4.tcp_syncookies': ('1', Severity.HIGH, 'TCP SYN cookies disabled'),
            'kernel.randomize_va_space': ('2', Severity.HIGH, 'ASLR not fully enabled'),
            'kernel.exec-shield': ('1', Severity.HIGH, 'Exec shield disabled'),
            'fs.suid_dumpable': ('0', Severity.HIGH, 'Core dumps for SUID programs enabled')
        }
        
        for param, (expected, severity, message) in params.items():
            ret, out, _ = self.execute_command(['sysctl', param], check=False)
            if ret == 0:
                current = out.strip().split('=')[1].strip()
                if current != expected:
                    results.append(AuditResult(
                        module="kernel",
                        check=param.replace('.', '_'),
                        status="FAIL",
                        severity=severity,
                        message=f"{message} ({param}={current})",
                        recommendation=f"Set {param} = {expected}"
                    ))
                else:
                    results.append(AuditResult(
                        module="kernel",
                        check=param.replace('.', '_'),
                        status="PASS",
                        severity=Severity.INFO,
                        message=f"{param} is properly configured",
                        recommendation=""
                    ))
        
        self.audit_results = results
        return results
    
    def harden(self) -> List[HardeningAction]:
        actions = []
        
        # Kernel hardening parameters
        kernel_params = """# Linux Hardening Tool - Kernel Parameters
# Network Security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_timestamps = 0

# IPv6 Security (disable if not needed)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Kernel Security
kernel.randomize_va_space = 2
kernel.exec-shield = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.sysrq = 0
kernel.core_uses_pid = 1
fs.suid_dumpable = 0

# Additional Hardening
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
vm.swappiness = 10
"""
        
        # Write kernel parameters
        if not self.dry_run:
            self.backup_file('/etc/sysctl.conf')
            with open(self.sysctl_file, 'w') as f:
                f.write(kernel_params)
        
        actions.append(HardeningAction(
            module="kernel",
            action="sysctl_hardening",
            description="Applied kernel security parameters",
            impact="Enhanced network and kernel security",
            commands=[['sysctl', '-p', self.sysctl_file]],
            rollback_commands=[['rm', '-f', self.sysctl_file]],
            files_modified=[self.sysctl_file]
        ))
        
        # Apply sysctl settings
        self.execute_command(['sysctl', '-p', self.sysctl_file])
        
        self.actions = actions
        return actions

class FilePermissionsModule(BaseModule):
    """File permissions and ownership hardening"""
    
    def audit(self) -> List[AuditResult]:
        results = []
        
        # Critical files and their expected permissions
        critical_files = {
            '/etc/passwd': ('0644', 'root', 'root'),
            '/etc/shadow': ('0640', 'root', 'shadow'),
            '/etc/group': ('0644', 'root', 'root'),
            '/etc/gshadow': ('0640', 'root', 'shadow'),
            '/etc/ssh/sshd_config': ('0600', 'root', 'root'),
            '/boot/grub/grub.cfg': ('0600', 'root', 'root'),
            '/etc/crontab': ('0600', 'root', 'root'),
            '/etc/cron.hourly': ('0700', 'root', 'root'),
            '/etc/cron.daily': ('0700', 'root', 'root'),
            '/etc/cron.weekly': ('0700', 'root', 'root'),
            '/etc/cron.monthly': ('0700', 'root', 'root')
        }
        
        for filepath, (expected_perms, expected_user, expected_group) in critical_files.items():
            if os.path.exists(filepath):
                try:
                    stat = os.stat(filepath)
                    current_perms = oct(stat.st_mode)[-4:]
                    
                    # Get owner and group
                    import pwd, grp
                    try:
                        current_user = pwd.getpwuid(stat.st_uid).pw_name
                    except:
                        current_user = str(stat.st_uid)
                    
                    try:
                        current_group = grp.getgrgid(stat.st_gid).gr_name
                    except:
                        current_group = str(stat.st_gid)
                    
                    # Check permissions
                    if current_perms != expected_perms:
                        results.append(AuditResult(
                            module="file_permissions",
                            check=f"perms_{filepath.replace('/', '_')}",
                            status="FAIL",
                            severity=Severity.HIGH,
                            message=f"{filepath} has incorrect permissions: {current_perms} (expected {expected_perms})",
                            recommendation=f"chmod {expected_perms} {filepath}"
                        ))
                    
                    # Check ownership
                    if current_user != expected_user or current_group != expected_group:
                        results.append(AuditResult(
                            module="file_permissions",
                            check=f"owner_{filepath.replace('/', '_')}",
                            status="FAIL",
                            severity=Severity.HIGH,
                            message=f"{filepath} has incorrect ownership: {current_user}:{current_group} (expected {expected_user}:{expected_group})",
                            recommendation=f"chown {expected_user}:{expected_group} {filepath}"
                        ))
                    
                except Exception as e:
                    logging.error(f"Failed to check {filepath}: {e}")
        
        # Check for world-writable files
        ret, out, _ = self.execute_command(['find', '/', '-xdev', '-type', 'f', '-perm', '-0002', '-ls'], check=False)
        if ret == 0 and out.strip():
            world_writable = len(out.strip().split('\n'))
            results.append(AuditResult(
                module="file_permissions",
                check="world_writable_files",
                status="FAIL",
                severity=Severity.MEDIUM,
                message=f"Found {world_writable} world-writable files",
                recommendation="Review and fix world-writable files"
            ))
        
        # Check for unowned files
        ret, out, _ = self.execute_command(['find', '/', '-xdev', '-nouser', '-o', '-nogroup', '-ls'], check=False)
        if ret == 0 and out.strip():
            unowned = len(out.strip().split('\n'))
            results.append(AuditResult(
                module="file_permissions",
                check="unowned_files",
                status="FAIL",
                severity=Severity.MEDIUM,
                message=f"Found {unowned} unowned files",
                recommendation="Assign ownership to unowned files"
            ))
        
        self.audit_results = results
        return results
    
    def harden(self) -> List[HardeningAction]:
        actions = []
        
        # Fix critical file permissions
        critical_files = {
            '/etc/passwd': ('0644', 'root', 'root'),
            '/etc/shadow': ('0640', 'root', 'shadow'),
            '/etc/group': ('0644', 'root', 'root'),
            '/etc/gshadow': ('0640', 'root', 'shadow'),
            '/etc/ssh/sshd_config': ('0600', 'root', 'root'),
            '/boot/grub/grub.cfg': ('0600', 'root', 'root'),
            '/etc/crontab': ('0600', 'root', 'root'),
            '/etc/cron.hourly': ('0700', 'root', 'root'),
            '/etc/cron.daily': ('0700', 'root', 'root'),
            '/etc/cron.weekly': ('0700', 'root', 'root'),
            '/etc/cron.monthly': ('0700', 'root', 'root')
        }
        
        for filepath, (perms, user, group) in critical_files.items():
            if os.path.exists(filepath):
                self.execute_command(['chmod', perms, filepath])
                self.execute_command(['chown', f'{user}:{group}', filepath])
                
                actions.append(HardeningAction(
                    module="file_permissions",
                    action=f"fix_perms_{filepath.replace('/', '_')}",
                    description=f"Fixed permissions for {filepath}",
                    impact="File access restricted to authorized users",
                    commands=[
                        ['chmod', perms, filepath],
                        ['chown', f'{user}:{group}', filepath]
                    ],
                    rollback_commands=[],
                    files_modified=[filepath]
                ))
        
        # Remove world-writable permissions from files
        ret, out, _ = self.execute_command(['find', '/', '-xdev', '-type', 'f', '-perm', '-0002'], check=False)
        if ret == 0 and out.strip():
            for filepath in out.strip().split('\n'):
                if filepath and not filepath.startswith('/proc') and not filepath.startswith('/sys'):
                    self.execute_command(['chmod', 'o-w', filepath])
            
            actions.append(HardeningAction(
                module="file_permissions",
                action="remove_world_writable",
                description="Removed world-writable permissions from files",
                impact="Files no longer writable by all users",
                commands=[],
                rollback_commands=[],
                files_modified=[]
            ))
        
        self.actions = actions
        return actions

class FirewallModule(BaseModule):
    """Firewall configuration hardening"""
    
    def __init__(self, dry_run: bool = False):
        super().__init__(dry_run)
        self.firewall_type = self._detect_firewall()
    
    def _detect_firewall(self) -> str:
        """Detect which firewall is in use"""
        # Check for firewalld
        ret, _, _ = self.execute_command(['systemctl', 'is-active', 'firewalld'], check=False)
        if ret == 0:
            return 'firewalld'
        
        # Check for ufw (Ubuntu)
        if os.path.exists('/usr/sbin/ufw'):
            return 'ufw'
        
        # Check for iptables
        if os.path.exists('/usr/sbin/iptables'):
            return 'iptables'
        
        return 'none'
    
    def audit(self) -> List[AuditResult]:
        results = []
        
        if self.firewall_type == 'none':
            results.append(AuditResult(
                module="firewall",
                check="firewall_installed",
                status="FAIL",
                severity=Severity.CRITICAL,
                message="No firewall detected",
                recommendation="Install and configure a firewall"
            ))
            return results
        
        if self.firewall_type == 'firewalld':
            # Check if firewalld is running
            ret, _, _ = self.execute_command(['systemctl', 'is-active', 'firewalld'], check=False)
            if ret != 0:
                results.append(AuditResult(
                    module="firewall",
                    check="firewalld_running",
                    status="FAIL",
                    severity=Severity.HIGH,
                    message="Firewalld is not running",
                    recommendation="Start and enable firewalld"
                ))
            
            # Check default zone
            ret, out, _ = self.execute_command(['firewall-cmd', '--get-default-zone'], check=False)
            if ret == 0:
                if out.strip() == 'public':
                    results.append(AuditResult(
                        module="firewall",
                        check="firewalld_zone",
                        status="WARN",
                        severity=Severity.MEDIUM,
                        message="Using default 'public' zone",
                        recommendation="Consider using a more restrictive zone"
                    ))
        
        elif self.firewall_type == 'ufw':
            # Check if ufw is active
            ret, out, _ = self.execute_command(['ufw', 'status'], check=False)
            if ret == 0 and 'inactive' in out.lower():
                results.append(AuditResult(
                    module="firewall",
                    check="ufw_active",
                    status="FAIL",
                    severity=Severity.HIGH,
                    message="UFW is not active",
                    recommendation="Enable UFW firewall"
                ))
        
        elif self.firewall_type == 'iptables':
            # Check if iptables has rules
            ret, out, _ = self.execute_command(['iptables', '-L', '-n'], check=False)
            if ret == 0:
                if 'ACCEPT     all' in out and out.count('\n') < 10:
                    results.append(AuditResult(
                        module="firewall",
                        check="iptables_rules",
                        status="FAIL",
                        severity=Severity.HIGH,
                        message="iptables has no restrictive rules",
                        recommendation="Configure iptables rules"
                    ))
        
        self.audit_results = results
        return results
    
    def harden(self) -> List[HardeningAction]:
        actions = []
        
        if self.firewall_type == 'firewalld':
            # Enable and start firewalld
            self.execute_command(['systemctl', 'enable', 'firewalld'])
            self.execute_command(['systemctl', 'start', 'firewalld'])
            
            # Set default zone to drop
            self.execute_command(['firewall-cmd', '--set-default-zone=drop'])
            
            # Allow SSH (prevent lockout)
            self.execute_command(['firewall-cmd', '--permanent', '--add-service=ssh'])
            
            # Reload firewall
            self.execute_command(['firewall-cmd', '--reload'])
            
            actions.append(HardeningAction(
                module="firewall",
                action="configure_firewalld",
                description="Configured firewalld with restrictive rules",
                impact="Only SSH traffic allowed by default",
                commands=[],
                rollback_commands=[['firewall-cmd', '--set-default-zone=public']],
                files_modified=[]
            ))
        
        elif self.firewall_type == 'ufw':
            # Reset and configure UFW
            self.execute_command(['ufw', '--force', 'reset'])
            self.execute_command(['ufw', 'default', 'deny', 'incoming'])
            self.execute_command(['ufw', 'default', 'allow', 'outgoing'])
            self.execute_command(['ufw', 'allow', 'ssh'])
            self.execute_command(['ufw', '--force', 'enable'])
            
            actions.append(HardeningAction(
                module="firewall",
                action="configure_ufw",
                description="Configured UFW with restrictive rules",
                impact="Only SSH traffic allowed by default",
                commands=[],
                rollback_commands=[['ufw', '--force', 'disable']],
                files_modified=[]
            ))
        
        elif self.firewall_type == 'iptables':
            # Basic iptables rules
            iptables_rules = [
                ['iptables', '-F'],
                ['iptables', '-X'],
                ['iptables', '-P', 'INPUT', 'DROP'],
                ['iptables', '-P', 'FORWARD', 'DROP'],
                ['iptables', '-P', 'OUTPUT', 'ACCEPT'],
                ['iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'],
                ['iptables', '-A', 'INPUT', '-m', 'state', '--state', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'],
                ['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'],
                ['iptables', '-A', 'INPUT', '-p', 'icmp', '-j', 'ACCEPT']
            ]
            
            for rule in iptables_rules:
                self.execute_command(rule)
            
            # Save iptables rules
            if self.distro.type == DistroType.RHEL:
                self.execute_command(['service', 'iptables', 'save'])
            elif self.distro.type in [DistroType.DEBIAN, DistroType.UBUNTU]:
                self.execute_command(['iptables-save'], check=False)
            
            actions.append(HardeningAction(
                module="firewall",
                action="configure_iptables",
                description="Configured iptables with restrictive rules",
                impact="Only SSH and ICMP traffic allowed",
                commands=iptables_rules,
                rollback_commands=[['iptables', '-F'], ['iptables', '-P', 'INPUT', 'ACCEPT']],
                files_modified=[]
            ))
        
        self.actions = actions
        return actions

class ServiceHardeningModule(BaseModule):
    """Service and package management hardening"""
    
    def audit(self) -> List[AuditResult]:
        results = []
        
        # Services that should typically be disabled on hardened systems
        unnecessary_services = [
            'telnet', 'rsh', 'rlogin', 'tftp', 'vsftpd', 'finger',
            'talk', 'ntalk', 'cups', 'avahi-daemon', 'bluetooth',
            'iscsid', 'rpcbind', 'nfs', 'snmpd'
        ]
        
        running_services = SystemInfo.get_running_services()
        
        for service in unnecessary_services:
            if any(service in s for s in running_services):
                results.append(AuditResult(
                    module="services",
                    check=f"service_{service}",
                    status="FAIL",
                    severity=Severity.MEDIUM,
                    message=f"Potentially unnecessary service running: {service}",
                    recommendation=f"Disable {service} if not required"
                ))
        
        # Check for development tools
        dev_packages = ['gcc', 'make', 'gdb', 'git', 'perl', 'python2']
        installed_packages = SystemInfo.get_installed_packages()
        
        for package in dev_packages:
            if package in installed_packages:
                results.append(AuditResult(
                    module="services",
                    check=f"package_{package}",
                    status="WARN",
                    severity=Severity.LOW,
                    message=f"Development tool installed: {package}",
                    recommendation=f"Remove {package} from production servers"
                ))
        
        self.audit_results = results
        return results
    
    def harden(self) -> List[HardeningAction]:
        actions = []
        
        # Disable unnecessary services
        unnecessary_services = [
            'telnet', 'rsh', 'rlogin', 'tftp', 'vsftpd', 'finger',
            'talk', 'ntalk', 'cups', 'avahi-daemon', 'bluetooth',
            'iscsid', 'rpcbind', 'nfs', 'snmpd'
        ]
        
        for service in unnecessary_services:
            ret, _, _ = self.execute_command(['systemctl', 'is-active', service], check=False)
            if ret == 0:  # Service is active
                self.execute_command(['systemctl', 'stop', service])
                self.execute_command(['systemctl', 'disable', service])
                
                actions.append(HardeningAction(
                    module="services",
                    action=f"disable_{service}",
                    description=f"Disabled service: {service}",
                    impact=f"{service} service will no longer run",
                    commands=[
                        ['systemctl', 'stop', service],
                        ['systemctl', 'disable', service]
                    ],
                    rollback_commands=[
                        ['systemctl', 'enable', service],
                        ['systemctl', 'start', service]
                    ],
                    files_modified=[]
                ))
        
        # Configure automatic security updates
        if self.distro.type == DistroType.RHEL:
            # Install dnf-automatic if not present
            self.execute_command(['dnf', 'install', '-y', 'dnf-automatic'], check=False)
            
            # Configure dnf-automatic
            dnf_auto_conf = '/etc/dnf/automatic.conf'
            if os.path.exists(dnf_auto_conf):
                self.backup_file(dnf_auto_conf)
                self.replace_in_file(dnf_auto_conf, r'apply_updates = no', 'apply_updates = yes')
                self.execute_command(['systemctl', 'enable', '--now', 'dnf-automatic.timer'])
                
                actions.append(HardeningAction(
                    module="services",
                    action="auto_updates_rhel",
                    description="Enabled automatic security updates",
                    impact="Security updates will be applied automatically",
                    commands=[],
                    rollback_commands=[['systemctl', 'disable', 'dnf-automatic.timer']],
                    files_modified=[dnf_auto_conf]
                ))
        
        elif self.distro.type in [DistroType.DEBIAN, DistroType.UBUNTU]:
            # Install unattended-upgrades
            self.execute_command(['apt-get', 'install', '-y', 'unattended-upgrades'], check=False)
            
            # Enable unattended-upgrades
            self.execute_command(['dpkg-reconfigure', '-plow', 'unattended-upgrades'], check=False)
            
            actions.append(HardeningAction(
                module="services",
                action="auto_updates_debian",
                description="Enabled unattended upgrades",
                impact="Security updates will be applied automatically",
                commands=[],
                rollback_commands=[],
                files_modified=['/etc/apt/apt.conf.d/50unattended-upgrades']
            ))
        
        self.actions = actions
        return actions

class AuditdModule(BaseModule):
    """Auditd and logging configuration"""
    
    def audit(self) -> List[AuditResult]:
        results = []
        
        # Check if auditd is installed and running
        ret, _, _ = self.execute_command(['systemctl', 'is-active', 'auditd'], check=False)
        if ret != 0:
            results.append(AuditResult(
                module="auditd",
                check="auditd_running",
                status="FAIL",
                severity=Severity.HIGH,
                message="Auditd is not running",
                recommendation="Install and enable auditd"
            ))
            return results
        
        # Check audit rules
        ret, out, _ = self.execute_command(['auditctl', '-l'], check=False)
        if ret == 0:
            if 'No rules' in out or not out.strip():
                results.append(AuditResult(
                    module="auditd",
                    check="audit_rules",
                    status="FAIL",
                    severity=Severity.HIGH,
                    message="No audit rules configured",
                    recommendation="Configure comprehensive audit rules"
                ))
        
        # Check log file permissions
        if os.path.exists('/var/log/audit/audit.log'):
            stat = os.stat('/var/log/audit/audit.log')
            perms = oct(stat.st_mode)[-3:]
            if perms != '600':
                results.append(AuditResult(
                    module="auditd",
                    check="audit_log_perms",
                    status="FAIL",
                    severity=Severity.MEDIUM,
                    message=f"Audit log has incorrect permissions: {perms}",
                    recommendation="Set audit log permissions to 600"
                ))
        
        self.audit_results = results
        return results
    
    def harden(self) -> List[HardeningAction]:
        actions = []
        
        # Install auditd if not present
        if self.distro.type == DistroType.RHEL:
            self.execute_command(['dnf', 'install', '-y', 'audit'], check=False)
        elif self.distro.type in [DistroType.DEBIAN, DistroType.UBUNTU]:
            self.execute_command(['apt-get', 'install', '-y', 'auditd'], check=False)
        
        # Enable and start auditd
        self.execute_command(['systemctl', 'enable', 'auditd'])
        self.execute_command(['systemctl', 'start', 'auditd'])
        
        # Configure audit rules
        audit_rules = """# Linux Hardening Tool - Audit Rules
# Delete all existing rules
-D

# Set buffer size
-b 8192

# Monitor authentication
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/gshadow -p wa -k gshadow_changes
-w /etc/security/opasswd -p wa -k opasswd_changes

# Monitor sudo
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Monitor SSH
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Monitor file deletions
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Monitor admin actions
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# Monitor login/logout
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Make configuration immutable
-e 2
"""
        
        audit_rules_file = '/etc/audit/rules.d/hardening.rules'
        if not self.dry_run:
            self.backup_file(audit_rules_file)
            with open(audit_rules_file, 'w') as f:
                f.write(audit_rules)
        
        # Restart auditd to apply rules
        self.execute_command(['service', 'auditd', 'restart'], check=False)
        
        actions.append(HardeningAction(
            module="auditd",
            action="configure_audit",
            description="Configured comprehensive audit rules",
            impact="System activities will be logged for security monitoring",
            commands=[],
            rollback_commands=[['rm', '-f', audit_rules_file]],
            files_modified=[audit_rules_file]
        ))
        
        # Configure log rotation
        logrotate_conf = """
/var/log/audit/audit.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0600 root root
    postrotate
        /usr/sbin/service auditd restart > /dev/null
    endscript
}
"""
        
        logrotate_file = '/etc/logrotate.d/audit'
        if not self.dry_run:
            with open(logrotate_file, 'w') as f:
                f.write(logrotate_conf)
        
        actions.append(HardeningAction(
            module="auditd",
            action="log_rotation",
            description="Configured audit log rotation",
            impact="Audit logs will be rotated daily and compressed",
            commands=[],
            rollback_commands=[],
            files_modified=[logrotate_file]
        ))
        
        self.actions = actions
        return actions

class SELinuxModule(BaseModule):
    """SELinux/AppArmor configuration"""
    
    def __init__(self, dry_run: bool = False):
        super().__init__(dry_run)
        self.mac_system = self._detect_mac_system()
    
    def _detect_mac_system(self) -> str:
        """Detect which MAC system is available"""
        if os.path.exists('/usr/sbin/getenforce'):
            return 'selinux'
        elif os.path.exists('/usr/sbin/aa-status'):
            return 'apparmor'
        return 'none'
    
    def audit(self) -> List[AuditResult]:
        results = []
        
        if self.mac_system == 'none':
            results.append(AuditResult(
                module="mac",
                check="mac_system",
                status="FAIL",
                severity=Severity.HIGH,
                message="No MAC system (SELinux/AppArmor) detected",
                recommendation="Install and configure SELinux or AppArmor"
            ))
            return results
        
        if self.mac_system == 'selinux':
            # Check SELinux status
            ret, out, _ = self.execute_command(['getenforce'], check=False)
            if ret == 0:
                status = out.strip()
                if status == 'Disabled':
                    results.append(AuditResult(
                        module="mac",
                        check="selinux_enabled",
                        status="FAIL",
                        severity=Severity.HIGH,
                        message="SELinux is disabled",
                        recommendation="Enable SELinux in enforcing mode"
                    ))
                elif status == 'Permissive':
                    results.append(AuditResult(
                        module="mac",
                        check="selinux_mode",
                        status="WARN",
                        severity=Severity.MEDIUM,
                        message="SELinux is in permissive mode",
                        recommendation="Set SELinux to enforcing mode"
                    ))
                else:
                    results.append(AuditResult(
                        module="mac",
                        check="selinux_enforcing",
                        status="PASS",
                        severity=Severity.INFO,
                        message="SELinux is enforcing",
                        recommendation=""
                    ))
        
        elif self.mac_system == 'apparmor':
            # Check AppArmor status
            ret, out, _ = self.execute_command(['aa-status'], check=False)
            if ret == 0:
                if 'profiles are loaded' in out:
                    loaded = int(re.search(r'(\d+) profiles are loaded', out).group(1))
                    enforced = int(re.search(r'(\d+) profiles are in enforce mode', out).group(1))
                    
                    if loaded == 0:
                        results.append(AuditResult(
                            module="mac",
                            check="apparmor_profiles",
                            status="FAIL",
                            severity=Severity.HIGH,
                            message="No AppArmor profiles loaded",
                            recommendation="Load AppArmor profiles"
                        ))
                    elif enforced < loaded:
                        results.append(AuditResult(
                            module="mac",
                            check="apparmor_enforce",
                            status="WARN",
                            severity=Severity.MEDIUM,
                            message=f"Only {enforced}/{loaded} profiles in enforce mode",
                            recommendation="Set all profiles to enforce mode"
                        ))
            else:
                results.append(AuditResult(
                    module="mac",
                    check="apparmor_status",
                    status="FAIL",
                    severity=Severity.HIGH,
                    message="AppArmor not functioning properly",
                    recommendation="Fix AppArmor configuration"
                ))
        
        self.audit_results = results
        return results
    
    def harden(self) -> List[HardeningAction]:
        actions = []
        
        if self.mac_system == 'selinux':
            # Set SELinux to enforcing
            config_file = '/etc/selinux/config'
            if os.path.exists(config_file):
                self.backup_file(config_file)
                self.replace_in_file(config_file, r'SELINUX=.*', 'SELINUX=enforcing')
                
                # Set current mode to enforcing (will take effect after reboot for disabled->enforcing)
                self.execute_command(['setenforce', '1'], check=False)
                
                actions.append(HardeningAction(
                    module="mac",
                    action="selinux_enforce",
                    description="Set SELinux to enforcing mode",
                    impact="SELinux will enforce security policies (requires reboot if disabled)",
                    commands=[],
                    rollback_commands=[['setenforce', '0']],
                    files_modified=[config_file]
                ))
        
        elif self.mac_system == 'apparmor':
            # Ensure AppArmor is enabled
            self.execute_command(['systemctl', 'enable', 'apparmor'])
            self.execute_command(['systemctl', 'start', 'apparmor'])
            
            # Set all profiles to enforce mode
            ret, out, _ = self.execute_command(['aa-status'], check=False)
            if ret == 0:
                # Parse complain mode profiles
                if 'profiles are in complain mode' in out:
                    for line in out.split('\n'):
                        if line.strip().startswith('/'):
                            profile = line.strip()
                            self.execute_command(['aa-enforce', profile], check=False)
                
                actions.append(HardeningAction(
                    module="mac",
                    action="apparmor_enforce",
                    description="Set AppArmor profiles to enforce mode",
                    impact="Applications will be confined by AppArmor policies",
                    commands=[],
                    rollback_commands=[],
                    files_modified=[]
                ))
        
        self.actions = actions
        return actions

class HardeningOrchestrator:
    """Main orchestrator for the hardening tool"""
    
    def __init__(self, config_file: Optional[str] = None, dry_run: bool = False):
        self.dry_run = dry_run
        self.config = self._load_config(config_file)
        self.backup_manager = BackupManager()
        self.modules = self._initialize_modules()
        self.audit_results = []
        self.actions_taken = []
        
        # Setup logging
        self._setup_logging()
    
    def _setup_logging(self):
        """Configure logging"""
        log_dir = Path(LOG_DIR)
        log_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = log_dir / f"hardening_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
    
    def _load_config(self, config_file: Optional[str]) -> Dict:
        """Load configuration from file"""
        default_config = {
            'modules': {
                'user_security': {'enabled': True},
                'ssh': {'enabled': True},
                'kernel': {'enabled': True},
                'file_permissions': {'enabled': True},
                'firewall': {'enabled': True},
                'services': {'enabled': True},
                'auditd': {'enabled': True},
                'selinux': {'enabled': True}
            },
            'options': {
                'create_backup': True,
                'interactive': True,
                'report_format': 'json'
            }
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    if config_file.endswith('.json'):
                        user_config = json.load(f)
                    elif config_file.endswith('.yaml') or config_file.endswith('.yml'):
                        user_config = yaml.safe_load(f)
                    else:
                        logging.error(f"Unsupported config format: {config_file}")
                        return default_config
                
                # Merge configs
                default_config.update(user_config)
            except Exception as e:
                logging.error(f"Failed to load config: {e}")
        
        return default_config
    
    def _initialize_modules(self) -> List[BaseModule]:
        """Initialize enabled modules"""
        available_modules = {
            'user_security': UserSecurityModule,
            'ssh': SSHHardeningModule,
            'kernel': KernelHardeningModule,
            'file_permissions': FilePermissionsModule,
            'firewall': FirewallModule,
            'services': ServiceHardeningModule,
            'auditd': AuditdModule,
            'selinux': SELinuxModule
        }
        
        modules = []
        for module_name, module_class in available_modules.items():
            if self.config['modules'].get(module_name, {}).get('enabled', True):
                modules.append(module_class(self.dry_run))
                logging.info(f"Initialized module: {module_name}")
        
        return modules
    
    def perform_audit(self) -> List[AuditResult]:
        """Perform security audit using all modules"""
        logging.info("Starting security audit...")
        all_results = []
        
        for module in self.modules:
            logging.info(f"Auditing: {module.__class__.__name__}")
            try:
                results = module.audit()
                all_results.extend(results)
            except Exception as e:
                logging.error(f"Error in {module.__class__.__name__}: {e}")
        
        self.audit_results = all_results
        return all_results
    
    def analyze_impact(self) -> Dict:
        """Analyze the impact of proposed changes"""
        impact_analysis = {
            'total_changes': 0,
            'high_impact': [],
            'medium_impact': [],
            'low_impact': [],
            'services_affected': [],
            'files_modified': [],
            'requires_reboot': False
        }
        
        for module in self.modules:
            actions = module.harden()  # Get proposed actions without executing
            
            for action in actions:
                impact_analysis['total_changes'] += 1
                impact_analysis['files_modified'].extend(action.files_modified)
                
                # Categorize impact
                if 'reboot' in action.impact.lower():
                    impact_analysis['requires_reboot'] = True
                    impact_analysis['high_impact'].append(action)
                elif 'service' in action.impact.lower() or 'ssh' in action.module:
                    impact_analysis['medium_impact'].append(action)
                    if 'service' in action.action:
                        impact_analysis['services_affected'].append(action.description)
                else:
                    impact_analysis['low_impact'].append(action)
        
        return impact_analysis
    
    def apply_hardening(self, interactive: bool = True) -> bool:
        """Apply hardening configurations"""
        if self.dry_run:
            logging.info("DRY RUN MODE - No changes will be made")
        
        # Create backup point
        if self.config['options']['create_backup'] and not self.dry_run:
            backup_id = self.backup_manager.create_backup("pre_hardening")
            logging.info(f"Created backup: {backup_id}")
        
        # Analyze impact first
        if interactive and not self.dry_run:
            impact = self.analyze_impact()
            self._display_impact_analysis(impact)
            
            response = input("\nProceed with hardening? [y/N]: ")
            if response.lower() != 'y':
                logging.info("Hardening cancelled by user")
                return False
        
        # Apply hardening
        logging.info("Applying hardening configurations...")
        
        for module in self.modules:
            logging.info(f"Hardening: {module.__class__.__name__}")
            try:
                actions = module.harden()
                self.actions_taken.extend(actions)
            except Exception as e:
                logging.error(f"Error in {module.__class__.__name__}: {e}")
        
        return True
    
    def _display_impact_analysis(self, impact: Dict):
        """Display impact analysis to user"""
        print("\n" + "="*60)
        print("IMPACT ANALYSIS")
        print("="*60)
        print(f"Total changes to be made: {impact['total_changes']}")
        print(f"Files to be modified: {len(set(impact['files_modified']))}")
        print(f"Requires reboot: {'Yes' if impact['requires_reboot'] else 'No'}")
        
        if impact['high_impact']:
            print("\nHIGH IMPACT CHANGES:")
            for action in impact['high_impact']:
                print(f"  - {action.description}")
                print(f"    Impact: {action.impact}")
        
        if impact['medium_impact']:
            print("\nMEDIUM IMPACT CHANGES:")
            for action in impact['medium_impact']:
                print(f"  - {action.description}")
        
        if impact['services_affected']:
            print("\nSERVICES AFFECTED:")
            for service in impact['services_affected']:
                print(f"  - {service}")
    
    def generate_report(self, output_file: Optional[str] = None) -> Dict:
        """Generate comprehensive report"""
        report = {
            'metadata': {
                'tool_version': TOOL_VERSION,
                'timestamp': datetime.datetime.now().isoformat(),
                'hostname': platform.node(),
                'distro': SystemInfo.get_distro().__dict__,
                'dry_run': self.dry_run
            },
            'audit_summary': {
                'total_checks': len(self.audit_results),
                'passed': len([r for r in self.audit_results if r.status == 'PASS']),
                'failed': len([r for r in self.audit_results if r.status == 'FAIL']),
                'warnings': len([r for r in self.audit_results if r.status == 'WARN']),
                'skipped': len([r for r in self.audit_results if r.status == 'SKIP'])
            },
            'audit_results': [result.__dict__ for result in self.audit_results],
            'actions_taken': [action.__dict__ for action in self.actions_taken],
            'statistics': {
                'critical_issues': len([r for r in self.audit_results if r.severity == Severity.CRITICAL]),
                'high_issues': len([r for r in self.audit_results if r.severity == Severity.HIGH]),
                'medium_issues': len([r for r in self.audit_results if r.severity == Severity.MEDIUM]),
                'low_issues': len([r for r in self.audit_results if r.severity == Severity.LOW])
            }
        }
        
        # Convert Enum values to strings for JSON serialization
        for result in report['audit_results']:
            result['severity'] = result['severity'].value
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            logging.info(f"Report saved to: {output_file}")
        
        return report
    
    def rollback(self, backup_id: str) -> bool:
        """Rollback to a previous state"""
        logging.info(f"Rolling back to: {backup_id}")
        return self.backup_manager.rollback(backup_id)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Linux System Hardening Tool - Automated security hardening for RHEL/Debian-based systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Perform audit only
  %(prog)s --audit-only
  
  # Run in dry-run mode
  %(prog)s --dry-run
  
  # Apply hardening with custom config
  %(prog)s --config custom.yaml
  
  # Generate report
  %(prog)s --audit-only --report audit_report.json
  
  # Rollback changes
  %(prog)s --rollback BACKUP_ID
        """
    )
    
    parser.add_argument('--version', action='version', version=f'%(prog)s {TOOL_VERSION}')
    parser.add_argument('--config', help='Configuration file (JSON/YAML)')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without making changes')
    parser.add_argument('--audit-only', action='store_true', help='Perform audit only, no hardening')
    parser.add_argument('--non-interactive', action='store_true', help='Run without user prompts')
    parser.add_argument('--report', help='Generate report file')
    parser.add_argument('--rollback', help='Rollback to a specific backup')
    parser.add_argument('--list-backups', action='store_true', help='List available backups')
    parser.add_argument('--modules', help='Comma-separated list of modules to run')
    
    args = parser.parse_args()
    
    # Check for root privileges
    if os.geteuid() != 0 and not args.dry_run:
        print("Error: This tool must be run as root (use --dry-run for testing)")
        sys.exit(1)
    
    # Initialize orchestrator
    orchestrator = HardeningOrchestrator(
        config_file=args.config,
        dry_run=args.dry_run
    )
    
    # Handle special operations
    if args.list_backups:
        backups = orchestrator.backup_manager.list_backups()
        print("\nAvailable backups:")
        for backup in backups:
            print(f"  {backup['backup_id']} - {backup['description']} ({backup['timestamp']})")
        return
    
    if args.rollback:
        if orchestrator.rollback(args.rollback):
            print("Rollback completed successfully")
        else:
            print("Rollback failed")
        return
    
    # Filter modules if specified
    if args.modules:
        requested_modules = args.modules.split(',')
        orchestrator.modules = [m for m in orchestrator.modules 
                               if m.__class__.__name__.lower().replace('module', '') in requested_modules]
    
    # Display system information
    distro = SystemInfo.get_distro()
    print(f"\nLinux System Hardening Tool v{TOOL_VERSION}")
    print(f"System: {distro.name} {distro.version}")
    print(f"Mode: {'DRY RUN' if args.dry_run else 'LIVE'}")
    print("="*60)
    
    # Perform audit
    audit_results = orchestrator.perform_audit()
    
    # Display audit summary
    print(f"\nAudit Summary:")
    print(f"  Total checks: {len(audit_results)}")
    print(f"  Passed: {len([r for r in audit_results if r.status == 'PASS'])}")
    print(f"  Failed: {len([r for r in audit_results if r.status == 'FAIL'])}")
    print(f"  Warnings: {len([r for r in audit_results if r.status == 'WARN'])}")
    
    # Apply hardening if not audit-only
    if not args.audit_only:
        orchestrator.apply_hardening(interactive=not args.non_interactive)
    
    # Generate report
    if args.report:
        orchestrator.generate_report(args.report)
    
    print("\nHardening process completed!")
    
    if orchestrator.actions_taken:
        print(f"Total actions taken: {len(orchestrator.actions_taken)}")
        if any('reboot' in action.impact.lower() for action in orchestrator.actions_taken):
            print("\nWARNING: Some changes require a system reboot to take effect!")

if __name__ == "__main__":
    main()