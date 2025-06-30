#!/usr/bin/env python3
"""
Kaktus Enhanced Linux System Hardening Tool v2.0
Advanced automated security hardening for Linux distributions
Features: Compliance frameworks, advanced monitoring, intelligent risk assessment
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
import threading
import time
import hashlib
import sqlite3
import asyncio
import aiofiles
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any, Set
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from enum import Enum, IntEnum
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
import tempfile
import tarfile
import gzip
from collections import defaultdict, Counter
import socket
import psutil
import netifaces

# Version and metadata
TOOL_VERSION = "2.0.0"
TOOL_NAME = "Enhanced Linux Hardening Tool"
AUTHOR = "Security Team"
LICENSE = "GPL-3.0"

# Configuration paths
BASE_DIR = "/opt/linux-hardening-tool"
LOG_DIR = f"{BASE_DIR}/logs"
BACKUP_DIR = f"{BASE_DIR}/backups"
CONFIG_DIR = f"{BASE_DIR}/config"
PROFILE_DIR = f"{CONFIG_DIR}/profiles"
CACHE_DIR = f"{BASE_DIR}/cache"
REPORTS_DIR = f"{BASE_DIR}/reports"
DB_PATH = f"{BASE_DIR}/hardening.db"

# Compliance frameworks
COMPLIANCE_FRAMEWORKS = {
    'cis': 'Center for Internet Security',
    'nist': 'NIST Cybersecurity Framework',
    'pci_dss': 'PCI Data Security Standard',
    'stig': 'Security Technical Implementation Guide',
    'iso27001': 'ISO 27001',
    'sox': 'Sarbanes-Oxley Act',
    'hipaa': 'Health Insurance Portability and Accountability Act'
}

# Ensure Python 3.8+
if sys.version_info < (3, 8):
    print("Error: Python 3.8+ required")
    sys.exit(1)

class Priority(IntEnum):
    """Priority levels for hardening actions"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5

class Severity(Enum):
    """Severity levels for security findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ComplianceLevel(Enum):
    """Compliance requirement levels"""
    REQUIRED = "required"
    RECOMMENDED = "recommended"
    OPTIONAL = "optional"

class ActionStatus(Enum):
    """Status of hardening actions"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLBACK = "rollback"

class DistroType(Enum):
    """Supported Linux distributions"""
    RHEL = "rhel"
    CENTOS = "centos"
    FEDORA = "fedora"
    DEBIAN = "debian"
    UBUNTU = "ubuntu"
    SUSE = "suse"
    ARCH = "arch"
    ALPINE = "alpine"
    UNKNOWN = "unknown"

@dataclass
class SystemInfo:
    """Comprehensive system information"""
    hostname: str
    distro_type: DistroType
    distro_name: str
    distro_version: str
    kernel_version: str
    architecture: str
    cpu_count: int
    memory_total: int
    disk_usage: Dict[str, Dict]
    network_interfaces: List[Dict]
    running_services: List[str]
    installed_packages: List[str]
    users: List[Dict]
    open_ports: List[Dict]
    environment_variables: Dict[str, str]
    uptime_seconds: int
    load_average: Tuple[float, float, float]
    
    @classmethod
    def gather(cls) -> 'SystemInfo':
        """Gather comprehensive system information"""
        return cls(
            hostname=socket.gethostname(),
            distro_type=cls._detect_distro_type(),
            distro_name=cls._get_distro_name(),
            distro_version=cls._get_distro_version(),
            kernel_version=platform.release(),
            architecture=platform.machine(),
            cpu_count=psutil.cpu_count(),
            memory_total=psutil.virtual_memory().total,
            disk_usage=cls._get_disk_usage(),
            network_interfaces=cls._get_network_interfaces(),
            running_services=cls._get_running_services(),
            installed_packages=cls._get_installed_packages(),
            users=cls._get_users(),
            open_ports=cls._get_open_ports(),
            environment_variables=dict(os.environ),
            uptime_seconds=int(time.time() - psutil.boot_time()),
            load_average=os.getloadavg()
        )
    
    @staticmethod
    def _detect_distro_type() -> DistroType:
        """Detect Linux distribution type"""
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                
            if 'rhel' in content or 'red hat' in content:
                return DistroType.RHEL
            elif 'centos' in content:
                return DistroType.CENTOS
            elif 'fedora' in content:
                return DistroType.FEDORA
            elif 'debian' in content:
                return DistroType.DEBIAN
            elif 'ubuntu' in content:
                return DistroType.UBUNTU
            elif 'suse' in content or 'opensuse' in content:
                return DistroType.SUSE
            elif 'arch' in content:
                return DistroType.ARCH
            elif 'alpine' in content:
                return DistroType.ALPINE
        except:
            pass
        
        return DistroType.UNKNOWN
    
    @staticmethod
    def _get_distro_name() -> str:
        """Get distribution name"""
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('NAME='):
                        return line.split('=', 1)[1].strip().strip('"')
        except:
            pass
        return "Unknown"
    
    @staticmethod
    def _get_distro_version() -> str:
        """Get distribution version"""
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('VERSION_ID='):
                        return line.split('=', 1)[1].strip().strip('"')
        except:
            pass
        return "Unknown"
    
    @staticmethod
    def _get_disk_usage() -> Dict[str, Dict]:
        """Get disk usage information"""
        disk_usage = {}
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_usage[partition.mountpoint] = {
                    'device': partition.device,
                    'fstype': partition.fstype,
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free,
                    'percent': (usage.used / usage.total) * 100
                }
            except:
                continue
        return disk_usage
    
    @staticmethod
    def _get_network_interfaces() -> List[Dict]:
        """Get network interface information"""
        interfaces = []
        for interface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(interface)
                interface_info = {'name': interface, 'addresses': {}}
                
                for family, addresses in addrs.items():
                    family_name = {
                        netifaces.AF_INET: 'ipv4',
                        netifaces.AF_INET6: 'ipv6',
                        netifaces.AF_LINK: 'mac'
                    }.get(family, f'family_{family}')
                    
                    interface_info['addresses'][family_name] = addresses
                
                interfaces.append(interface_info)
            except:
                continue
        return interfaces
    
    @staticmethod
    def _get_running_services() -> List[str]:
        """Get list of running services"""
        services = []
        try:
            result = subprocess.run(
                ['systemctl', 'list-units', '--type=service', '--state=running', 
                 '--no-pager', '--no-legend'], 
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        service_name = line.split()[0]
                        services.append(service_name)
        except:
            pass
        return services
    
    @staticmethod
    def _get_installed_packages() -> List[str]:
        """Get list of installed packages"""
        packages = []
        distro_type = SystemInfo._detect_distro_type()
        
        try:
            if distro_type in [DistroType.RHEL, DistroType.CENTOS, DistroType.FEDORA]:
                result = subprocess.run(['rpm', '-qa', '--qf', '%{NAME}\n'], 
                                      capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    packages = result.stdout.strip().split('\n')
            elif distro_type in [DistroType.DEBIAN, DistroType.UBUNTU]:
                result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.startswith('ii'):
                            parts = line.split()
                            if len(parts) >= 2:
                                packages.append(parts[1])
        except:
            pass
        
        return packages
    
    @staticmethod
    def _get_users() -> List[Dict]:
        """Get system users information"""
        users = []
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    fields = line.strip().split(':')
                    if len(fields) >= 7:
                        users.append({
                            'username': fields[0],
                            'uid': int(fields[2]),
                            'gid': int(fields[3]),
                            'home': fields[5],
                            'shell': fields[6]
                        })
        except:
            pass
        return users
    
    @staticmethod
    def _get_open_ports() -> List[Dict]:
        """Get open network ports"""
        ports = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_LISTEN and conn.laddr:
                    ports.append({
                        'port': conn.laddr.port,
                        'address': conn.laddr.ip,
                        'family': 'tcp' if conn.type == socket.SOCK_STREAM else 'udp',
                        'pid': conn.pid
                    })
        except:
            pass
        return ports

@dataclass
class ComplianceMapping:
    """Maps security controls to compliance frameworks"""
    framework: str
    control_id: str
    title: str
    description: str
    level: ComplianceLevel
    
@dataclass
class SecurityFinding:
    """Enhanced security finding with compliance mapping"""
    id: str
    module: str
    check: str
    title: str
    description: str
    severity: Severity
    priority: Priority
    status: str
    current_value: Optional[str] = None
    expected_value: Optional[str] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    compliance_mappings: List[ComplianceMapping] = field(default_factory=list)
    technical_details: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    exploitability: float = 0.0
    impact_score: float = 0.0
    
    def calculate_risk_score(self) -> float:
        """Calculate CVSS-like risk score"""
        severity_weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 0.0
        }
        
        base_score = severity_weights.get(self.severity, 0.0)
        self.risk_score = min(10.0, base_score * (1 + self.exploitability * 0.3))
        return self.risk_score

@dataclass
class HardeningAction:
    """Enhanced hardening action with advanced features"""
    id: str
    module: str
    title: str
    description: str
    commands: List[List[str]]
    verification_commands: List[List[str]] = field(default_factory=list)
    rollback_commands: List[List[str]] = field(default_factory=list)
    files_modified: List[str] = field(default_factory=list)
    services_affected: List[str] = field(default_factory=list)
    packages_required: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    impact_description: str = ""
    estimated_duration: int = 0  # seconds
    requires_reboot: bool = False
    reversible: bool = True
    priority: Priority = Priority.MEDIUM
    status: ActionStatus = ActionStatus.PENDING
    compliance_mappings: List[ComplianceMapping] = field(default_factory=list)
    execution_log: List[str] = field(default_factory=list)
    start_time: Optional[datetime.datetime] = None
    end_time: Optional[datetime.datetime] = None

class DatabaseManager:
    """Enhanced database management for audit trails and history"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with comprehensive schema"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Audit runs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    hostname TEXT,
                    distro TEXT,
                    tool_version TEXT,
                    config_hash TEXT,
                    total_findings INTEGER,
                    critical_findings INTEGER,
                    high_findings INTEGER,
                    medium_findings INTEGER,
                    low_findings INTEGER,
                    duration_seconds INTEGER,
                    compliance_frameworks TEXT
                )
            ''')
            
            # Security findings table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_findings (
                    id TEXT PRIMARY KEY,
                    audit_run_id INTEGER,
                    module TEXT,
                    check_name TEXT,
                    title TEXT,
                    description TEXT,
                    severity TEXT,
                    priority INTEGER,
                    status TEXT,
                    current_value TEXT,
                    expected_value TEXT,
                    risk_score REAL,
                    compliance_frameworks TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (audit_run_id) REFERENCES audit_runs (id)
                )
            ''')
            
            # Hardening actions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hardening_actions (
                    id TEXT PRIMARY KEY,
                    audit_run_id INTEGER,
                    module TEXT,
                    title TEXT,
                    description TEXT,
                    status TEXT,
                    priority INTEGER,
                    start_time DATETIME,
                    end_time DATETIME,
                    duration_seconds INTEGER,
                    success BOOLEAN,
                    error_message TEXT,
                    files_modified TEXT,
                    services_affected TEXT,
                    requires_reboot BOOLEAN,
                    FOREIGN KEY (audit_run_id) REFERENCES audit_runs (id)
                )
            ''')
            
            # System snapshots table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    audit_run_id INTEGER,
                    snapshot_type TEXT,
                    file_path TEXT,
                    content_hash TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (audit_run_id) REFERENCES audit_runs (id)
                )
            ''')
            
            conn.commit()
    
    @contextmanager
    def get_connection(self):
        """Get database connection with proper cleanup"""
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()
    
    def create_audit_run(self, system_info: SystemInfo, config_hash: str, 
                        compliance_frameworks: List[str]) -> int:
        """Create new audit run record"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO audit_runs 
                (hostname, distro, tool_version, config_hash, compliance_frameworks)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                system_info.hostname,
                f"{system_info.distro_name} {system_info.distro_version}",
                TOOL_VERSION,
                config_hash,
                ','.join(compliance_frameworks)
            ))
            conn.commit()
            return cursor.lastrowid
    
    def update_audit_run(self, run_id: int, findings_summary: Dict, duration: int):
        """Update audit run with results"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE audit_runs SET
                total_findings = ?, critical_findings = ?, high_findings = ?,
                medium_findings = ?, low_findings = ?, duration_seconds = ?
                WHERE id = ?
            ''', (
                findings_summary.get('total', 0),
                findings_summary.get('critical', 0),
                findings_summary.get('high', 0),
                findings_summary.get('medium', 0),
                findings_summary.get('low', 0),
                duration,
                run_id
            ))
            conn.commit()
    
    def save_finding(self, run_id: int, finding: SecurityFinding):
        """Save security finding to database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO security_findings
                (id, audit_run_id, module, check_name, title, description, 
                 severity, priority, status, current_value, expected_value, 
                 risk_score, compliance_frameworks)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                finding.id, run_id, finding.module, finding.check, finding.title,
                finding.description, finding.severity.value, finding.priority.value,
                finding.status, finding.current_value, finding.expected_value,
                finding.risk_score, ','.join([m.framework for m in finding.compliance_mappings])
            ))
            conn.commit()
    
    def save_action(self, run_id: int, action: HardeningAction):
        """Save hardening action to database"""
        duration = 0
        if action.start_time and action.end_time:
            duration = int((action.end_time - action.start_time).total_seconds())
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO hardening_actions
                (id, audit_run_id, module, title, description, status, priority,
                 start_time, end_time, duration_seconds, success, 
                 files_modified, services_affected, requires_reboot)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                action.id, run_id, action.module, action.title, action.description,
                action.status.value, action.priority.value, action.start_time,
                action.end_time, duration, action.status == ActionStatus.SUCCESS,
                ','.join(action.files_modified), ','.join(action.services_affected),
                action.requires_reboot
            ))
            conn.commit()
    
    def get_audit_history(self, limit: int = 50) -> List[Dict]:
        """Get audit run history"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM audit_runs 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def get_trend_data(self, days: int = 30) -> Dict:
        """Get security trend data"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT 
                    DATE(timestamp) as date,
                    AVG(total_findings) as avg_findings,
                    AVG(critical_findings) as avg_critical,
                    AVG(high_findings) as avg_high
                FROM audit_runs 
                WHERE timestamp >= datetime('now', '-{} days')
                GROUP BY DATE(timestamp)
                ORDER BY date
            '''.format(days))
            
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]

class AdvancedBackupManager:
    """Enhanced backup management with compression and encryption"""
    
    def __init__(self, backup_dir: str = BACKUP_DIR):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.compression_level = 6
        self.max_backups = 50
    
    def create_backup(self, description: str, files: List[str] = None) -> str:
        """Create compressed backup with metadata"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_id = f"{timestamp}_{description.replace(' ', '_')[:50]}"
        backup_path = self.backup_dir / backup_id
        backup_path.mkdir(parents=True, exist_ok=True)
        
        metadata = {
            'backup_id': backup_id,
            'timestamp': timestamp,
            'description': description,
            'files': files or [],
            'system_info': asdict(SystemInfo.gather()),
            'tool_version': TOOL_VERSION
        }
        
        # Save metadata
        with open(backup_path / 'metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2, default=str)
        
        # Create compressed archive of files
        if files:
            self._create_file_archive(backup_path, files)
        
        # Create system state snapshot
        self._create_system_snapshot(backup_path)
        
        # Cleanup old backups
        self._cleanup_old_backups()
        
        logging.info(f"Created backup: {backup_id}")
        return backup_id
    
    def _create_file_archive(self, backup_path: Path, files: List[str]):
        """Create compressed archive of specified files"""
        archive_path = backup_path / 'files.tar.gz'
        
        with tarfile.open(archive_path, 'w:gz', compresslevel=self.compression_level) as tar:
            for file_path in files:
                if os.path.exists(file_path):
                    try:
                        tar.add(file_path, arcname=file_path.lstrip('/'))
                    except Exception as e:
                        logging.warning(f"Failed to backup {file_path}: {e}")
    
    def _create_system_snapshot(self, backup_path: Path):
        """Create snapshot of critical system files"""
        critical_files = [
            '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow',
            '/etc/hosts', '/etc/hostname', '/etc/resolv.conf',
            '/etc/ssh/sshd_config', '/etc/sudoers',
            '/etc/fstab', '/etc/crontab'
        ]
        
        snapshot_dir = backup_path / 'system_snapshot'
        snapshot_dir.mkdir(exist_ok=True)
        
        for file_path in critical_files:
            if os.path.exists(file_path):
                try:
                    dest_path = snapshot_dir / file_path.lstrip('/').replace('/', '_')
                    shutil.copy2(file_path, dest_path)
                except Exception as e:
                    logging.warning(f"Failed to snapshot {file_path}: {e}")
    
    def _cleanup_old_backups(self):
        """Remove old backups exceeding limit"""
        backups = sorted(self.backup_dir.iterdir(), 
                        key=lambda x: x.stat().st_mtime, reverse=True)
        
        for backup in backups[self.max_backups:]:
            if backup.is_dir():
                try:
                    shutil.rmtree(backup)
                    logging.info(f"Removed old backup: {backup.name}")
                except Exception as e:
                    logging.warning(f"Failed to remove backup {backup.name}: {e}")
    
    def restore_backup(self, backup_id: str) -> bool:
        """Restore from backup"""
        backup_path = self.backup_dir / backup_id
        if not backup_path.exists():
            logging.error(f"Backup not found: {backup_id}")
            return False
        
        try:
            # Load metadata
            with open(backup_path / 'metadata.json', 'r') as f:
                metadata = json.load(f)
            
            # Restore files from archive
            archive_path = backup_path / 'files.tar.gz'
            if archive_path.exists():
                with tarfile.open(archive_path, 'r:gz') as tar:
                    tar.extractall('/')
            
            # Restore system snapshot
            snapshot_dir = backup_path / 'system_snapshot'
            if snapshot_dir.exists():
                for snapshot_file in snapshot_dir.iterdir():
                    original_path = '/' + snapshot_file.name.replace('_', '/')
                    if os.path.exists(os.path.dirname(original_path)):
                        shutil.copy2(snapshot_file, original_path)
            
            logging.info(f"Restored backup: {backup_id}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to restore backup {backup_id}: {e}")
            return False
    
    def list_backups(self) -> List[Dict]:
        """List available backups with metadata"""
        backups = []
        for backup_dir in self.backup_dir.iterdir():
            if backup_dir.is_dir():
                metadata_file = backup_dir / 'metadata.json'
                if metadata_file.exists():
                    try:
                        with open(metadata_file, 'r') as f:
                            metadata = json.load(f)
                        backups.append(metadata)
                    except Exception as e:
                        logging.warning(f"Failed to read metadata for {backup_dir.name}: {e}")
        
        return sorted(backups, key=lambda x: x['timestamp'], reverse=True)

class BaseHardeningModule(ABC):
    """Enhanced base class for hardening modules"""
    
    def __init__(self, name: str, dry_run: bool = False, 
                 compliance_frameworks: List[str] = None):
        self.name = name
        self.dry_run = dry_run
        self.compliance_frameworks = compliance_frameworks or []
        self.findings: List[SecurityFinding] = []
        self.actions: List[HardeningAction] = []
        self.system_info = SystemInfo.gather()
        self.backup_manager = AdvancedBackupManager()
        
        # Performance monitoring
        self.start_time = None
        self.end_time = None
        
        # Thread safety
        self._lock = threading.Lock()
    
    @abstractmethod
    async def audit(self) -> List[SecurityFinding]:
        """Perform security audit (async)"""
        pass
    
    @abstractmethod
    async def harden(self) -> List[HardeningAction]:
        """Apply hardening configurations (async)"""
        pass
    
    def add_finding(self, finding: SecurityFinding):
        """Thread-safe finding addition"""
        with self._lock:
            self.findings.append(finding)
    
    def add_action(self, action: HardeningAction):
        """Thread-safe action addition"""
        with self._lock:
            self.actions.append(action)
    
    async def execute_command(self, command: List[str], timeout: int = 30, 
                            check: bool = True) -> Tuple[int, str, str]:
        """Execute command asynchronously"""
        if self.dry_run:
            logging.info(f"[DRY RUN] Would execute: {' '.join(command)}")
            return 0, "", ""
        
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
            
            return process.returncode, stdout.decode(), stderr.decode()
        except asyncio.TimeoutError:
            logging.error(f"Command timeout: {' '.join(command)}")
            return -1, "", "Command timeout"
        except Exception as e:
            logging.error(f"Command execution failed: {e}")
            return -1, "", str(e)
    
    def create_finding(self, check_id: str, title: str, description: str,
                      severity: Severity, status: str,
                      current_value: str = None, expected_value: str = None,
                      remediation: str = "", compliance_mappings: List[ComplianceMapping] = None) -> SecurityFinding:
        """Create standardized security finding"""
        priority_map = {
            Severity.CRITICAL: Priority.CRITICAL,
            Severity.HIGH: Priority.HIGH,
            Severity.MEDIUM: Priority.MEDIUM,
            Severity.LOW: Priority.LOW,
            Severity.INFO: Priority.INFO
        }
        
        finding = SecurityFinding(
            id=f"{self.name}_{check_id}",
            module=self.name,
            check=check_id,
            title=title,
            description=description,
            severity=severity,
            priority=priority_map.get(severity, Priority.MEDIUM),
            status=status,
            current_value=current_value,
            expected_value=expected_value,
            remediation=remediation,
            compliance_mappings=compliance_mappings or []
        )
        
        finding.calculate_risk_score()
        return finding
    
    def create_action(self, action_id: str, title: str, description: str,
                     commands: List[List[str]], impact_description: str = "",
                     verification_commands: List[List[str]] = None,
                     rollback_commands: List[List[str]] = None,
                     files_modified: List[str] = None,
                     services_affected: List[str] = None,
                     requires_reboot: bool = False,
                     priority: Priority = Priority.MEDIUM) -> HardeningAction:
        """Create standardized hardening action"""
        return HardeningAction(
            id=f"{self.name}_{action_id}",
            module=self.name,
            title=title,
            description=description,
            commands=commands,
            verification_commands=verification_commands or [],
            rollback_commands=rollback_commands or [],
            files_modified=files_modified or [],
            services_affected=services_affected or [],
            impact_description=impact_description,
            requires_reboot=requires_reboot,
            priority=priority
        )
    
    def get_compliance_mapping(self, framework: str, control_id: str, 
                              title: str, level: ComplianceLevel = ComplianceLevel.RECOMMENDED) -> ComplianceMapping:
        """Create compliance mapping"""
        return ComplianceMapping(
            framework=framework,
            control_id=control_id,
            title=title,
            description=f"{framework.upper()} {control_id}: {title}",
            level=level
        )

class AdvancedUserSecurityModule(BaseHardeningModule):
    """Enhanced user and authentication security module"""
    
    def __init__(self, dry_run: bool = False, compliance_frameworks: List[str] = None):
        super().__init__("user_security", dry_run, compliance_frameworks)
    
    async def audit(self) -> List[SecurityFinding]:
        """Comprehensive user security audit"""
        findings = []
        
        # Check for users with empty passwords
        findings.extend(await self._check_empty_passwords())
        
        # Check for users with UID 0
        findings.extend(await self._check_uid_zero())
        
        # Check password policies
        findings.extend(await self._check_password_policies())
        
        # Check account lockout policies
        findings.extend(await self._check_account_lockout())
        
        # Check for inactive accounts
        findings.extend(await self._check_inactive_accounts())
        
        # Check sudo configuration
        findings.extend(await self._check_sudo_config())
        
        # Check for shared accounts
        findings.extend(await self._check_shared_accounts())
        
        self.findings = findings
        return findings
    
    async def _check_empty_passwords(self) -> List[SecurityFinding]:
        """Check for users with empty passwords"""
        findings = []
        
        try:
            with open('/etc/shadow', 'r') as f:
                for line_num, line in enumerate(f, 1):
                    fields = line.strip().split(':')
                    if len(fields) >= 2:
                        username, password = fields[0], fields[1]
                        if password == '' or password == '*' or password == '!':
                            # Account disabled or no password - check if it should be
                            if username not in ['sync', 'shutdown', 'halt', 'daemon', 'bin']:
                                compliance_mappings = []
                                if 'cis' in self.compliance_frameworks:
                                    compliance_mappings.append(
                                        self.get_compliance_mapping('cis', '5.4.1.1', 
                                        'Ensure password expiration is 365 days or less', 
                                        ComplianceLevel.REQUIRED)
                                    )
                                
                                finding = self.create_finding(
                                    "empty_password",
                                    f"User {username} has empty/disabled password",
                                    f"User account {username} has an empty or disabled password field in /etc/shadow",
                                    Severity.HIGH if password == '' else Severity.MEDIUM,
                                    "FAIL",
                                    current_value=password or "empty",
                                    expected_value="encrypted_password",
                                    remediation=f"Set a strong password for {username} or disable the account if not needed",
                                    compliance_mappings=compliance_mappings
                                )
                                findings.append(finding)
        except PermissionError:
            finding = self.create_finding(
                "shadow_access",
                "Cannot access /etc/shadow",
                "Unable to read /etc/shadow file to check for empty passwords",
                Severity.HIGH,
                "ERROR",
                remediation="Run with sufficient privileges"
            )
            findings.append(finding)
        
        return findings
    
    async def _check_uid_zero(self) -> List[SecurityFinding]:
        """Check for non-root users with UID 0"""
        findings = []
        
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    fields = line.strip().split(':')
                    if len(fields) >= 3:
                        username, uid = fields[0], fields[2]
                        if uid == '0' and username != 'root':
                            compliance_mappings = []
                            if 'cis' in self.compliance_frameworks:
                                compliance_mappings.append(
                                    self.get_compliance_mapping('cis', '6.2.5', 
                                    'Ensure root is the only UID 0 account', 
                                    ComplianceLevel.REQUIRED)
                                )
                            
                            finding = self.create_finding(
                                "uid_zero_non_root",
                                f"Non-root user {username} has UID 0",
                                f"User {username} has root privileges (UID 0) which violates security principles",
                                Severity.CRITICAL,
                                "FAIL",
                                current_value=f"{username}:UID=0",
                                expected_value="Only root should have UID 0",
                                remediation=f"Change UID for {username} or remove the account",
                                compliance_mappings=compliance_mappings
                            )
                            findings.append(finding)
        except Exception as e:
            logging.error(f"Error checking UID 0: {e}")
        
        return findings
    
    async def _check_password_policies(self) -> List[SecurityFinding]:
        """Check password policy configuration"""
        findings = []
        
        # Check /etc/login.defs
        login_defs_checks = {
            'PASS_MAX_DAYS': (90, 'Maximum password age'),
            'PASS_MIN_DAYS': (7, 'Minimum password age'),
            'PASS_WARN_AGE': (14, 'Password warning age'),
            'PASS_MIN_LEN': (8, 'Minimum password length')
        }
        
        try:
            with open('/etc/login.defs', 'r') as f:
                content = f.read()
                
            for param, (expected, description) in login_defs_checks.items():
                pattern = rf'^{param}\s+(\d+)'
                match = re.search(pattern, content, re.MULTILINE)
                
                compliance_mappings = []
                if 'cis' in self.compliance_frameworks:
                    compliance_mappings.append(
                        self.get_compliance_mapping('cis', '5.4.1', 
                        'Ensure password expiration is configured', 
                        ComplianceLevel.REQUIRED)
                    )
                
                if match:
                    current_value = int(match.group(1))
                    if param == 'PASS_MAX_DAYS' and current_value > expected:
                        finding = self.create_finding(
                            f"password_policy_{param.lower()}",
                            f"Password maximum age too high",
                            f"{description} is set to {current_value} days, should be {expected} or less",
                            Severity.MEDIUM,
                            "FAIL",
                            current_value=str(current_value),
                            expected_value=f"<= {expected}",
                            remediation=f"Set {param} to {expected} in /etc/login.defs",
                            compliance_mappings=compliance_mappings
                        )
                        findings.append(finding)
                    elif param != 'PASS_MAX_DAYS' and current_value < expected:
                        finding = self.create_finding(
                            f"password_policy_{param.lower()}",
                            f"Password {description.lower()} too low",
                            f"{description} is set to {current_value}, should be {expected} or more",
                            Severity.MEDIUM,
                            "FAIL",
                            current_value=str(current_value),
                            expected_value=f">= {expected}",
                            remediation=f"Set {param} to {expected} in /etc/login.defs",
                            compliance_mappings=compliance_mappings
                        )
                        findings.append(finding)
                else:
                    finding = self.create_finding(
                        f"password_policy_{param.lower()}",
                        f"Password policy {param} not configured",
                        f"{description} is not configured in /etc/login.defs",
                        Severity.MEDIUM,
                        "FAIL",
                        current_value="not_set",
                        expected_value=str(expected),
                        remediation=f"Add {param} {expected} to /etc/login.defs",
                        compliance_mappings=compliance_mappings
                    )
                    findings.append(finding)
        
        except Exception as e:
            logging.error(f"Error checking password policies: {e}")
        
        return findings
    
    async def _check_account_lockout(self) -> List[SecurityFinding]:
        """Check account lockout policies"""
        findings = []
        
        # Check if pam_faillock or pam_tally2 is configured
        pam_files = ['/etc/pam.d/common-auth', '/etc/pam.d/system-auth', '/etc/pam.d/password-auth']
        
        lockout_configured = False
        for pam_file in pam_files:
            if os.path.exists(pam_file):
                try:
                    with open(pam_file, 'r') as f:
                        content = f.read()
                        if 'pam_faillock' in content or 'pam_tally2' in content:
                            lockout_configured = True
                            break
                except Exception:
                    continue
        
        if not lockout_configured:
            compliance_mappings = []
            if 'cis' in self.compliance_frameworks:
                compliance_mappings.append(
                    self.get_compliance_mapping('cis', '5.3.2', 
                    'Ensure lockout for failed password attempts is configured', 
                    ComplianceLevel.REQUIRED)
                )
            
            finding = self.create_finding(
                "account_lockout",
                "Account lockout policy not configured",
                "No account lockout mechanism (pam_faillock/pam_tally2) found in PAM configuration",
                Severity.HIGH,
                "FAIL",
                current_value="not_configured",
                expected_value="pam_faillock or pam_tally2 configured",
                remediation="Configure pam_faillock or pam_tally2 in PAM configuration",
                compliance_mappings=compliance_mappings
            )
            findings.append(finding)
        
        return findings
    
    async def _check_inactive_accounts(self) -> List[SecurityFinding]:
        """Check for inactive user accounts"""
        findings = []
        
        try:
            ret_code, output, _ = await self.execute_command(['lastlog'])
            if ret_code == 0:
                inactive_threshold = 90  # days
                current_time = time.time()
                
                for line in output.strip().split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 1:
                            username = parts[0]
                            if 'Never logged in' in line:
                                # Check if this is a system account
                                user_info = next((u for u in self.system_info.users if u['username'] == username), None)
                                if user_info and user_info['uid'] >= 1000:  # Regular user
                                    finding = self.create_finding(
                                        f"inactive_account_{username}",
                                        f"User {username} has never logged in",
                                        f"Regular user account {username} exists but has never been used",
                                        Severity.MEDIUM,
                                        "WARN",
                                        current_value="never_logged_in",
                                        expected_value="active_or_disabled",
                                        remediation=f"Review and disable {username} if not needed"
                                    )
                                    findings.append(finding)
        
        except Exception as e:
            logging.error(f"Error checking inactive accounts: {e}")
        
        return findings
    
    async def _check_sudo_config(self) -> List[SecurityFinding]:
        """Check sudo configuration security"""
        findings = []
        
        sudo_files = ['/etc/sudoers'] + list(Path('/etc/sudoers.d').glob('*')) if Path('/etc/sudoers.d').exists() else ['/etc/sudoers']
        
        for sudo_file in sudo_files:
            if os.path.exists(sudo_file):
                try:
                    with open(sudo_file, 'r') as f:
                        content = f.read()
                    
                    # Check for dangerous sudo rules
                    dangerous_patterns = [
                        (r'ALL\s*=\s*\(ALL\)\s*NOPASSWD:\s*ALL', 'Passwordless sudo to ALL commands'),
                        (r'%wheel\s*ALL=\(ALL\)\s*NOPASSWD:\s*ALL', 'Passwordless sudo for wheel group'),
                        (r'.*NOPASSWD:.*\/bin\/su', 'Passwordless sudo to su command')
                    ]
                    
                    for pattern, description in dangerous_patterns:
                        if re.search(pattern, content, re.MULTILINE):
                            compliance_mappings = []
                            if 'cis' in self.compliance_frameworks:
                                compliance_mappings.append(
                                    self.get_compliance_mapping('cis', '5.3.4', 
                                    'Ensure users must provide password for privilege escalation', 
                                    ComplianceLevel.REQUIRED)
                                )
                            
                            finding = self.create_finding(
                                "sudo_dangerous_rule",
                                f"Dangerous sudo rule in {sudo_file}",
                                f"{description} found in sudo configuration",
                                Severity.HIGH,
                                "FAIL",
                                current_value=description,
                                expected_value="password_required_sudo",
                                remediation=f"Review and restrict sudo rules in {sudo_file}",
                                compliance_mappings=compliance_mappings
                            )
                            findings.append(finding)
                
                except Exception as e:
                    logging.error(f"Error checking sudo config {sudo_file}: {e}")
        
        return findings
    
    async def _check_shared_accounts(self) -> List[SecurityFinding]:
        """Check for potential shared accounts"""
        findings = []
        
        # Look for accounts with generic names that might be shared
        shared_patterns = ['admin', 'test', 'temp', 'guest', 'shared', 'common', 'service']
        
        for user in self.system_info.users:
            username = user['username'].lower()
            if user['uid'] >= 1000:  # Regular user account
                for pattern in shared_patterns:
                    if pattern in username:
                        finding = self.create_finding(
                            f"potential_shared_account_{user['username']}",
                            f"Potential shared account: {user['username']}",
                            f"Account {user['username']} has a generic name suggesting it might be shared",
                            Severity.MEDIUM,
                            "WARN",
                            current_value=user['username'],
                            expected_value="individual_user_accounts",
                            remediation=f"Review {user['username']} - ensure it's for individual use only"
                        )
                        findings.append(finding)
                        break
        
        return findings
    
    async def harden(self) -> List[HardeningAction]:
        """Apply user security hardening"""
        actions = []
        
        # Configure password aging policies
        actions.append(await self._configure_password_policies())
        
        # Configure account lockout
        actions.append(await self._configure_account_lockout())
        
        # Disable unnecessary system accounts
        actions.extend(await self._disable_system_accounts())
        
        # Set secure umask
        actions.append(await self._set_secure_umask())
        
        # Configure sudo timeout
        actions.append(await self._configure_sudo_timeout())
        
        self.actions = [a for a in actions if a is not None]
        return self.actions
    
    async def _configure_password_policies(self) -> HardeningAction:
        """Configure secure password policies"""
        commands = [
            ['sed', '-i', 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/', '/etc/login.defs'],
            ['sed', '-i', 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/', '/etc/login.defs'],
            ['sed', '-i', 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/', '/etc/login.defs'],
            ['sed', '-i', 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 8/', '/etc/login.defs']
        ]
        
        verification_commands = [
            ['grep', 'PASS_MAX_DAYS', '/etc/login.defs'],
            ['grep', 'PASS_MIN_DAYS', '/etc/login.defs']
        ]
        
        return self.create_action(
            "password_policies",
            "Configure Password Aging Policies",
            "Set secure password aging policies in /etc/login.defs",
            commands,
            impact_description="Users will be required to change passwords within 90 days",
            verification_commands=verification_commands,
            files_modified=['/etc/login.defs'],
            priority=Priority.HIGH
        )
    
    async def _configure_account_lockout(self) -> HardeningAction:
        """Configure account lockout policies"""
        if self.system_info.distro_type in [DistroType.UBUNTU, DistroType.DEBIAN]:
            # Configure pam_faillock for Debian/Ubuntu
            commands = [
                ['apt-get', 'install', '-y', 'libpam-modules'],
            ]
            # Add pam_faillock configuration to common-auth
            pam_config = """
# Account lockout configuration
auth required pam_faillock.so preauth silent audit deny=3 unlock_time=600
auth [default=die] pam_faillock.so authfail audit deny=3 unlock_time=600
account required pam_faillock.so
"""
        else:
            # Configure for RHEL/CentOS/Fedora
            commands = [
                ['authconfig', '--enablefaillock', '--faillockargs="deny=3 unlock_time=600"', '--update']
            ]
        
        return self.create_action(
            "account_lockout",
            "Configure Account Lockout",
            "Configure account lockout after 3 failed login attempts",
            commands,
            impact_description="Accounts will be locked for 10 minutes after 3 failed login attempts",
            files_modified=['/etc/pam.d/common-auth', '/etc/pam.d/system-auth'],
            priority=Priority.HIGH
        )
    
    async def _disable_system_accounts(self) -> List[HardeningAction]:
        """Disable unnecessary system accounts"""
        actions = []
        system_accounts = ['bin', 'daemon', 'adm', 'lp', 'sync', 'shutdown', 'halt', 
                          'mail', 'operator', 'games', 'ftp', 'nobody', 'dbus']
        
        for account in system_accounts:
            # Check if account exists and is not already disabled
            user_exists = any(u['username'] == account for u in self.system_info.users)
            if user_exists:
                commands = [
                    ['usermod', '-L', '-s', '/sbin/nologin', account]
                ]
                
                rollback_commands = [
                    ['usermod', '-U', account]
                ]
                
                action = self.create_action(
                    f"disable_account_{account}",
                    f"Disable System Account: {account}",
                    f"Lock system account {account} and set shell to nologin",
                    commands,
                    impact_description=f"Account {account} will be unable to login",
                    rollback_commands=rollback_commands,
                    priority=Priority.MEDIUM
                )
                actions.append(action)
        
        return actions
    
    async def _set_secure_umask(self) -> HardeningAction:
        """Set secure default umask"""
        umask_config = "\n# Security hardening - Secure umask\numask 027\n"
        
        commands = [
            ['sh', '-c', f'echo "{umask_config}" >> /etc/profile'],
            ['sh', '-c', f'echo "{umask_config}" >> /etc/bash.bashrc']
        ]
        
        return self.create_action(
            "secure_umask",
            "Set Secure Default Umask",
            "Configure umask 027 for more restrictive default file permissions",
            commands,
            impact_description="New files will have more restrictive permissions (750 for directories, 640 for files)",
            files_modified=['/etc/profile', '/etc/bash.bashrc'],
            priority=Priority.MEDIUM
        )
    
    async def _configure_sudo_timeout(self) -> HardeningAction:
        """Configure sudo timeout"""
        sudo_config = "\n# Security hardening - Sudo timeout\nDefaults timestamp_timeout=5\nDefaults passwd_timeout=1\n"
        
        commands = [
            ['sh', '-c', f'echo "{sudo_config}" > /etc/sudoers.d/security-timeout'],
            ['chmod', '440', '/etc/sudoers.d/security-timeout']
        ]
        
        verification_commands = [
            ['visudo', '-c']  # Check sudo configuration syntax
        ]
        
        return self.create_action(
            "sudo_timeout",
            "Configure Sudo Timeout",
            "Set sudo timeout to 5 minutes and password timeout to 1 minute",
            commands,
            impact_description="Sudo credentials will expire after 5 minutes of inactivity",
            verification_commands=verification_commands,
            files_modified=['/etc/sudoers.d/security-timeout'],
            priority=Priority.MEDIUM
        )

class AdvancedSSHHardeningModule(BaseHardeningModule):
    """Enhanced SSH security hardening module"""
    
    def __init__(self, dry_run: bool = False, compliance_frameworks: List[str] = None):
        super().__init__("ssh_hardening", dry_run, compliance_frameworks)
        self.sshd_config_path = '/etc/ssh/sshd_config'
    
    async def audit(self) -> List[SecurityFinding]:
        """Comprehensive SSH security audit"""
        findings = []
        
        if not os.path.exists(self.sshd_config_path):
            finding = self.create_finding(
                "ssh_not_installed",
                "SSH server not installed",
                "OpenSSH server is not installed on this system",
                Severity.INFO,
                "SKIP",
                remediation="Install openssh-server if SSH access is needed"
            )
            findings.append(finding)
            return findings
        
        # Read SSH configuration
        try:
            with open(self.sshd_config_path, 'r') as f:
                ssh_config = f.read()
        except Exception as e:
            finding = self.create_finding(
                "ssh_config_read_error",
                "Cannot read SSH configuration",
                f"Failed to read {self.sshd_config_path}: {e}",
                Severity.HIGH,
                "ERROR",
                remediation="Check file permissions and run with appropriate privileges"
            )
            findings.append(finding)
            return findings
        
        # SSH security checks
        security_checks = {
            'Protocol': {
                'expected': '2',
                'severity': Severity.CRITICAL,
                'title': 'SSH Protocol Version',
                'description': 'SSH should use protocol version 2 only',
                'cis_control': '5.2.4'
            },
            'PermitRootLogin': {
                'expected': 'no',
                'severity': Severity.HIGH,
                'title': 'Root Login via SSH',
                'description': 'Root login via SSH should be disabled',
                'cis_control': '5.2.10'
            },
            'PasswordAuthentication': {
                'expected': 'no',
                'severity': Severity.MEDIUM,
                'title': 'Password Authentication',
                'description': 'SSH should use key-based authentication only',
                'cis_control': '5.2.11'
            },
            'PermitEmptyPasswords': {
                'expected': 'no',
                'severity': Severity.CRITICAL,
                'title': 'Empty Password Authentication',
                'description': 'Empty passwords should never be permitted',
                'cis_control': '5.2.12'
            },
            'X11Forwarding': {
                'expected': 'no',
                'severity': Severity.LOW,
                'title': 'X11 Forwarding',
                'description': 'X11 forwarding should be disabled unless needed',
                'cis_control': '5.2.6'
            },
            'MaxAuthTries': {
                'expected': '4',
                'severity': Severity.MEDIUM,
                'title': 'SSH Authentication Attempts',
                'description': 'Limit SSH authentication attempts',
                'cis_control': '5.2.5',
                'comparison': 'lte'
            },
            'ClientAliveInterval': {
                'expected': '300',
                'severity': Severity.LOW,
                'title': 'SSH Client Timeout',
                'description': 'Configure SSH client timeout',
                'cis_control': '5.2.13'
            },
            'ClientAliveCountMax': {
                'expected': '0',
                'severity': Severity.LOW,
                'title': 'SSH Client Alive Count',
                'description': 'Set SSH client alive count maximum',
                'cis_control': '5.2.13'
            },
            'LoginGraceTime': {
                'expected': '60',
                'severity': Severity.MEDIUM,
                'title': 'SSH Login Grace Time',
                'description': 'Set SSH login grace time',
                'cis_control': '5.2.14',
                'comparison': 'lte'
            },
            'Banner': {
                'expected': '/etc/issue.net',
                'severity': Severity.LOW,
                'title': 'SSH Login Banner',
                'description': 'Display warning banner before SSH login',
                'cis_control': '5.2.15'
            }
        }
        
        for param, check_info in security_checks.items():
            finding = await self._check_ssh_parameter(ssh_config, param, check_info)
            if finding:
                findings.append(finding)
        
        # Check for weak ciphers and algorithms
        findings.extend(await self._check_crypto_algorithms(ssh_config))
        
        # Check SSH key permissions
        findings.extend(await self._check_ssh_key_permissions())
        
        # Check for SSH user restrictions
        findings.extend(await self._check_ssh_user_restrictions(ssh_config))
        
        self.findings = findings
        return findings
    
    async def _check_ssh_parameter(self, config: str, param: str, check_info: Dict) -> Optional[SecurityFinding]:
        """Check individual SSH parameter"""
        pattern = rf'^{param}\s+(.+)$'
        match = re.search(pattern, config, re.MULTILINE | re.IGNORECASE)
        
        compliance_mappings = []
        if 'cis' in self.compliance_frameworks and 'cis_control' in check_info:
            compliance_mappings.append(
                self.get_compliance_mapping('cis', check_info['cis_control'], 
                check_info['title'], ComplianceLevel.REQUIRED)
            )
        
        if match:
            current_value = match.group(1).strip()
            expected = check_info['expected']
            comparison = check_info.get('comparison', 'eq')
            
            # Handle different comparison types
            if comparison == 'eq' and current_value.lower() != expected.lower():
                return self.create_finding(
                    f"ssh_{param.lower()}",
                    f"SSH {check_info['title']} Misconfigured",
                    f"{check_info['description']} (current: {current_value}, expected: {expected})",
                    check_info['severity'],
                    "FAIL",
                    current_value=current_value,
                    expected_value=expected,
                    remediation=f"Set {param} {expected} in {self.sshd_config_path}",
                    compliance_mappings=compliance_mappings
                )
            elif comparison == 'lte':
                try:
                    if int(current_value) > int(expected):
                        return self.create_finding(
                            f"ssh_{param.lower()}",
                            f"SSH {check_info['title']} Too High",
                            f"{check_info['description']} (current: {current_value}, should be <= {expected})",
                            check_info['severity'],
                            "FAIL",
                            current_value=current_value,
                            expected_value=f"<= {expected}",
                            remediation=f"Set {param} {expected} in {self.sshd_config_path}",
                            compliance_mappings=compliance_mappings
                        )
                except ValueError:
                    pass
        else:
            # Parameter not found
            return self.create_finding(
                f"ssh_{param.lower()}_missing",
                f"SSH {check_info['title']} Not Configured",
                f"{check_info['description']} - {param} not found in configuration",
                check_info['severity'],
                "FAIL",
                current_value="not_configured",
                expected_value=expected,
                remediation=f"Add {param} {expected} to {self.sshd_config_path}",
                compliance_mappings=compliance_mappings
            )
        
        return None
    
    async def _check_crypto_algorithms(self, config: str) -> List[SecurityFinding]:
        """Check for weak cryptographic algorithms"""
        findings = []
        
        # Weak ciphers to avoid
        weak_ciphers = ['3des-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'arcfour', 'arcfour128', 'arcfour256', 'blowfish-cbc', 'cast128-cbc', 'rijndael-cbc@lysator.liu.se']
        
        # Check configured ciphers
        cipher_match = re.search(r'^Ciphers\s+(.+)$', config, re.MULTILINE | re.IGNORECASE)
        if cipher_match:
            configured_ciphers = [c.strip() for c in cipher_match.group(1).split(',')]
            weak_found = [c for c in configured_ciphers if c in weak_ciphers]
            
            if weak_found:
                finding = self.create_finding(
                    "ssh_weak_ciphers",
                    "Weak SSH Ciphers Configured",
                    f"Weak encryption ciphers are configured: {', '.join(weak_found)}",
                    Severity.HIGH,
                    "FAIL",
                    current_value=', '.join(weak_found),
                    expected_value="Strong ciphers only (AES-CTR, ChaCha20)",
                    remediation="Configure only strong ciphers: aes128-ctr,aes192-ctr,aes256-ctr,chacha20-poly1305@openssh.com"
                )
                findings.append(finding)
        else:
            # No ciphers specified - using defaults which may be weak
            finding = self.create_finding(
                "ssh_ciphers_not_specified",
                "SSH Ciphers Not Explicitly Configured",
                "SSH ciphers not explicitly configured, may be using weak defaults",
                Severity.MEDIUM,
                "WARN",
                current_value="default_ciphers",
                expected_value="explicitly_configured_strong_ciphers",
                remediation="Explicitly configure strong ciphers in SSH configuration"
            )
            findings.append(finding)
        
        # Check MACs
        weak_macs = ['hmac-md5', 'hmac-md5-96', 'hmac-sha1', 'hmac-sha1-96']
        mac_match = re.search(r'^MACs\s+(.+)$', config, re.MULTILINE | re.IGNORECASE)
        if mac_match:
            configured_macs = [m.strip() for m in mac_match.group(1).split(',')]
            weak_macs_found = [m for m in configured_macs if m in weak_macs]
            
            if weak_macs_found:
                finding = self.create_finding(
                    "ssh_weak_macs",
                    "Weak SSH MACs Configured",
                    f"Weak MAC algorithms are configured: {', '.join(weak_macs_found)}",
                    Severity.MEDIUM,
                    "FAIL",
                    current_value=', '.join(weak_macs_found),
                    expected_value="Strong MACs only (SHA-256, SHA-512)",
                    remediation="Configure only strong MACs: hmac-sha2-256,hmac-sha2-512"
                )
                findings.append(finding)
        
        return findings
    
    async def _check_ssh_key_permissions(self) -> List[SecurityFinding]:
        """Check SSH key file permissions"""
        findings = []
        
        ssh_key_files = [
            ('/etc/ssh/ssh_host_rsa_key', '600', 'SSH RSA host private key'),
            ('/etc/ssh/ssh_host_rsa_key.pub', '644', 'SSH RSA host public key'),
            ('/etc/ssh/ssh_host_dsa_key', '600', 'SSH DSA host private key'),
            ('/etc/ssh/ssh_host_dsa_key.pub', '644', 'SSH DSA host public key'),
            ('/etc/ssh/ssh_host_ecdsa_key', '600', 'SSH ECDSA host private key'),
            ('/etc/ssh/ssh_host_ecdsa_key.pub', '644', 'SSH ECDSA host public key'),
            ('/etc/ssh/ssh_host_ed25519_key', '600', 'SSH Ed25519 host private key'),
            ('/etc/ssh/ssh_host_ed25519_key.pub', '644', 'SSH Ed25519 host public key'),
        ]
        
        for key_file, expected_perms, description in ssh_key_files:
            if os.path.exists(key_file):
                try:
                    stat_info = os.stat(key_file)
                    current_perms = oct(stat_info.st_mode)[-3:]
                    
                    if current_perms != expected_perms:
                        severity = Severity.HIGH if expected_perms == '600' else Severity.MEDIUM
                        finding = self.create_finding(
                            f"ssh_key_perms_{os.path.basename(key_file)}",
                            f"Incorrect SSH Key Permissions: {key_file}",
                            f"{description} has permissions {current_perms}, should be {expected_perms}",
                            severity,
                            "FAIL",
                            current_value=current_perms,
                            expected_value=expected_perms,
                            remediation=f"chmod {expected_perms} {key_file}"
                        )
                        findings.append(finding)
                
                except Exception as e:
                    logging.error(f"Error checking {key_file} permissions: {e}")
        
        return findings
    
    async def _check_ssh_user_restrictions(self, config: str) -> List[SecurityFinding]:
        """Check SSH user access restrictions"""
        findings = []
        
        # Check if AllowUsers or AllowGroups is configured
        allow_users = re.search(r'^AllowUsers\s+(.+)$', config, re.MULTILINE | re.IGNORECASE)
        allow_groups = re.search(r'^AllowGroups\s+(.+)$', config, re.MULTILINE | re.IGNORECASE)
        deny_users = re.search(r'^DenyUsers\s+(.+)$', config, re.MULTILINE | re.IGNORECASE)
        deny_groups = re.search(r'^DenyGroups\s+(.+)$', config, re.MULTILINE | re.IGNORECASE)

        if not any([allow_users, allow_groups, deny_users, deny_groups]):
            finding = self.create_finding(
                "ssh_no_user_restrictions",
                "No SSH User Access Restrictions",
                "SSH does not have user or group access restrictions configured",
                Severity.MEDIUM,
                "WARN",
                current_value="no_restrictions",
                expected_value="AllowUsers, AllowGroups, DenyUsers, or DenyGroups configured",
                remediation="Configure SSH user access restrictions using AllowUsers or AllowGroups"
            )
            findings.append(finding)
        
        return findings
    
    async def harden(self) -> List[HardeningAction]:
        """Apply SSH hardening configurations"""
        actions = []
        
        if not os.path.exists(self.sshd_config_path):
            return actions
        
        # Backup SSH configuration
        backup_id = self.backup_manager.create_backup("ssh_hardening", [self.sshd_config_path])
        
        # Apply SSH hardening
        actions.append(await self._harden_ssh_config())
        actions.append(await self._configure_ssh_banner())
        actions.append(await self._fix_ssh_key_permissions())
        actions.append(await self._configure_ssh_logging())
        
        # Restart SSH service
        actions.append(await self._restart_ssh_service())
        
        self.actions = [a for a in actions if a is not None]
        return self.actions
    
    async def _harden_ssh_config(self) -> HardeningAction:
        """Apply comprehensive SSH hardening configuration"""
        
        ssh_hardening_config = """
# Enhanced SSH Security Configuration
# Generated by Linux Hardening Tool v2.0

# Protocol and Encryption
Protocol 2
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256

# Authentication
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
PubkeyAuthentication yes
AuthenticationMethods publickey

# Session Management
X11Forwarding no
MaxAuthTries 3
MaxSessions 2
MaxStartups 2
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 0

# Logging and Monitoring
LogLevel INFO
SyslogFacility AUTH

# File Transfer
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no

# Misc Security
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
Banner /etc/issue.net
DebianBanner no
"""
        
        commands = [
            ['cp', self.sshd_config_path, f'{self.sshd_config_path}.backup'],
            ['sh', '-c', f'cat > {self.sshd_config_path} << "EOF"\n{ssh_hardening_config}\nEOF']
        ]
        
        verification_commands = [
            ['sshd', '-t'],  # Test SSH configuration
            ['systemctl', 'status', 'sshd']
        ]
        
        rollback_commands = [
            ['cp', f'{self.sshd_config_path}.backup', self.sshd_config_path],
            ['systemctl', 'restart', 'sshd']
        ]
        
        return self.create_action(
            "ssh_hardening_config",
            "Apply SSH Hardening Configuration",
            "Configure SSH with enhanced security settings including strong ciphers, disabled root login, and secure defaults",
            commands,
            impact_description="SSH will require key-based authentication, disable root login, and use strong encryption",
            verification_commands=verification_commands,
            rollback_commands=rollback_commands,
            files_modified=[self.sshd_config_path],
            services_affected=['sshd'],
            priority=Priority.HIGH
        )
    
    async def _configure_ssh_banner(self) -> HardeningAction:
        """Configure SSH warning banner"""
        banner_content = """
***********************************************************************
*                                                                     *
*   This system is for authorized users only. All activity on this   *
*   system is monitored and logged. Unauthorized access is           *
*   prohibited and will be prosecuted to the full extent of the law. *
*                                                                     *
***********************************************************************
"""
        
        commands = [
            ['sh', '-c', f'cat > /etc/issue.net << "EOF"\n{banner_content}\nEOF'],
            ['chmod', '644', '/etc/issue.net']
        ]
        
        return self.create_action(
            "ssh_banner",
            "Configure SSH Warning Banner",
            "Set up warning banner displayed before SSH login",
            commands,
            impact_description="Users will see a warning message before SSH login",
            files_modified=['/etc/issue.net'],
            priority=Priority.LOW
        )
    
    async def _fix_ssh_key_permissions(self) -> HardeningAction:
        """Fix SSH host key permissions"""
        commands = []
        
        # SSH key files and their correct permissions
        key_files = [
            ('/etc/ssh/ssh_host_rsa_key', '600'),
            ('/etc/ssh/ssh_host_rsa_key.pub', '644'),
            ('/etc/ssh/ssh_host_dsa_key', '600'),
            ('/etc/ssh/ssh_host_dsa_key.pub', '644'),
            ('/etc/ssh/ssh_host_ecdsa_key', '600'),
            ('/etc/ssh/ssh_host_ecdsa_key.pub', '644'),
            ('/etc/ssh/ssh_host_ed25519_key', '600'),
            ('/etc/ssh/ssh_host_ed25519_key.pub', '644'),
        ]
        
        files_modified = []
        for key_file, perms in key_files:
            if os.path.exists(key_file):
                commands.append(['chmod', perms, key_file])
                commands.append(['chown', 'root:root', key_file])
                files_modified.append(key_file)
        
        if not commands:
            return None
        
        return self.create_action(
            "ssh_key_permissions",
            "Fix SSH Host Key Permissions",
            "Set correct permissions on SSH host key files",
            commands,
            impact_description="SSH host keys will have secure permissions",
            files_modified=files_modified,
            priority=Priority.MEDIUM
        )
    
    async def _configure_ssh_logging(self) -> HardeningAction:
        """Configure enhanced SSH logging"""
        rsyslog_ssh_config = """
# Enhanced SSH logging configuration
$ModLoad imuxsock
$ModLoad imklog

# SSH specific logging
auth,authpriv.* /var/log/auth.log
daemon.info /var/log/ssh.log

# Separate SSH authentication failures
auth.warn /var/log/ssh-auth-failures.log
"""
        
        commands = [
            ['sh', '-c', f'cat > /etc/rsyslog.d/50-ssh.conf << "EOF"\n{rsyslog_ssh_config}\nEOF'],
            ['systemctl', 'restart', 'rsyslog']
        ]
        
        return self.create_action(
            "ssh_enhanced_logging",
            "Configure Enhanced SSH Logging",
            "Set up detailed SSH logging for security monitoring",
            commands,
            impact_description="SSH activities will be logged in detail for security analysis",
            files_modified=['/etc/rsyslog.d/50-ssh.conf'],
            services_affected=['rsyslog'],
            priority=Priority.MEDIUM
        )
    
    async def _restart_ssh_service(self) -> HardeningAction:
        """Restart SSH service to apply changes"""
        commands = [
            ['systemctl', 'restart', 'sshd']
        ]
        
        verification_commands = [
            ['systemctl', 'is-active', 'sshd'],
            ['ss', '-tulpn', '|', 'grep', ':22']
        ]
        
        return self.create_action(
            "restart_ssh",
            "Restart SSH Service",
            "Restart SSH service to apply configuration changes",
            commands,
            impact_description="SSH service will be restarted (brief interruption to SSH connections)",
            verification_commands=verification_commands,
            services_affected=['sshd'],
            priority=Priority.CRITICAL
        )

class AdvancedKernelHardeningModule(BaseHardeningModule):
    """Enhanced kernel and system hardening module"""
    
    def __init__(self, dry_run: bool = False, compliance_frameworks: List[str] = None):
        super().__init__("kernel_hardening", dry_run, compliance_frameworks)
        self.sysctl_config_file = '/etc/sysctl.d/99-hardening.conf'
    
    async def audit(self) -> List[SecurityFinding]:
        """Comprehensive kernel security audit"""
        findings = []
        
        # Network security parameters
        network_params = {
            'net.ipv4.ip_forward': {
                'expected': '0',
                'description': 'IP forwarding should be disabled',
                'severity': Severity.HIGH,
                'cis_control': '3.1.1'
            },
            'net.ipv4.conf.all.send_redirects': {
                'expected': '0',
                'description': 'ICMP redirects should not be sent',
                'severity': Severity.MEDIUM,
                'cis_control': '3.1.2'
            },
            'net.ipv4.conf.default.send_redirects': {
                'expected': '0',
                'description': 'ICMP redirects should not be sent (default)',
                'severity': Severity.MEDIUM,
                'cis_control': '3.1.2'
            },
            'net.ipv4.conf.all.accept_source_route': {
                'expected': '0',
                'description': 'Source routed packets should be rejected',
                'severity': Severity.HIGH,
                'cis_control': '3.2.1'
            },
            'net.ipv4.conf.all.accept_redirects': {
                'expected': '0',
                'description': 'ICMP redirects should not be accepted',
                'severity': Severity.MEDIUM,
                'cis_control': '3.2.2'
            },
            'net.ipv4.conf.all.secure_redirects': {
                'expected': '0',
                'description': 'Secure ICMP redirects should not be accepted',
                'severity': Severity.MEDIUM,
                'cis_control': '3.2.3'
            },
            'net.ipv4.conf.all.log_martians': {
                'expected': '1',
                'description': 'Suspicious packets should be logged',
                'severity': Severity.LOW,
                'cis_control': '3.2.4'
            },
            'net.ipv4.icmp_echo_ignore_broadcasts': {
                'expected': '1',
                'description': 'Broadcast ICMP requests should be ignored',
                'severity': Severity.MEDIUM,
                'cis_control': '3.2.5'
            },
            'net.ipv4.icmp_ignore_bogus_error_responses': {
                'expected': '1',
                'description': 'Bogus ICMP responses should be ignored',
                'severity': Severity.LOW,
                'cis_control': '3.2.6'
            },
            'net.ipv4.conf.all.rp_filter': {
                'expected': '1',
                'description': 'Reverse path filtering should be enabled',
                'severity': Severity.MEDIUM,
                'cis_control': '3.2.7'
            },
            'net.ipv4.tcp_syncookies': {
                'expected': '1',
                'description': 'TCP SYN cookies should be enabled',
                'severity': Severity.HIGH,
                'cis_control': '3.2.8'
            }
        }
        
        # Kernel security parameters
        kernel_params = {
            'kernel.randomize_va_space': {
                'expected': '2',
                'description': 'Address Space Layout Randomization should be enabled',
                'severity': Severity.HIGH,
                'cis_control': '1.5.3'
            },
            'kernel.dmesg_restrict': {
                'expected': '1',
                'description': 'Access to kernel logs should be restricted',
                'severity': Severity.MEDIUM,
                'cis_control': '1.5.1'
            },
            'kernel.kptr_restrict': {
                'expected': '2',
                'description': 'Kernel pointer addresses should be hidden',
                'severity': Severity.MEDIUM,
                'cis_control': '1.5.2'
            },
            'kernel.yama.ptrace_scope': {
                'expected': '1',
                'description': 'Ptrace should be restricted',
                'severity': Severity.MEDIUM,
                'cis_control': '1.5.4'
            },
            'kernel.kexec_load_disabled': {
                'expected': '1',
                'description': 'Kexec should be disabled',
                'severity': Severity.HIGH,
                'cis_control': '1.5.5'
            },
            'kernel.sysrq': {
                'expected': '0',
                'description': 'Magic SysRq key should be disabled',
                'severity': Severity.MEDIUM,
                'cis_control': '1.5.6'
            },
            'fs.suid_dumpable': {
                'expected': '0',
                'description': 'Core dumps of SUID programs should be disabled',
                'severity': Severity.HIGH,
                'cis_control': '1.5.7'
            }
        }
        
        all_params = {**network_params, **kernel_params}
        
        for param, param_info in all_params.items():
            finding = await self._check_kernel_parameter(param, param_info)
            if finding:
                findings.append(finding)
        
        # Check for loaded kernel modules
        findings.extend(await self._check_kernel_modules())
        
        # Check core dump configuration
        findings.extend(await self._check_core_dumps())
        
        self.findings = findings
        return findings
    
    async def _check_kernel_parameter(self, param: str, param_info: Dict) -> Optional[SecurityFinding]:
        """Check individual kernel parameter"""
        ret_code, output, _ = await self.execute_command(['sysctl', param])
        
        compliance_mappings = []
        if 'cis' in self.compliance_frameworks and 'cis_control' in param_info:
            compliance_mappings.append(
                self.get_compliance_mapping('cis', param_info['cis_control'], 
                param_info['description'], ComplianceLevel.REQUIRED)
            )
        
        if ret_code == 0:
            current_value = output.strip().split('=')[1].strip()
            expected_value = param_info['expected']
            
            if current_value != expected_value:
                return self.create_finding(
                    f"kernel_param_{param.replace('.', '_')}",
                    f"Kernel Parameter {param} Misconfigured",
                    f"{param_info['description']} (current: {current_value}, expected: {expected_value})",
                    param_info['severity'],
                    "FAIL",
                    current_value=current_value,
                    expected_value=expected_value,
                    remediation=f"Set {param} = {expected_value} in sysctl configuration",
                    compliance_mappings=compliance_mappings
                )
        else:
            return self.create_finding(
                f"kernel_param_{param.replace('.', '_')}_missing",
                f"Kernel Parameter {param} Not Available",
                f"Unable to read kernel parameter {param}",
                Severity.MEDIUM,
                "ERROR",
                current_value="unavailable",
                expected_value=param_info['expected'],
                remediation=f"Ensure kernel supports {param} or update kernel",
                compliance_mappings=compliance_mappings
            )
        
        return None
    
    async def _check_kernel_modules(self) -> List[SecurityFinding]:
        """Check for potentially dangerous kernel modules"""
        findings = []
        
        # Modules that should typically be blacklisted
        dangerous_modules = [
            'dccp', 'sctp', 'rds', 'tipc',  # Network protocols
            'cramfs', 'freevxfs', 'jffs2', 'hfs', 'hfsplus', 'squashfs', 'udf',  # Filesystems
            'usb-storage', 'firewire-core', 'bluetooth'  # Hardware interfaces
        ]
        
        ret_code, output, _ = await self.execute_command(['lsmod'])
        if ret_code == 0:
            loaded_modules = [line.split()[0] for line in output.strip().split('\n')[1:]]
            
            for module in dangerous_modules:
                if module in loaded_modules:
                    finding = self.create_finding(
                        f"dangerous_module_{module}",
                        f"Potentially Dangerous Module Loaded: {module}",
                        f"Kernel module {module} is loaded and may present security risks",
                        Severity.MEDIUM,
                        "WARN",
                        current_value="loaded",
                        expected_value="blacklisted",
                        remediation=f"Consider blacklisting module {module} if not needed"
                    )
                    findings.append(finding)
        
        # Check if module loading is restricted
        ret_code, output, _ = await self.execute_command(['sysctl', 'kernel.modules_disabled'])
        if ret_code == 0:
            modules_disabled = output.strip().split('=')[1].strip()
            if modules_disabled != '1':
                finding = self.create_finding(
                    "kernel_modules_not_disabled",
                    "Kernel Module Loading Not Disabled",
                    "Kernel module loading is not disabled, allowing runtime module insertion",
                    Severity.MEDIUM,
                    "WARN",
                    current_value=modules_disabled,
                    expected_value="1",
                    remediation="Consider setting kernel.modules_disabled=1 after system initialization"
                )
                findings.append(finding)
        
        return findings
    
    async def _check_core_dumps(self) -> List[SecurityFinding]:
        """Check core dump configuration"""
        findings = []
        
        # Check systemd core dump configuration
        if os.path.exists('/etc/systemd/coredump.conf'):
            try:
                with open('/etc/systemd/coredump.conf', 'r') as f:
                    coredump_config = f.read()
                
                # Check if core dumps are disabled
                if 'Storage=none' not in coredump_config:
                    finding = self.create_finding(
                        "coredump_storage_enabled",
                        "Core Dump Storage Enabled",
                        "Core dumps are stored on disk, potentially exposing sensitive information",
                        Severity.MEDIUM,
                        "WARN",
                        current_value="enabled",
                        expected_value="disabled",
                        remediation="Set Storage=none in /etc/systemd/coredump.conf"
                    )
                    findings.append(finding)
                
                if 'ProcessSizeMax=0' not in coredump_config:
                    finding = self.create_finding(
                        "coredump_size_not_limited",
                        "Core Dump Size Not Limited",
                        "Core dump size is not limited, potentially consuming disk space",
                        Severity.LOW,
                        "WARN",
                        current_value="unlimited",
                        expected_value="0",
                        remediation="Set ProcessSizeMax=0 in /etc/systemd/coredump.conf"
                    )
                    findings.append(finding)
            
            except Exception as e:
                logging.error(f"Error checking core dump configuration: {e}")
        
        # Check ulimit core dump setting
        ret_code, output, _ = await self.execute_command(['ulimit', '-c'])
        if ret_code == 0 and output.strip() != '0':
            finding = self.create_finding(
                "ulimit_core_dumps_enabled",
                "Core Dumps Enabled via ulimit",
                "Core dumps are enabled via ulimit setting",
                Severity.MEDIUM,
                "WARN",
                current_value=output.strip(),
                expected_value="0",
                remediation="Set 'ulimit -c 0' in shell profiles and /etc/security/limits.conf"
            )
            findings.append(finding)
        
        return findings
    
    async def harden(self) -> List[HardeningAction]:
        """Apply kernel hardening configurations"""
        actions = []
        
        # Apply sysctl hardening
        actions.append(await self._apply_sysctl_hardening())
        
        # Configure module blacklisting
        actions.append(await self._configure_module_blacklist())
        
        # Disable core dumps
        actions.append(await self._disable_core_dumps())
        
        # Configure kernel parameters at boot
        actions.append(await self._configure_boot_parameters())
        
        self.actions = [a for a in actions if a is not None]
        return self.actions
    
    async def _apply_sysctl_hardening(self) -> HardeningAction:
        """Apply comprehensive sysctl hardening"""
        
        sysctl_config = """# Linux Hardening Tool v2.0 - Kernel Security Parameters
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
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0

# IPv6 Security (disable if not needed)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# Kernel Security
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.kexec_load_disabled = 1
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.ctrl-alt-del = 0

# File System Security
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# Memory and Process Security
vm.swappiness = 1
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.mmap_min_addr = 65536
kernel.pid_max = 65536

# Additional Hardening
net.core.bpf_jit_harden = 2
kernel.unprivileged_bpf_disabled = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 2048
"""
        
        commands = [
            ['sh', '-c', f'cat > {self.sysctl_config_file} << "EOF"\n{sysctl_config}\nEOF'],
            ['sysctl', '-p', self.sysctl_config_file],
            ['chmod', '644', self.sysctl_config_file]
        ]
        
        verification_commands = [
            ['sysctl', 'net.ipv4.ip_forward'],
            ['sysctl', 'kernel.randomize_va_space'],
            ['sysctl', 'fs.suid_dumpable']
        ]
        
        rollback_commands = [
            ['rm', '-f', self.sysctl_config_file],
            ['sysctl', '--system']
        ]
        
        return self.create_action(
            "sysctl_hardening",
            "Apply Kernel Security Parameters",
            "Configure comprehensive kernel security parameters via sysctl",
            commands,
            impact_description="Network security enhanced, ASLR enabled, kernel information restricted",
            verification_commands=verification_commands,
            rollback_commands=rollback_commands,
            files_modified=[self.sysctl_config_file],
            priority=Priority.HIGH
        )
    
    async def _configure_module_blacklist(self) -> HardeningAction:
        """Configure kernel module blacklisting"""
        
        blacklist_modules = [
            'dccp', 'sctp', 'rds', 'tipc',  # Network protocols
            'cramfs', 'freevxfs', 'jffs2', 'hfs', 'hfsplus', 'squashfs', 'udf',  # Filesystems
            'bluetooth', 'btusb',  # Bluetooth
            'firewire-core', 'firewire-ohci',  # Firewire
            'usb-storage'  # USB storage
        ]
        
        blacklist_config = "# Linux Hardening Tool - Module Blacklist\n"
        for module in blacklist_modules:
            blacklist_config += f"blacklist {module}\ninstall {module} /bin/true\n"
        
        commands = [
            ['sh', '-c', f'cat > /etc/modprobe.d/hardening-blacklist.conf << "EOF"\n{blacklist_config}\nEOF'],
            ['chmod', '644', '/etc/modprobe.d/hardening-blacklist.conf'],
            ['depmod', '-a']
        ]
        
        return self.create_action(
            "module_blacklist",
            "Blacklist Unnecessary Kernel Modules",
            "Prevent loading of potentially dangerous or unnecessary kernel modules",
            commands,
            impact_description="Specified kernel modules will be prevented from loading",
            files_modified=['/etc/modprobe.d/hardening-blacklist.conf'],
            priority=Priority.MEDIUM
        )
    
    async def _disable_core_dumps(self) -> HardeningAction:
        """Disable core dumps system-wide"""
        
        # Configure systemd coredump
        coredump_config = """[Coredump]
Storage=none
ProcessSizeMax=0
ExternalSizeMax=0
JournalSizeMax=0
MaxUse=0
"""
        
        # Configure limits
        limits_config = """
# Disable core dumps - Linux Hardening Tool
*               hard    core            0
*               soft    core            0
"""
        
        commands = [
            ['sh', '-c', f'cat > /etc/systemd/coredump.conf << "EOF"\n{coredump_config}\nEOF'],
            ['sh', '-c', f'echo "{limits_config}" >> /etc/security/limits.conf'],
            ['sh', '-c', 'echo "ulimit -c 0" >> /etc/profile'],
            ['systemctl', 'daemon-reload']
        ]
        
        return self.create_action(
            "disable_core_dumps",
            "Disable Core Dumps",
            "Disable core dumps system-wide to prevent information disclosure",
            commands,
            impact_description="Core dumps will be disabled, preventing potential information leakage",
            files_modified=['/etc/systemd/coredump.conf', '/etc/security/limits.conf', '/etc/profile'],
            priority=Priority.MEDIUM
        )
    
    async def _configure_boot_parameters(self) -> HardeningAction:
        """Configure secure kernel boot parameters"""
        
        # Add kernel parameters to GRUB configuration
        secure_boot_params = [
            'slab_nomerge',          # Prevent slab merging
            'slub_debug=P',          # Enable SLUB debugging
            'page_poison=1',         # Enable page poisoning
            'pti=on',                # Enable Kernel Page Table Isolation
            'vsyscall=none',         # Disable vsyscalls
            'debugfs=off',           # Disable debugfs
            'oops=panic',            # Panic on oops
            'module.sig_enforce=1',  # Enforce module signatures
            'lockdown=confidentiality'  # Enable kernel lockdown
        ]
        
        boot_params = ' '.join(secure_boot_params)
        
        commands = [
            ['cp', '/etc/default/grub', '/etc/default/grub.backup'],
            ['sed', '-i', f's/GRUB_CMDLINE_LINUX_DEFAULT="\\(.*\\)"/GRUB_CMDLINE_LINUX_DEFAULT="\\1 {boot_params}"/', '/etc/default/grub'],
            ['update-grub'] if self.system_info.distro_type in [DistroType.DEBIAN, DistroType.UBUNTU] else ['grub2-mkconfig', '-o', '/boot/grub2/grub.cfg']
        ]
        
        rollback_commands = [
            ['cp', '/etc/default/grub.backup', '/etc/default/grub'],
            ['update-grub'] if self.system_info.distro_type in [DistroType.DEBIAN, DistroType.UBUNTU] else ['grub2-mkconfig', '-o', '/boot/grub2/grub.cfg']
        ]
        
        return self.create_action(
            "secure_boot_params",
            "Configure Secure Kernel Boot Parameters",
            "Add security-focused kernel parameters to boot configuration",
            commands,
            impact_description="Additional kernel security features will be enabled at boot",
            rollback_commands=rollback_commands,
            files_modified=['/etc/default/grub'],
            requires_reboot=True,
            priority=Priority.HIGH
        )

class ComplianceEngine:
    """Advanced compliance framework engine"""
    
    def __init__(self, frameworks: List[str]):
        self.frameworks = frameworks
        self.control_mappings = self._load_control_mappings()
    
    def _load_control_mappings(self) -> Dict[str, Dict]:
        """Load compliance control mappings"""
        mappings = {
            'cis': {
                '1.1.1.1': {'title': 'Ensure mounting of cramfs filesystems is disabled', 'level': 1},
                '1.1.1.2': {'title': 'Ensure mounting of freevxfs filesystems is disabled', 'level': 1},
                '1.5.1': {'title': 'Ensure core dumps are restricted', 'level': 1},
                '1.5.3': {'title': 'Ensure address space layout randomization (ASLR) is enabled', 'level': 1},
                '3.1.1': {'title': 'Ensure IP forwarding is disabled', 'level': 1},
                '3.2.1': {'title': 'Ensure source routed packets are not accepted', 'level': 1},
                '5.2.4': {'title': 'Ensure SSH Protocol is set to 2', 'level': 1},
                '5.2.5': {'title': 'Ensure SSH LogLevel is appropriate', 'level': 1},
                '5.2.10': {'title': 'Ensure SSH root login is disabled', 'level': 1},
                '5.3.2': {'title': 'Ensure lockout for failed password attempts is configured', 'level': 1},
                '5.4.1': {'title': 'Ensure password expiration is 365 days or less', 'level': 1},
                '6.2.5': {'title': 'Ensure root is the only UID 0 account', 'level': 1}
            },
            'nist': {
                'AC-2': {'title': 'Account Management', 'family': 'Access Control'},
                'AC-3': {'title': 'Access Enforcement', 'family': 'Access Control'},
                'AU-2': {'title': 'Event Logging', 'family': 'Audit and Accountability'},
                'SC-5': {'title': 'Denial of Service Protection', 'family': 'System and Communications Protection'},
                'SC-7': {'title': 'Boundary Protection', 'family': 'System and Communications Protection'},
                'SI-2': {'title': 'Flaw Remediation', 'family': 'System and Information Integrity'}
            }
        }
        return mappings
    
    def get_control_mapping(self, framework: str, control_id: str) -> Optional[Dict]:
        """Get control mapping for framework"""
        return self.control_mappings.get(framework, {}).get(control_id)
    
    def generate_compliance_report(self, findings: List[SecurityFinding]) -> Dict:
        """Generate compliance assessment report"""
        report = {
            'frameworks': {},
            'overall_score': 0.0,
            'total_controls': 0,
            'passed_controls': 0,
            'failed_controls': 0
        }
        
        for framework in self.frameworks:
            framework_findings = [f for f in findings if any(m.framework == framework for m in f.compliance_mappings)]
            
            framework_report = {
                'total_findings': len(framework_findings),
                'critical_findings': len([f for f in framework_findings if f.severity == Severity.CRITICAL]),
                'high_findings': len([f for f in framework_findings if f.severity == Severity.HIGH]),
                'medium_findings': len([f for f in framework_findings if f.severity == Severity.MEDIUM]),
                'low_findings': len([f for f in framework_findings if f.severity == Severity.LOW]),
                'passed_controls': len([f for f in framework_findings if f.status == 'PASS']),
                'failed_controls': len([f for f in framework_findings if f.status == 'FAIL']),
                'compliance_score': 0.0
            }
            
            if framework_report['total_findings'] > 0:
                framework_report['compliance_score'] = (
                    framework_report['passed_controls'] / framework_report['total_findings']
                ) * 100
            
            report['frameworks'][framework] = framework_report
            report['total_controls'] += framework_report['total_findings']
            report['passed_controls'] += framework_report['passed_controls']
            report['failed_controls'] += framework_report['failed_controls']
        
        if report['total_controls'] > 0:
            report['overall_score'] = (report['passed_controls'] / report['total_controls']) * 100
        
        return report

class EnhancedReportGenerator:
    """Advanced report generation with multiple formats"""
    
    def __init__(self, output_dir: str = REPORTS_DIR):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_comprehensive_report(self, audit_results: List[SecurityFinding], 
                                    actions_taken: List[HardeningAction],
                                    system_info: SystemInfo,
                                    compliance_report: Dict = None) -> Dict[str, str]:
        """Generate comprehensive security report in multiple formats"""
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"security_report_{timestamp}"
        
        # Prepare report data
        report_data = {
            'metadata': {
                'tool_name': TOOL_NAME,
                'tool_version': TOOL_VERSION,
                'timestamp': datetime.datetime.now().isoformat(),
                'hostname': system_info.hostname,
                'distro': f"{system_info.distro_name} {system_info.distro_version}",
                'kernel': system_info.kernel_version,
                'architecture': system_info.architecture
            },
            'executive_summary': self._generate_executive_summary(audit_results, actions_taken),
            'system_information': asdict(system_info),
            'audit_results': [asdict(finding) for finding in audit_results],
            'hardening_actions': [asdict(action) for action in actions_taken],
            'compliance_assessment': compliance_report or {},
            'statistics': self._calculate_statistics(audit_results, actions_taken),
            'recommendations': self._generate_recommendations(audit_results)
        }
        
        # Generate reports in different formats
        generated_files = {}
        
        # JSON Report
        json_file = self.output_dir / f"{base_filename}.json"
        with open(json_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        generated_files['json'] = str(json_file)
        
        # HTML Report
        html_file = self.output_dir / f"{base_filename}.html"
        html_content = self._generate_html_report(report_data)
        with open(html_file, 'w') as f:
            f.write(html_content)
        generated_files['html'] = str(html_file)
        
        # CSV Summary
        csv_file = self.output_dir / f"{base_filename}_summary.csv"
        self._generate_csv_summary(audit_results, csv_file)
        generated_files['csv'] = str(csv_file)
        
        # Executive Summary (Text)
        txt_file = self.output_dir / f"{base_filename}_executive.txt"
        with open(txt_file, 'w') as f:
            f.write(self._generate_text_summary(report_data))
        generated_files['txt'] = str(txt_file)
        
        return generated_files
    
    def _generate_executive_summary(self, findings: List[SecurityFinding], 
                                  actions: List[HardeningAction]) -> Dict:
        """Generate executive summary"""
        severity_counts = Counter(f.severity.value for f in findings)
        status_counts = Counter(f.status for f in findings)
        action_counts = Counter(a.status.value for a in actions)
        
        critical_issues = [f for f in findings if f.severity == Severity.CRITICAL and f.status == 'FAIL']
        high_issues = [f for f in findings if f.severity == Severity.HIGH and f.status == 'FAIL']
        
        return {
            'total_findings': len(findings),
            'severity_breakdown': dict(severity_counts),
            'status_breakdown': dict(status_counts),
            'actions_taken': len(actions),
            'action_status': dict(action_counts),
            'security_posture': self._assess_security_posture(findings),
            'top_critical_issues': [f.title for f in critical_issues[:5]],
            'top_high_issues': [f.title for f in high_issues[:5]],
            'recommendations_count': len([f for f in findings if f.status == 'FAIL'])
        }
    
    def _assess_security_posture(self, findings: List[SecurityFinding]) -> str:
        """Assess overall security posture"""
        critical_count = len([f for f in findings if f.severity == Severity.CRITICAL and f.status == 'FAIL'])
        high_count = len([f for f in findings if f.severity == Severity.HIGH and f.status == 'FAIL'])
        total_failed = len([f for f in findings if f.status == 'FAIL'])
        total_findings = len(findings)
        
        if critical_count > 0:
            return "CRITICAL - Immediate attention required"
        elif high_count > 5:
            return "HIGH RISK - Multiple high-severity issues found"
        elif total_failed / total_findings > 0.5:
            return "MEDIUM RISK - Multiple security improvements needed"
        elif total_failed / total_findings > 0.2:
            return "LOW RISK - Some security improvements recommended"
        else:
            return "GOOD - Strong security posture"
    
    def _calculate_statistics(self, findings: List[SecurityFinding], 
                            actions: List[HardeningAction]) -> Dict:
        """Calculate detailed statistics"""
        return {
            'findings_by_module': dict(Counter(f.module for f in findings)),
            'severity_distribution': dict(Counter(f.severity.value for f in findings)),
            'actions_by_module': dict(Counter(a.module for a in actions)),
            'average_risk_score': sum(f.risk_score for f in findings) / len(findings) if findings else 0,
            'high_impact_actions': len([a for a in actions if a.priority in [Priority.CRITICAL, Priority.HIGH]]),
            'reboot_required': any(a.requires_reboot for a in actions),
            'files_modified': len(set().union(*[a.files_modified for a in actions])),
            'services_affected': len(set().union(*[a.services_affected for a in actions]))
        }
    
    def _generate_recommendations(self, findings: List[SecurityFinding]) -> List[Dict]:
        """Generate prioritized recommendations"""
        failed_findings = [f for f in findings if f.status == 'FAIL']
        
        # Sort by risk score and severity
        failed_findings.sort(key=lambda x: (x.priority.value, -x.risk_score))
        
        recommendations = []
        for finding in failed_findings[:20]:  # Top 20 recommendations
            recommendations.append({
                'priority': finding.priority.value,
                'title': finding.title,
                'description': finding.description,
                'remediation': finding.remediation,
                'risk_score': finding.risk_score,
                'module': finding.module
            })
        
        return recommendations
    
    def _generate_html_report(self, report_data: Dict) -> str:
        """Generate comprehensive HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux Security Hardening Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 40px; padding-bottom: 20px; border-bottom: 2px solid #e0e0e0; }}
        .header h1 {{ color: #2c3e50; margin: 0; font-size: 2.5em; }}
        .header .subtitle {{ color: #7f8c8d; font-size: 1.2em; margin-top: 10px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 40px; }}
        .summary-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }}
        .summary-card.critical {{ background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%); }}
        .summary-card.high {{ background: linear-gradient(135deg, #feca57 0%, #ff9ff3 100%); }}
        .summary-card.medium {{ background: linear-gradient(135deg, #48dbfb 0%, #0abde3 100%); }}
        .summary-card h3 {{ margin: 0 0 10px 0; font-size: 1.1em; }}
        .summary-card .value {{ font-size: 2.5em; font-weight: bold; }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        .findings-table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        .findings-table th, .findings-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        .findings-table th {{ background-color: #f8f9fa; font-weight: bold; }}
        .severity-critical {{ background-color: #ffebee; color: #c62828; }}
        .severity-high {{ background-color: #fff3e0; color: #ef6c00; }}
        .severity-medium {{ background-color: #e8f5e8; color: #2e7d32; }}
        .severity-low {{ background-color: #e3f2fd; color: #1565c0; }}
        .status-fail {{ background-color: #ffcdd2; color: #d32f2f; }}
        .status-pass {{ background-color: #c8e6c9; color: #388e3c; }}
        .status-warn {{ background-color: #ffe0b2; color: #f57c00; }}
        .chart-container {{ width: 100%; height: 300px; margin: 20px 0; }}
        .recommendation {{ background-color: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #3498db; border-radius: 5px; }}
        .recommendation h4 {{ margin: 0 0 10px 0; color: #2c3e50; }}
        .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #7f8c8d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Linux Security Hardening Report</h1>
            <div class="subtitle">Generated by {tool_name} v{tool_version}</div>
            <div class="subtitle">{timestamp}</div>
            <div class="subtitle">Host: {hostname} | OS: {distro}</div>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card critical">
                <h3>Critical Issues</h3>
                <div class="value">{critical_count}</div>
            </div>
            <div class="summary-card high">
                <h3>High Priority</h3>
                <div class="value">{high_count}</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium Priority</h3>
                <div class="value">{medium_count}</div>
            </div>
            <div class="summary-card">
                <h3>Security Score</h3>
                <div class="value">{security_score}%</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <p><strong>Security Posture:</strong> {security_posture}</p>
            <p><strong>Total Findings:</strong> {total_findings}</p>
            <p><strong>Actions Taken:</strong> {actions_taken}</p>
            <p><strong>Recommendations:</strong> {recommendations_count}</p>
        </div>
        
        <div class="section">
            <h2>Top Priority Recommendations</h2>
            {recommendations_html}
        </div>
        
        <div class="section">
            <h2>Detailed Findings</h2>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Module</th>
                        <th>Finding</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Risk Score</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows}
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Report generated by {tool_name} v{tool_version} on {timestamp}</p>
            <p>For more information, visit the tool documentation</p>
        </div>
    </div>
</body>
</html>
"""
        
        # Prepare template variables
        exec_summary = report_data['executive_summary']
        severity_counts = exec_summary['severity_breakdown']
        
        # Generate recommendations HTML
        recommendations_html = ""
        for rec in report_data['recommendations'][:10]:
            recommendations_html += f"""
            <div class="recommendation">
                <h4>{rec['title']}</h4>
                <p>{rec['description']}</p>
                <p><strong>Remediation:</strong> {rec['remediation']}</p>
                <p><strong>Risk Score:</strong> {rec['risk_score']:.1f} | <strong>Module:</strong> {rec['module']}</p>
            </div>
            """
        
        # Generate findings table rows
        findings_rows = ""
        for finding_data in report_data['audit_results'][:50]:  # Top 50 findings
            severity_class = f"severity-{finding_data['severity']}"
            status_class = f"status-{finding_data['status'].lower()}"
            findings_rows += f"""
            <tr>
                <td>{finding_data['module']}</td>
                <td class="{severity_class}">{finding_data['title']}</td>
                <td class="{severity_class}">{finding_data['severity'].upper()}</td>
                <td class="{status_class}">{finding_data['status']}</td>
                <td>{finding_data['risk_score']:.1f}</td>
            </tr>
            """
        
        # Calculate security score
        total_findings = exec_summary['total_findings']
        passed_findings = exec_summary['status_breakdown'].get('PASS', 0)
        security_score = int((passed_findings / total_findings * 100)) if total_findings > 0 else 100
        
        return html_template.format(
            tool_name=report_data['metadata']['tool_name'],
            tool_version=report_data['metadata']['tool_version'],
            timestamp=report_data['metadata']['timestamp'],
            hostname=report_data['metadata']['hostname'],
            distro=report_data['metadata']['distro'],
            critical_count=severity_counts.get('critical', 0),
            high_count=severity_counts.get('high', 0),
            medium_count=severity_counts.get('medium', 0),
            security_score=security_score,
            security_posture=exec_summary['security_posture'],
            total_findings=exec_summary['total_findings'],
            actions_taken=exec_summary['actions_taken'],
            recommendations_count=exec_summary['recommendations_count'],
            recommendations_html=recommendations_html,
            findings_rows=findings_rows
        )
    
    def _generate_csv_summary(self, findings: List[SecurityFinding], output_file: Path):
        """Generate CSV summary of findings"""
        import csv
        
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['Module', 'Check', 'Title', 'Severity', 'Status', 'Risk_Score', 
                         'Current_Value', 'Expected_Value', 'Remediation']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for finding in findings:
                writer.writerow({
                    'Module': finding.module,
                    'Check': finding.check,
                    'Title': finding.title,
                    'Severity': finding.severity.value,
                    'Status': finding.status,
                    'Risk_Score': f"{finding.risk_score:.1f}",
                    'Current_Value': finding.current_value or '',
                    'Expected_Value': finding.expected_value or '',
                    'Remediation': finding.remediation
                })
    
    def _generate_text_summary(self, report_data: Dict) -> str:
        """Generate executive text summary"""
        exec_summary = report_data['executive_summary']
        metadata = report_data['metadata']
        
        text_report = f"""
{metadata['tool_name']} v{metadata['tool_version']} - Security Assessment Report
{'=' * 80}

SYSTEM INFORMATION
Host: {metadata['hostname']}
Operating System: {metadata['distro']}
Kernel: {metadata.get('kernel', 'Unknown')}
Architecture: {metadata.get('architecture', 'Unknown')}
Assessment Date: {metadata['timestamp']}

EXECUTIVE SUMMARY
Security Posture: {exec_summary['security_posture']}
Total Findings: {exec_summary['total_findings']}
Actions Taken: {exec_summary['actions_taken']}

SEVERITY BREAKDOWN
Critical: {exec_summary['severity_breakdown'].get('critical', 0)}
High: {exec_summary['severity_breakdown'].get('high', 0)}
Medium: {exec_summary['severity_breakdown'].get('medium', 0)}
Low: {exec_summary['severity_breakdown'].get('low', 0)}

STATUS BREAKDOWN
Failed: {exec_summary['status_breakdown'].get('FAIL', 0)}
Passed: {exec_summary['status_breakdown'].get('PASS', 0)}
Warnings: {exec_summary['status_breakdown'].get('WARN', 0)}

TOP CRITICAL ISSUES
{chr(10).join(f"- {issue}" for issue in exec_summary['top_critical_issues'])}

TOP HIGH PRIORITY ISSUES
{chr(10).join(f"- {issue}" for issue in exec_summary['top_high_issues'])}

RECOMMENDATIONS
Review the detailed HTML or JSON report for comprehensive remediation guidance.
Address critical and high-severity issues immediately.
Implement a regular security assessment schedule.

{'=' * 80}
Report generated by {metadata['tool_name']} v{metadata['tool_version']}
"""
        return text_report

class EnhancedHardeningOrchestrator:
    """Advanced orchestration engine with async support and enhanced features"""
    
    def __init__(self, config_file: Optional[str] = None, dry_run: bool = False,
                 compliance_frameworks: List[str] = None, max_workers: int = 4):
        self.dry_run = dry_run
        self.compliance_frameworks = compliance_frameworks or ['cis']
        self.max_workers = max_workers
        
        # Load configuration
        self.config = self._load_configuration(config_file)
        
        # Initialize components
        self.db_manager = DatabaseManager(DB_PATH)
        self.backup_manager = AdvancedBackupManager()
        self.compliance_engine = ComplianceEngine(self.compliance_frameworks)
        self.report_generator = EnhancedReportGenerator()
        
        # System information
        self.system_info = SystemInfo.gather()
        
        # Initialize modules
        self.modules = self._initialize_modules()
        
        # Results storage
        self.audit_results: List[SecurityFinding] = []
        self.hardening_actions: List[HardeningAction] = []
        self.audit_run_id: Optional[int] = None
        
        # Performance tracking
        self.start_time: Optional[datetime.datetime] = None
        self.end_time: Optional[datetime.datetime] = None
        
        # Setup logging
        self._setup_enhanced_logging()
    
    def _load_configuration(self, config_file: Optional[str]) -> Dict:
        """Load enhanced configuration"""
        default_config = {
            'modules': {
                'user_security': {'enabled': True, 'priority': 'high'},
                'ssh_hardening': {'enabled': True, 'priority': 'high'},
                'kernel_hardening': {'enabled': True, 'priority': 'high'},
                'firewall': {'enabled': True, 'priority': 'medium'},
                'file_permissions': {'enabled': True, 'priority': 'medium'},
                'services': {'enabled': True, 'priority': 'low'},
                'audit_logging': {'enabled': True, 'priority': 'medium'},
                'network_security': {'enabled': True, 'priority': 'medium'}
            },
            'compliance': {
                'frameworks': self.compliance_frameworks,
                'generate_compliance_report': True,
                'compliance_level': 'recommended'
            },
            'execution': {
                'parallel_execution': True,
                'max_workers': self.max_workers,
                'timeout_seconds': 300,
                'retry_failed_actions': True,
                'create_backup_before_changes': True
            },
            'reporting': {
                'formats': ['html', 'json', 'csv', 'txt'],
                'include_system_info': True,
                'include_compliance_mapping': True,
                'executive_summary': True
            },
            'security': {
                'verify_actions': True,
                'rollback_on_failure': True,
                'require_confirmation': not self.dry_run
            }
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    if config_file.endswith('.json'):
                        user_config = json.load(f)
                    elif config_file.endswith(('.yaml', '.yml')):
                        user_config = yaml.safe_load(f)
                    else:
                        logging.warning(f"Unsupported config format: {config_file}")
                        return default_config
                
                # Deep merge configurations
                default_config.update(user_config)
            except Exception as e:
                logging.error(f"Failed to load configuration: {e}")
        
        return default_config
    
    def _initialize_modules(self) -> List[BaseHardeningModule]:
        """Initialize enabled hardening modules"""
        available_modules = {
            'user_security': AdvancedUserSecurityModule,
            'ssh_hardening': AdvancedSSHHardeningModule,
            'kernel_hardening': AdvancedKernelHardeningModule,
            # Additional modules would be implemented here
        }
        
        modules = []
        for module_name, module_class in available_modules.items():
            module_config = self.config['modules'].get(module_name, {})
            if module_config.get('enabled', True):
                try:
                    module = module_class(
                        dry_run=self.dry_run,
                        compliance_frameworks=self.compliance_frameworks
                    )
                    modules.append(module)
                    logging.info(f"Initialized module: {module_name}")
                except Exception as e:
                    logging.error(f"Failed to initialize module {module_name}: {e}")
        
        return modules
    
    def _setup_enhanced_logging(self):
        """Setup comprehensive logging system"""
        log_dir = Path(LOG_DIR)
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create timestamped log file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"hardening_{timestamp}.log"
        
        # Configure logging with multiple handlers
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # File handler with detailed format
        file_handler = logging.FileHandler(log_file)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)
        
        # Console handler with simpler format
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(logging.INFO)
        logger.addHandler(console_handler)
        
        logging.info(f"Enhanced logging initialized - Log file: {log_file}")
    
    async def perform_comprehensive_audit(self) -> List[SecurityFinding]:
        """Perform comprehensive security audit using all modules"""
        self.start_time = datetime.datetime.now()
        logging.info("Starting comprehensive security audit...")
        
        # Create audit run record
        config_hash = hashlib.sha256(
            json.dumps(self.config, sort_keys=True).encode()
        ).hexdigest()[:16]
        
        self.audit_run_id = self.db_manager.create_audit_run(
            self.system_info, config_hash, self.compliance_frameworks
        )
        
        all_findings = []
        
        if self.config['execution']['parallel_execution']:
            # Parallel execution for faster auditing
            async with asyncio.Semaphore(self.max_workers):
                tasks = [self._audit_module(module) for module in self.modules]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        logging.error(f"Module {self.modules[i].name} failed: {result}")
                    else:
                        all_findings.extend(result)
        else:
            # Sequential execution
            for module in self.modules:
                try:
                    findings = await self._audit_module(module)
                    all_findings.extend(findings)
                except Exception as e:
                    logging.error(f"Module {module.name} failed: {e}")
        
        # Store findings in database
        for finding in all_findings:
            self.db_manager.save_finding(self.audit_run_id, finding)
        
        # Update audit run with summary
        findings_summary = self._calculate_findings_summary(all_findings)
        duration = int((datetime.datetime.now() - self.start_time).total_seconds())
        self.db_manager.update_audit_run(self.audit_run_id, findings_summary, duration)
        
        self.audit_results = all_findings
        self.end_time = datetime.datetime.now()
        
        logging.info(f"Audit completed in {duration} seconds. Found {len(all_findings)} issues.")
        return all_findings
    
    async def _audit_module(self, module: BaseHardeningModule) -> List[SecurityFinding]:
        """Audit individual module with error handling"""
        module_start = time.time()
        logging.info(f"Auditing module: {module.name}")
        
        try:
            findings = await module.audit()
            duration = time.time() - module_start
            logging.info(f"Module {module.name} completed in {duration:.2f}s - {len(findings)} findings")
            return findings
        except Exception as e:
            logging.error(f"Module {module.name} audit failed: {e}")
            return []
    
    async def apply_hardening_actions(self, interactive: bool = True) -> List[HardeningAction]:
        """Apply hardening actions with enhanced error handling and rollback"""
        logging.info("Starting hardening process...")
        
        if self.dry_run:
            logging.info("DRY RUN MODE - No actual changes will be made")
        
        # Create comprehensive backup
        if self.config['execution']['create_backup_before_changes'] and not self.dry_run:
            backup_files = self._collect_files_to_backup()
            backup_id = self.backup_manager.create_backup(
                "pre_hardening_comprehensive", backup_files
            )
            logging.info(f"Created comprehensive backup: {backup_id}")
        
        # Collect all actions from modules
        all_actions = []
        for module in self.modules:
            try:
                actions = await module.harden()
                all_actions.extend(actions)
            except Exception as e:
                logging.error(f"Failed to get actions from {module.name}: {e}")
        
        # Sort actions by priority
        all_actions.sort(key=lambda x: x.priority.value)
        
        # Display impact analysis
        if interactive and not self.dry_run:
            impact_analysis = self._analyze_hardening_impact(all_actions)
            self._display_impact_analysis(impact_analysis)
            
            if not self._get_user_confirmation():
                logging.info("Hardening cancelled by user")
                return []
        
        # Execute actions
        executed_actions = []
        if self.config['execution']['parallel_execution']:
            executed_actions = await self._execute_actions_parallel(all_actions)
        else:
            executed_actions = await self._execute_actions_sequential(all_actions)
        
        # Save actions to database
        for action in executed_actions:
            self.db_manager.save_action(self.audit_run_id, action)
        
        self.hardening_actions = executed_actions
        return executed_actions
    
    async def _execute_actions_parallel(self, actions: List[HardeningAction]) -> List[HardeningAction]:
        """Execute actions in parallel with proper dependency management"""
        executed_actions = []
        
        # Group actions by dependency and priority
        action_groups = self._group_actions_by_dependency(actions)
        
        for group in action_groups:
            # Execute each group in parallel
            semaphore = asyncio.Semaphore(self.max_workers)
            tasks = [self._execute_single_action(action, semaphore) for action in group]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for action, result in zip(group, results):
                if isinstance(result, Exception):
                    logging.error(f"Action {action.id} failed: {result}")
                    action.status = ActionStatus.FAILED
                else:
                    executed_actions.append(action)
        
        return executed_actions
    
    async def _execute_actions_sequential(self, actions: List[HardeningAction]) -> List[HardeningAction]:
        """Execute actions sequentially"""
        executed_actions = []
        
        for action in actions:
            try:
                await self._execute_single_action(action)
                executed_actions.append(action)
            except Exception as e:
                logging.error(f"Action {action.id} failed: {e}")
                action.status = ActionStatus.FAILED
                
                if self.config['security']['rollback_on_failure']:
                    await self._rollback_action(action)
        
        return executed_actions
    
    async def _execute_single_action(self, action: HardeningAction, 
                                   semaphore: asyncio.Semaphore = None) -> HardeningAction:
        """Execute a single hardening action"""
        if semaphore:
            async with semaphore:
                return await self._do_execute_action(action)
        else:
            return await self._do_execute_action(action)
    
    async def _do_execute_action(self, action: HardeningAction) -> HardeningAction:
        """Internal action execution logic"""
        action.start_time = datetime.datetime.now()
        action.status = ActionStatus.RUNNING
        
        logging.info(f"Executing action: {action.title}")
        
        try:
            # Check prerequisites
            if not await self._check_action_prerequisites(action):
                action.status = ActionStatus.SKIPPED
                return action
            
            # Execute commands
            for command in action.commands:
                ret_code, stdout, stderr = await self._execute_command_with_retry(command)
                action.execution_log.append(f"Command: {' '.join(command)}")
                action.execution_log.append(f"Return code: {ret_code}")
                
                if ret_code != 0:
                    action.execution_log.append(f"Error: {stderr}")
                    raise Exception(f"Command failed: {' '.join(command)} - {stderr}")
                else:
                    action.execution_log.append(f"Output: {stdout}")
            
            # Verify action if configured
            if self.config['security']['verify_actions']:
                verification_passed = await self._verify_action(action)
                if not verification_passed:
                    raise Exception("Action verification failed")
            
            action.status = ActionStatus.SUCCESS
            action.end_time = datetime.datetime.now()
            
            logging.info(f"Action completed successfully: {action.title}")
            return action
            
        except Exception as e:
            action.status = ActionStatus.FAILED
            action.end_time = datetime.datetime.now()
            action.execution_log.append(f"Failed: {str(e)}")
            
            logging.error(f"Action failed: {action.title} - {e}")
            raise e
    
    async def _execute_command_with_retry(self, command: List[str], 
                                        max_retries: int = 3) -> Tuple[int, str, str]:
        """Execute command with retry logic"""
        for attempt in range(max_retries):
            try:
                if self.dry_run:
                    logging.info(f"[DRY RUN] Would execute: {' '.join(command)}")
                    return 0, "", ""
                
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                timeout = self.config['execution']['timeout_seconds']
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
                
                return process.returncode, stdout.decode(), stderr.decode()
                
            except asyncio.TimeoutError:
                if attempt < max_retries - 1:
                    logging.warning(f"Command timeout, retrying: {' '.join(command)}")
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    raise Exception(f"Command timeout after {max_retries} attempts")
            except Exception as e:
                if attempt < max_retries - 1:
                    logging.warning(f"Command failed, retrying: {e}")
                    await asyncio.sleep(2 ** attempt)
                else:
                    raise e
    
    def _calculate_findings_summary(self, findings: List[SecurityFinding]) -> Dict:
        """Calculate findings summary for database"""
        severity_counts = Counter(f.severity.value for f in findings)
        return {
            'total': len(findings),
            'critical': severity_counts.get('critical', 0),
            'high': severity_counts.get('high', 0),
            'medium': severity_counts.get('medium', 0),
            'low': severity_counts.get('low', 0)
        }
    
    def _collect_files_to_backup(self) -> List[str]:
        """Collect all files that might be modified during hardening"""
        critical_files = [
            '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow',
            '/etc/ssh/sshd_config', '/etc/sudoers', '/etc/hosts',
            '/etc/sysctl.conf', '/etc/login.defs', '/etc/security/limits.conf',
            '/etc/pam.d/', '/etc/systemd/', '/etc/default/grub'
        ]
        
        # Expand directories to individual files
        files_to_backup = []
        for path in critical_files:
            if os.path.isfile(path):
                files_to_backup.append(path)
            elif os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        files_to_backup.append(os.path.join(root, file))
        
        return files_to_backup
    
    def _analyze_hardening_impact(self, actions: List[HardeningAction]) -> Dict:
        """Analyze the impact of hardening actions"""
        return {
            'total_actions': len(actions),
            'critical_priority': len([a for a in actions if a.priority == Priority.CRITICAL]),
            'high_priority': len([a for a in actions if a.priority == Priority.HIGH]),
            'medium_priority': len([a for a in actions if a.priority == Priority.MEDIUM]),
            'low_priority': len([a for a in actions if a.priority == Priority.LOW]),
            'requires_reboot': any(a.requires_reboot for a in actions),
            'services_affected': len(set().union(*[a.services_affected for a in actions])),
            'files_modified': len(set().union(*[a.files_modified for a in actions])),
            'estimated_duration': sum(a.estimated_duration for a in actions),
            'reversible_actions': len([a for a in actions if a.reversible])
        }
    
    def _display_impact_analysis(self, impact: Dict):
        """Display impact analysis to user"""
        print("\n" + "="*80)
        print("HARDENING IMPACT ANALYSIS")
        print("="*80)
        print(f"Total Actions: {impact['total_actions']}")
        print(f"Critical Priority: {impact['critical_priority']}")
        print(f"High Priority: {impact['high_priority']}")
        print(f"Medium Priority: {impact['medium_priority']}")
        print(f"Low Priority: {impact['low_priority']}")
        print(f"Requires Reboot: {'Yes' if impact['requires_reboot'] else 'No'}")
        print(f"Services Affected: {impact['services_affected']}")
        print(f"Files Modified: {impact['files_modified']}")
        print(f"Estimated Duration: {impact['estimated_duration']} seconds")
        print(f"Reversible Actions: {impact['reversible_actions']}/{impact['total_actions']}")
        print("="*80)
    
    def _get_user_confirmation(self) -> bool:
        """Get user confirmation for hardening"""
        if not self.config['security']['require_confirmation']:
            return True
        
        while True:
            response = input("\nProceed with hardening? [y/N/details]: ").lower().strip()
            if response == 'y':
                return True
            elif response == 'n' or response == '':
                return False
            elif response == 'details':
                # Show detailed action list
                for action in self.hardening_actions:
                    print(f"- {action.title}: {action.description}")
                continue
            else:
                print("Please enter 'y' for yes, 'n' for no, or 'details' for more information.")
    
    async def generate_comprehensive_report(self) -> Dict[str, str]:
        """Generate comprehensive security assessment report"""
        logging.info("Generating comprehensive security report...")
        
        # Generate compliance assessment
        compliance_report = self.compliance_engine.generate_compliance_report(self.audit_results)
        
        # Generate reports in multiple formats
        report_files = self.report_generator.generate_comprehensive_report(
            self.audit_results,
            self.hardening_actions,
            self.system_info,
            compliance_report
        )
        
        logging.info(f"Reports generated: {list(report_files.keys())}")
        return report_files
    
    async def rollback_to_backup(self, backup_id: str) -> bool:
        """Rollback system to a previous backup"""
        logging.info(f"Rolling back to backup: {backup_id}")
        
        success = self.backup_manager.restore_backup(backup_id)
        if success:
            logging.info("Rollback completed successfully")
            # Restart affected services
            await self._restart_critical_services()
        else:
            logging.error("Rollback failed")
        
        return success
    
    async def _restart_critical_services(self):
        """Restart critical services after rollback"""
        critical_services = ['sshd', 'systemd-logind', 'networking']
        
        for service in critical_services:
            try:
                ret_code, _, _ = await self._execute_command_with_retry(
                    ['systemctl', 'restart', service]
                )
                if ret_code == 0:
                    logging.info(f"Restarted service: {service}")
                else:
                    logging.warning(f"Failed to restart service: {service}")
            except Exception as e:
                logging.error(f"Error restarting {service}: {e}")

async def main():
    """Enhanced main function with comprehensive argument parsing"""
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} v{TOOL_VERSION} - Advanced Linux Security Hardening",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Comprehensive audit and hardening
  %(prog)s --audit --harden --compliance cis,nist
  
  # Audit only with specific modules
  %(prog)s --audit-only --modules user_security,ssh_hardening
  
  # Dry run to see what would be changed
  %(prog)s --dry-run --verbose
  
  # Generate compliance report
  %(prog)s --audit-only --compliance cis --report-format html,json
  
  # Rollback to previous state
  %(prog)s --rollback BACKUP_ID
  
  # Show system status and history
  %(prog)s --status --history 30
        """
    )
    
    # Main operations
    parser.add_argument('--audit', action='store_true', help='Perform security audit')
    parser.add_argument('--audit-only', action='store_true', help='Audit only, no hardening')
    parser.add_argument('--harden', action='store_true', help='Apply hardening configurations')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without making changes')
    
    # Configuration
    parser.add_argument('--config', help='Configuration file (JSON/YAML)')
    parser.add_argument('--compliance', help='Compliance frameworks (comma-separated): cis,nist,pci_dss,stig,iso27001')
    parser.add_argument('--modules', help='Specific modules to run (comma-separated)')
    
    # Execution control
    parser.add_argument('--non-interactive', action='store_true', help='Run without user prompts')
    parser.add_argument('--parallel', action='store_true', default=True, help='Enable parallel execution')
    parser.add_argument('--max-workers', type=int, default=4, help='Maximum parallel workers')
    
    # Reporting
    parser.add_argument('--report-format', default='html,json', help='Report formats: html,json,csv,txt')
    parser.add_argument('--output-dir', default=REPORTS_DIR, help='Output directory for reports')
    
    # Backup and rollback
    parser.add_argument('--backup-before', action='store_true', default=True, help='Create backup before changes')
    parser.add_argument('--rollback', help='Rollback to specific backup ID')
    parser.add_argument('--list-backups', action='store_true', help='List available backups')
    
    # Status and history
    parser.add_argument('--status', action='store_true', help='Show current security status')
    parser.add_argument('--history', type=int, metavar='DAYS', help='Show audit history for specified days')
    parser.add_argument('--trends', action='store_true', help='Show security trends')
    
    # Logging and debugging
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--log-file', help='Custom log file path')
    
    # Version
    parser.add_argument('--version', action='version', version=f'{TOOL_NAME} v{TOOL_VERSION}')
    
    args = parser.parse_args()
    
    # Validate root privileges for non-dry-run operations
    if not args.dry_run and os.geteuid() != 0:
        print(f"Error: {TOOL_NAME} requires root privileges for actual changes.")
        print("Use --dry-run to test without making changes, or run with sudo.")
        sys.exit(1)
    
    # Parse compliance frameworks
    compliance_frameworks = []
    if args.compliance:
        compliance_frameworks = [f.strip() for f in args.compliance.split(',')]
        invalid_frameworks = [f for f in compliance_frameworks if f not in COMPLIANCE_FRAMEWORKS]
        if invalid_frameworks:
            print(f"Error: Invalid compliance frameworks: {invalid_frameworks}")
            print(f"Valid options: {list(COMPLIANCE_FRAMEWORKS.keys())}")
            sys.exit(1)
    
    # Initialize orchestrator
    try:
        orchestrator = EnhancedHardeningOrchestrator(
            config_file=args.config,
            dry_run=args.dry_run,
            compliance_frameworks=compliance_frameworks,
            max_workers=args.max_workers
        )
    except Exception as e:
        print(f"Error initializing hardening tool: {e}")
        sys.exit(1)
    
    # Handle special operations
    if args.list_backups:
        backups = orchestrator.backup_manager.list_backups()
        print("\nAvailable Backups:")
        print("-" * 80)
        for backup in backups:
            print(f"ID: {backup['backup_id']}")
            print(f"Description: {backup['description']}")
            print(f"Date: {backup['timestamp']}")
            print(f"Files: {len(backup.get('files', []))}")
            print("-" * 80)
        return
    
    if args.rollback:
        success = await orchestrator.rollback_to_backup(args.rollback)
        sys.exit(0 if success else 1)
    
    if args.status:
        # Show current system status
        print(f"\n{TOOL_NAME} v{TOOL_VERSION} - System Status")
        print("=" * 80)
        print(f"Hostname: {orchestrator.system_info.hostname}")
        print(f"OS: {orchestrator.system_info.distro_name} {orchestrator.system_info.distro_version}")
        print(f"Kernel: {orchestrator.system_info.kernel_version}")
        print(f"Uptime: {orchestrator.system_info.uptime_seconds // 3600} hours")
        print(f"Load Average: {orchestrator.system_info.load_average}")
        print(f"Memory: {orchestrator.system_info.memory_total // (1024**3)} GB")
        print(f"Running Services: {len(orchestrator.system_info.running_services)}")
        print(f"Open Ports: {len(orchestrator.system_info.open_ports)}")
        print("=" * 80)
        return
    
 
    if args.history:
        # Show audit history
        history = orchestrator.db_manager.get_audit_history(args.history)
        print(f"\nAudit History (Last {args.history} runs):")
        print("-" * 120)
        print(f"{'Date':<20} {'Hostname':<15} {'Total':<8} {'Critical':<10} {'High':<8} {'Medium':<8} {'Duration':<10}")
        print("-" * 120)
        for run in history:
            print(f"{run['timestamp']:<20} {run['hostname']:<15} {run['total_findings']:<8} "
                  f"{run['critical_findings']:<10} {run['high_findings']:<8} {run['medium_findings']:<8} "
                  f"{run['duration_seconds'] or 0:<10}s")
        return
    
    if args.trends:
        # Show security trends
        trends = orchestrator.db_manager.get_trend_data()
        print("\nSecurity Trends (Last 30 days):")
        print("-" * 80)
        for trend in trends:
            print(f"Date: {trend['date']} | Avg Findings: {trend['avg_findings']:.1f} | "
                  f"Critical: {trend['avg_critical']:.1f} | High: {trend['avg_high']:.1f}")
        return
    
    # Display system information
    print(f"\n{TOOL_NAME} v{TOOL_VERSION}")
    print(f"System: {orchestrator.system_info.distro_name} {orchestrator.system_info.distro_version}")
    print(f"Kernel: {orchestrator.system_info.kernel_version}")
    print(f"Architecture: {orchestrator.system_info.architecture}")
    print(f"Mode: {'DRY RUN' if args.dry_run else 'LIVE EXECUTION'}")
    if compliance_frameworks:
        print(f"Compliance: {', '.join(compliance_frameworks)}")
    print("=" * 80)
    
    try:
        # Perform audit
        if args.audit or args.audit_only or not args.harden:
            print("\n🔍 Starting comprehensive security audit...")
            audit_results = await orchestrator.perform_comprehensive_audit()
            
            # Display audit summary
            severity_counts = Counter(f.severity.value for f in audit_results)
            status_counts = Counter(f.status for f in audit_results)
            
            print(f"\n📊 Audit Summary:")
            print(f"  Total Checks: {len(audit_results)}")
            print(f"  ✅ Passed: {status_counts.get('PASS', 0)}")
            print(f"  ❌ Failed: {status_counts.get('FAIL', 0)}")
            print(f"  ⚠️  Warnings: {status_counts.get('WARN', 0)}")
            print(f"  🔴 Critical: {severity_counts.get('critical', 0)}")
            print(f"  🟠 High: {severity_counts.get('high', 0)}")
            print(f"  🟡 Medium: {severity_counts.get('medium', 0)}")
            print(f"  🟢 Low: {severity_counts.get('low', 0)}")
            
            # Show top issues
            critical_issues = [f for f in audit_results if f.severity == Severity.CRITICAL and f.status == 'FAIL']
            if critical_issues:
                print(f"\n🚨 Critical Issues Found:")
                for issue in critical_issues[:5]:
                    print(f"  • {issue.title}")
            
            high_issues = [f for f in audit_results if f.severity == Severity.HIGH and f.status == 'FAIL']
            if high_issues:
                print(f"\n⚠️  High Priority Issues:")
                for issue in high_issues[:5]:
                    print(f"  • {issue.title}")
        
        # Apply hardening if requested
        if args.harden and not args.audit_only:
            print("\n🔧 Starting hardening process...")
            hardening_actions = await orchestrator.apply_hardening_actions(
                interactive=not args.non_interactive
            )
            
            # Display hardening summary
            action_counts = Counter(a.status.value for a in hardening_actions)
            print(f"\n🛡️  Hardening Summary:")
            print(f"  Total Actions: {len(hardening_actions)}")
            print(f"  ✅ Successful: {action_counts.get('success', 0)}")
            print(f"  ❌ Failed: {action_counts.get('failed', 0)}")
            print(f"  ⏭️  Skipped: {action_counts.get('skipped', 0)}")
            
            # Check if reboot is required
            reboot_required = any(a.requires_reboot for a in hardening_actions if a.status == ActionStatus.SUCCESS)
            if reboot_required:
                print(f"\n🔄 REBOOT REQUIRED: Some changes require a system restart to take effect!")
        
        # Generate comprehensive report
        print(f"\n📄 Generating comprehensive report...")
        report_formats = [f.strip() for f in args.report_format.split(',')]
        
        # Set output directory
        orchestrator.report_generator.output_dir = Path(args.output_dir)
        
        report_files = await orchestrator.generate_comprehensive_report()
        
        print(f"\n📋 Reports Generated:")
        for format_type, file_path in report_files.items():
            if format_type in report_formats:
                print(f"  • {format_type.upper()}: {file_path}")
        
        # Display compliance summary if frameworks specified
        if compliance_frameworks:
            compliance_report = orchestrator.compliance_engine.generate_compliance_report(
                orchestrator.audit_results
            )
            print(f"\n📊 Compliance Assessment:")
            print(f"  Overall Score: {compliance_report['overall_score']:.1f}%")
            for framework, data in compliance_report['frameworks'].items():
                print(f"  {framework.upper()}: {data['compliance_score']:.1f}% "
                      f"({data['passed_controls']}/{data['total_findings']} controls)")
        
        # Final recommendations
        failed_findings = [f for f in orchestrator.audit_results if f.status == 'FAIL']
        if failed_findings:
            print(f"\n💡 Next Steps:")
            
            critical_count = len([f for f in failed_findings if f.severity == Severity.CRITICAL])
            high_count = len([f for f in failed_findings if f.severity == Severity.HIGH])
            
            if critical_count > 0:
                print(f"  🔴 Address {critical_count} critical security issues immediately")
            if high_count > 0:
                print(f"  🟠 Remediate {high_count} high-priority vulnerabilities")
            
            print(f"  📋 Review detailed report for comprehensive remediation guidance")
            print(f"  🔄 Schedule regular security assessments")
            print(f"  💾 Maintain current backup: {orchestrator.backup_manager.backup_dir}")
        
        print(f"\n✅ Security assessment completed successfully!")
        
        # Exit with appropriate code
        if failed_findings:
            critical_failed = any(f.severity == Severity.CRITICAL for f in failed_findings)
            sys.exit(2 if critical_failed else 1)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        print(f"\n\n⚠️  Operation cancelled by user")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        print(f"\n❌ Fatal error occurred: {e}")
        print(f"Check logs for detailed information: {LOG_DIR}")
        sys.exit(1)


# Additional utility functions and classes

class SecurityMetrics:
    """Security metrics and scoring system"""
    
    @staticmethod
    def calculate_security_score(findings: List[SecurityFinding]) -> Dict[str, float]:
        """Calculate comprehensive security score"""
        if not findings:
            return {'overall': 100.0, 'by_severity': {}, 'by_module': {}}
        
        # Weight factors for different severities
        severity_weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 5.0,
            Severity.MEDIUM: 2.0,
            Severity.LOW: 1.0,
            Severity.INFO: 0.0
        }
        
        total_weight = 0
        failed_weight = 0
        
        severity_scores = {}
        module_scores = defaultdict(lambda: {'total': 0, 'failed': 0})
        
        for finding in findings:
            weight = severity_weights.get(finding.severity, 0)
            total_weight += weight
            
            # Track by severity
            if finding.severity.value not in severity_scores:
                severity_scores[finding.severity.value] = {'total': 0, 'failed': 0}
            severity_scores[finding.severity.value]['total'] += 1
            
            # Track by module
            module_scores[finding.module]['total'] += weight
            
            if finding.status == 'FAIL':
                failed_weight += weight
                severity_scores[finding.severity.value]['failed'] += 1
                module_scores[finding.module]['failed'] += weight
        
        # Calculate overall score
        overall_score = ((total_weight - failed_weight) / total_weight * 100) if total_weight > 0 else 100.0
        
        # Calculate scores by severity
        by_severity = {}
        for severity, counts in severity_scores.items():
            if counts['total'] > 0:
                by_severity[severity] = ((counts['total'] - counts['failed']) / counts['total'] * 100)
        
        # Calculate scores by module
        by_module = {}
        for module, weights in module_scores.items():
            if weights['total'] > 0:
                by_module[module] = ((weights['total'] - weights['failed']) / weights['total'] * 100)
        
        return {
            'overall': round(overall_score, 1),
            'by_severity': by_severity,
            'by_module': by_module
        }
    
    @staticmethod
    def generate_security_trend(historical_scores: List[Dict]) -> Dict:
        """Generate security trend analysis"""
        if len(historical_scores) < 2:
            return {'trend': 'insufficient_data', 'change': 0.0}
        
        recent_score = historical_scores[-1]['overall']
        previous_score = historical_scores[-2]['overall']
        change = recent_score - previous_score
        
        if change > 5:
            trend = 'improving'
        elif change < -5:
            trend = 'declining'
        else:
            trend = 'stable'
        
        return {
            'trend': trend,
            'change': round(change, 1),
            'recent_score': recent_score,
            'previous_score': previous_score
        }

class HardeningProfileManager:
    """Manage hardening profiles for different environments"""
    
    def __init__(self, profile_dir: str = PROFILE_DIR):
        self.profile_dir = Path(profile_dir)
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        self.default_profiles = self._create_default_profiles()
    
    def _create_default_profiles(self) -> Dict[str, Dict]:
        """Create default hardening profiles"""
        return {
            'server': {
                'name': 'Server Hardening Profile',
                'description': 'Comprehensive hardening for production servers',
                'modules': {
                    'user_security': {'enabled': True, 'priority': 'high'},
                    'ssh_hardening': {'enabled': True, 'priority': 'high'},
                    'kernel_hardening': {'enabled': True, 'priority': 'high'},
                    'firewall': {'enabled': True, 'priority': 'high'},
                    'file_permissions': {'enabled': True, 'priority': 'medium'},
                    'services': {'enabled': True, 'priority': 'medium'},
                    'audit_logging': {'enabled': True, 'priority': 'high'}
                },
                'compliance_frameworks': ['cis', 'nist'],
                'security_level': 'high'
            },
            'workstation': {
                'name': 'Workstation Hardening Profile',
                'description': 'Balanced hardening for desktop/laptop systems',
                'modules': {
                    'user_security': {'enabled': True, 'priority': 'high'},
                    'ssh_hardening': {'enabled': False, 'priority': 'low'},
                    'kernel_hardening': {'enabled': True, 'priority': 'medium'},
                    'firewall': {'enabled': True, 'priority': 'medium'},
                    'file_permissions': {'enabled': True, 'priority': 'medium'},
                    'services': {'enabled': True, 'priority': 'low'}
                },
                'compliance_frameworks': ['cis'],
                'security_level': 'medium'
            },
            'container': {
                'name': 'Container Hardening Profile',
                'description': 'Hardening optimized for containerized environments',
                'modules': {
                    'user_security': {'enabled': True, 'priority': 'high'},
                    'ssh_hardening': {'enabled': False, 'priority': 'low'},
                    'kernel_hardening': {'enabled': True, 'priority': 'high'},
                    'firewall': {'enabled': False, 'priority': 'low'},
                    'file_permissions': {'enabled': True, 'priority': 'high'},
                    'services': {'enabled': True, 'priority': 'medium'}
                },
                'compliance_frameworks': ['cis'],
                'security_level': 'high'
            },
            'minimal': {
                'name': 'Minimal Hardening Profile',
                'description': 'Basic hardening with minimal system impact',
                'modules': {
                    'user_security': {'enabled': True, 'priority': 'medium'},
                    'ssh_hardening': {'enabled': True, 'priority': 'medium'},
                    'kernel_hardening': {'enabled': False, 'priority': 'low'},
                    'firewall': {'enabled': True, 'priority': 'medium'},
                    'file_permissions': {'enabled': True, 'priority': 'low'},
                    'services': {'enabled': False, 'priority': 'low'}
                },
                'compliance_frameworks': [],
                'security_level': 'low'
            }
        }
    
    def get_profile(self, profile_name: str) -> Optional[Dict]:
        """Get hardening profile by name"""
        # Check default profiles first
        if profile_name in self.default_profiles:
            return self.default_profiles[profile_name]
        
        # Check custom profiles
        profile_file = self.profile_dir / f"{profile_name}.json"
        if profile_file.exists():
            try:
                with open(profile_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logging.error(f"Failed to load profile {profile_name}: {e}")
        
        return None
    
    def save_profile(self, profile_name: str, profile_data: Dict) -> bool:
        """Save custom hardening profile"""
        try:
            profile_file = self.profile_dir / f"{profile_name}.json"
            with open(profile_file, 'w') as f:
                json.dump(profile_data, f, indent=2)
            logging.info(f"Saved profile: {profile_name}")
            return True
        except Exception as e:
            logging.error(f"Failed to save profile {profile_name}: {e}")
            return False
    
    def list_profiles(self) -> List[str]:
        """List all available profiles"""
        profiles = list(self.default_profiles.keys())
        
        # Add custom profiles
        for profile_file in self.profile_dir.glob("*.json"):
            profile_name = profile_file.stem
            if profile_name not in profiles:
                profiles.append(profile_name)
        
        return sorted(profiles)

class NetworkSecurityAnalyzer:
    """Advanced network security analysis"""
    
    def __init__(self):
        self.suspicious_ports = {
            21: 'FTP', 23: 'Telnet', 53: 'DNS', 69: 'TFTP',
            135: 'RPC', 139: 'NetBIOS', 445: 'SMB', 1433: 'MSSQL',
            1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL'
        }
    
    async def analyze_network_security(self, system_info: SystemInfo) -> List[SecurityFinding]:
        """Perform comprehensive network security analysis"""
        findings = []
        
        # Analyze open ports
        findings.extend(await self._analyze_open_ports(system_info.open_ports))
        
        # Analyze network interfaces
        findings.extend(await self._analyze_network_interfaces(system_info.network_interfaces))
        
        # Check for suspicious network connections
        findings.extend(await self._check_network_connections())
        
        return findings
    
    async def _analyze_open_ports(self, open_ports: List[Dict]) -> List[SecurityFinding]:
        """Analyze open network ports for security issues"""
        findings = []
        
        for port_info in open_ports:
            port = port_info['port']
            address = port_info['address']
            
            # Check for suspicious ports
            if port in self.suspicious_ports:
                service_name = self.suspicious_ports[port]
                
                severity = Severity.HIGH if port in [21, 23, 69, 135] else Severity.MEDIUM
                
                finding = SecurityFinding(
                    id=f"network_suspicious_port_{port}",
                    module="network_security",
                    check=f"suspicious_port_{port}",
                    title=f"Suspicious Service Running: {service_name}",
                    description=f"Service {service_name} is running on port {port} and may pose security risks",
                    severity=severity,
                    priority=Priority.HIGH if severity == Severity.HIGH else Priority.MEDIUM,
                    status="FAIL",
                    current_value=f"Port {port} open ({service_name})",
                    expected_value="Port closed or secured",
                    remediation=f"Review necessity of {service_name} service and secure or disable if not needed"
                )
                findings.append(finding)
            
            # Check for services bound to all interfaces
            if address == '0.0.0.0':
                finding = SecurityFinding(
                    id=f"network_port_all_interfaces_{port}",
                    module="network_security",
                    check=f"port_all_interfaces_{port}",
                    title=f"Service Bound to All Interfaces: Port {port}",
                    description=f"Service on port {port} is accessible from all network interfaces",
                    severity=Severity.MEDIUM,
                    priority=Priority.MEDIUM,
                    status="WARN",
                    current_value=f"Port {port} bound to 0.0.0.0",
                    expected_value="Bound to specific interface or localhost",
                    remediation=f"Configure service on port {port} to bind to specific interfaces only"
                )
                findings.append(finding)
        
        return findings
    
    async def _analyze_network_interfaces(self, interfaces: List[Dict]) -> List[SecurityFinding]:
        """Analyze network interface configuration"""
        findings = []
        
        for interface in interfaces:
            interface_name = interface['name']
            
            # Skip loopback interface
            if interface_name == 'lo':
                continue
            
            # Check for promiscuous mode
            try:
                ret_code, output, _ = await self._execute_command(['ip', 'link', 'show', interface_name])
                if ret_code == 0 and 'PROMISC' in output:
                    finding = SecurityFinding(
                        id=f"network_promiscuous_mode_{interface_name}",
                        module="network_security",
                        check=f"promiscuous_mode_{interface_name}",
                        title=f"Network Interface in Promiscuous Mode: {interface_name}",
                        description=f"Interface {interface_name} is in promiscuous mode, allowing packet sniffing",
                        severity=Severity.HIGH,
                        priority=Priority.HIGH,
                        status="FAIL",
                        current_value="Promiscuous mode enabled",
                        expected_value="Promiscuous mode disabled",
                        remediation=f"Disable promiscuous mode on interface {interface_name}"
                    )
                    findings.append(finding)
            except:
                pass
        
        return findings
    
    async def _check_network_connections(self) -> List[SecurityFinding]:
        """Check for suspicious network connections"""
        findings = []
        
        try:
            # Check for established connections to suspicious IPs or ports
            connections = psutil.net_connections(kind='inet')
            
            suspicious_connections = []
            for conn in connections:
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    # Check for connections to private IP ranges from public IPs
                    if self._is_suspicious_connection(conn):
                        suspicious_connections.append(conn)
            
            if suspicious_connections:
                finding = SecurityFinding(
                    id="network_suspicious_connections",
                    module="network_security",
                    check="suspicious_connections",
                    title="Suspicious Network Connections Detected",
                    description=f"Found {len(suspicious_connections)} potentially suspicious network connections",
                    severity=Severity.MEDIUM,
                    priority=Priority.MEDIUM,
                    status="WARN",
                    current_value=f"{len(suspicious_connections)} suspicious connections",
                    expected_value="No suspicious connections",
                    remediation="Review network connections and investigate suspicious traffic"
                )
                findings.append(finding)
        
        except Exception as e:
            logging.error(f"Error checking network connections: {e}")
        
        return findings
    
    def _is_suspicious_connection(self, connection) -> bool:
        """Determine if a network connection is suspicious"""
        # Add logic to identify suspicious connections
        # This is a simplified example
        if connection.raddr and connection.raddr.port in [21, 23, 69]:
            return True
        return False
    
    async def _execute_command(self, command: List[str]) -> Tuple[int, str, str]:
        """Execute system command"""
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            return process.returncode, stdout.decode(), stderr.decode()
        except Exception as e:
            return -1, "", str(e)
# Enhanced main entry point
if __name__ == "__main__":
    try:
        # Check for required dependencies
        import psutil
        import netifaces
    except ImportError as e:
        print(f"Missing required dependency: {e}")
        print("Please install required packages:")
        print("pip install psutil netifaces")
        sys.exit(1)
    
    # Ensure required directories exist
    for directory in [BASE_DIR, LOG_DIR, BACKUP_DIR, CONFIG_DIR, PROFILE_DIR, CACHE_DIR, REPORTS_DIR]:
        Path(directory).mkdir(parents=True, exist_ok=True)
    
    # Run the main async function
    asyncio.run(main())