#!/usr/bin/env python3
"""
Distributed Slow HTTP C2 - Default Configuration
This file contains default configuration settings for the C2 system.
"""

import os
from pathlib import Path

# Base directory (where the main script is located)
BASE_DIR = Path(__file__).parent.parent.absolute()

# =============================================================================
# CORE SETTINGS
# =============================================================================

# Application Name
APP_NAME = "Distributed Slow HTTP C2"
APP_VERSION = "1.0.0"

# Debug Mode (set to False in production)
DEBUG = False

# =============================================================================
# DATABASE SETTINGS
# =============================================================================

# Database file location
DATABASE_FILE = BASE_DIR / "c2_database.db"

# Database connection timeout (seconds)
DATABASE_TIMEOUT = 30

# Database backup settings
DATABASE_AUTO_BACKUP = True
DATABASE_BACKUP_INTERVAL = 3600  # 1 hour in seconds
DATABASE_MAX_BACKUPS = 10

# =============================================================================
# SECURITY SETTINGS
# =============================================================================

# Encryption key file location
ENCRYPTION_KEY_FILE = BASE_DIR / "key.key"

# Password encryption algorithm (do not change unless you know what you're doing)
ENCRYPTION_ALGORITHM = "Fernet"

# SSH connection settings
SSH_TIMEOUT = 30  # seconds
SSH_BANNER_TIMEOUT = 15  # seconds
SSH_AUTH_TIMEOUT = 10  # seconds

# Maximum number of concurrent SSH connections
MAX_CONCURRENT_SSH = 50

# =============================================================================
# VPS MANAGEMENT
# =============================================================================

# Maximum number of VPS nodes
MAX_VPS_NODES = 100

# Default SSH port
DEFAULT_SSH_PORT = 22

# VPS connection test timeout
VPS_TEST_TIMEOUT = 10  # seconds

# Agent deployment timeout
AGENT_DEPLOY_TIMEOUT = 60  # seconds

# VPS cleanup timeout
VPS_CLEANUP_TIMEOUT = 30  # seconds

# =============================================================================
# ATTACK SETTINGS
# =============================================================================

# Default attack parameters
DEFAULT_CONNECTIONS_PER_VPS = 1000
DEFAULT_ATTACK_DELAY = 15  # seconds
DEFAULT_ATTACK_DURATION = 0  # 0 = unlimited

# Maximum connections per VPS (safety limit)
MAX_CONNECTIONS_PER_VPS = 10000

# Maximum attack duration (safety limit, 0 = no limit)
MAX_ATTACK_DURATION = 7200  # 2 hours

# Attack monitoring refresh interval
MONITORING_REFRESH_INTERVAL = 5  # seconds

# Maximum concurrent attack sessions
MAX_CONCURRENT_ATTACKS = 10

# =============================================================================
# LOGGING SETTINGS
# =============================================================================

# Log directory
LOG_DIR = BASE_DIR / "logs"

# Main log file
LOG_FILE = LOG_DIR / "c2.log"

# Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
LOG_LEVEL = "INFO"

# Log format
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Log file rotation
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
LOG_BACKUP_COUNT = 5

# Console logging
CONSOLE_LOGGING = True
CONSOLE_LOG_LEVEL = "INFO"

# =============================================================================
# NETWORK SETTINGS
# =============================================================================

# Web interface settings (if implemented)
WEB_HOST = "127.0.0.1"
WEB_PORT = 5000
WEB_DEBUG = False

# API settings (if implemented)
API_ENABLED = False
API_HOST = "127.0.0.1"
API_PORT = 5001

# Network timeouts
HTTP_TIMEOUT = 30  # seconds
DNS_TIMEOUT = 10   # seconds

# =============================================================================
# UI/UX SETTINGS
# =============================================================================

# Terminal colors
ENABLE_COLORS = True

# Terminal refresh rate
UI_REFRESH_RATE = 1.0  # seconds

# Maximum table width
MAX_TABLE_WIDTH = 120

# Progress bar settings
PROGRESS_BAR_WIDTH = 50

# =============================================================================
# PERFORMANCE SETTINGS
# =============================================================================

# Thread pool settings
MAX_WORKER_THREADS = 20

# Memory settings
MAX_MEMORY_USAGE = 512 * 1024 * 1024  # 512 MB

# Process limits
MAX_PROCESSES_PER_VPS = 10

# File descriptor limits
MAX_FILE_DESCRIPTORS = 65536

# =============================================================================
# TEMPORARY FILE SETTINGS
# =============================================================================

# Temporary directory on VPS
VPS_TEMP_DIR = "/tmp/slowhttp_c2"

# Agent script name
AGENT_SCRIPT_NAME = "agent.py"

# Temporary file cleanup
AUTO_CLEANUP_TEMP_FILES = True
TEMP_FILE_MAX_AGE = 86400  # 24 hours

# =============================================================================
# BACKUP AND RECOVERY
# =============================================================================

# Backup directory
BACKUP_DIR = BASE_DIR / "backups"

# Automatic backup settings
AUTO_BACKUP_ENABLED = True
AUTO_BACKUP_INTERVAL = 3600  # 1 hour
MAX_AUTO_BACKUPS = 24  # Keep 24 backups (1 day if hourly)

# Backup compression
BACKUP_COMPRESSION = True
BACKUP_COMPRESSION_LEVEL = 6  # 1-9, higher = better compression but slower

# =============================================================================
# ALERTING AND NOTIFICATIONS
# =============================================================================

# Alert settings
ALERTS_ENABLED = True

# Alert thresholds
VPS_OFFLINE_ALERT_THRESHOLD = 3  # Alert if 3+ VPS go offline
ATTACK_FAILURE_ALERT_THRESHOLD = 50  # Alert if >50% of attacks fail

# Notification methods (future implementation)
EMAIL_NOTIFICATIONS = False
EMAIL_SMTP_SERVER = ""
EMAIL_SMTP_PORT = 587
EMAIL_USERNAME = ""
EMAIL_PASSWORD = ""

# =============================================================================
# DEVELOPMENT SETTINGS
# =============================================================================

# Development mode features
DEV_MODE = False
DEV_MOCK_SSH = False  # Mock SSH connections for testing
DEV_FAKE_VPS = False  # Create fake VPS for testing

# Testing settings
TEST_MODE = False
TEST_DATABASE_FILE = BASE_DIR / "test_database.db"
TEST_LOG_LEVEL = "DEBUG"

# =============================================================================
# FEATURE FLAGS
# =============================================================================

# Feature toggles
FEATURE_WEB_INTERFACE = False
FEATURE_API_ACCESS = False
FEATURE_MULTI_USER = False
FEATURE_ATTACK_SCHEDULING = False
FEATURE_VPS_AUTO_DISCOVERY = False
FEATURE_LOAD_BALANCING = False

# Experimental features
EXPERIMENTAL_IPV6_SUPPORT = False
EXPERIMENTAL_TOR_SUPPORT = False
EXPERIMENTAL_CLOUD_INTEGRATION = False

# =============================================================================
# LEGAL AND COMPLIANCE
# =============================================================================

# Legal disclaimer settings
SHOW_LEGAL_WARNING = True
REQUIRE_LEGAL_ACCEPTANCE = True
LOG_LEGAL_ACCEPTANCE = True

# Compliance settings
GDPR_COMPLIANCE = True
DATA_RETENTION_DAYS = 90
ANONYMIZE_LOGS = False

# Usage tracking (anonymous)
ANONYMOUS_USAGE_STATS = False

# =============================================================================
# LOCALIZATION
# =============================================================================

# Language settings
DEFAULT_LANGUAGE = "en"
SUPPORTED_LANGUAGES = ["en"]

# Timezone
DEFAULT_TIMEZONE = "UTC"
USE_LOCAL_TIMEZONE = True

# Date/time formats
DATE_FORMAT = "%Y-%m-%d"
TIME_FORMAT = "%H:%M:%S"
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# =============================================================================
# ADVANCED SETTINGS
# =============================================================================

# Advanced SSH settings
SSH_KEY_EXCHANGE_ALGORITHMS = []  # Use default
SSH_SERVER_HOST_KEY_ALGORITHMS = []  # Use default
SSH_ENCRYPTION_ALGORITHMS = []  # Use default

# Advanced attack settings
ATTACK_RANDOMIZATION = True  # Randomize attack parameters
ATTACK_STEALTH_MODE = False  # Use stealth techniques
ATTACK_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
]

# Resource monitoring
MONITOR_SYSTEM_RESOURCES = True
RESOURCE_CHECK_INTERVAL = 60  # seconds
MAX_CPU_USAGE = 80  # percent
MAX_MEMORY_USAGE_PERCENT = 80  # percent

# =============================================================================
# ENVIRONMENT OVERRIDES
# =============================================================================

# Allow environment variables to override settings
def get_env_bool(key: str, default: bool) -> bool:
    """Get boolean value from environment variable."""
    value = os.getenv(key, str(default)).lower()
    return value in ('true', '1', 'yes', 'on')

def get_env_int(key: str, default: int) -> int:
    """Get integer value from environment variable."""
    try:
        return int(os.getenv(key, str(default)))
    except ValueError:
        return default

def get_env_str(key: str, default: str) -> str:
    """Get string value from environment variable."""
    return os.getenv(key, default)

# Apply environment overrides
if os.getenv('C2_CONFIG_FROM_ENV'):
    DEBUG = get_env_bool('C2_DEBUG', DEBUG)
    LOG_LEVEL = get_env_str('C2_LOG_LEVEL', LOG_LEVEL)
    MAX_VPS_NODES = get_env_int('C2_MAX_VPS_NODES', MAX_VPS_NODES)
    DEFAULT_CONNECTIONS_PER_VPS = get_env_int('C2_DEFAULT_CONNECTIONS', DEFAULT_CONNECTIONS_PER_VPS)
    WEB_HOST = get_env_str('C2_WEB_HOST', WEB_HOST)
    WEB_PORT = get_env_int('C2_WEB_PORT', WEB_PORT)
    SSH_TIMEOUT = get_env_int('C2_SSH_TIMEOUT', SSH_TIMEOUT)

# =============================================================================
# CONFIGURATION VALIDATION
# =============================================================================

def validate_config():
    """Validate configuration settings."""
    errors = []
    
    # Check critical directories exist
    if not BASE_DIR.exists():
        errors.append(f"Base directory does not exist: {BASE_DIR}")
    
    # Validate numeric ranges
    if MAX_VPS_NODES <= 0:
        errors.append("MAX_VPS_NODES must be positive")
    
    if DEFAULT_CONNECTIONS_PER_VPS <= 0:
        errors.append("DEFAULT_CONNECTIONS_PER_VPS must be positive")
    
    if SSH_TIMEOUT <= 0:
        errors.append("SSH_TIMEOUT must be positive")
    
    # Validate log level
    valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    if LOG_LEVEL not in valid_log_levels:
        errors.append(f"LOG_LEVEL must be one of: {valid_log_levels}")
    
    # Validate file paths
    if not ENCRYPTION_KEY_FILE.parent.exists():
        try:
            ENCRYPTION_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"Cannot create encryption key directory: {e}")
    
    return errors

# =============================================================================
# CONFIGURATION EXPORT
# =============================================================================

def get_config_dict():
    """Get all configuration as a dictionary."""
    config = {}
    
    # Get all module variables that don't start with underscore
    for key, value in globals().items():
        if not key.startswith('_') and key.isupper():
            config[key] = value
    
    return config

def print_config():
    """Print current configuration (for debugging)."""
    config = get_config_dict()
    
    print("Current Configuration:")
    print("=" * 50)
    
    for key, value in sorted(config.items()):
        if 'PASSWORD' in key or 'KEY' in key:
            value = '[HIDDEN]'
        print(f"{key}: {value}")

# Validate configuration on import
if __name__ == "__main__":
    validation_errors = validate_config()
    if validation_errors:
        print("Configuration Errors:")
        for error in validation_errors:
            print(f"  - {error}")
    else:
        print("Configuration is valid")
        print_config()