#!/bin/bash
# Distributed Slow HTTP C2 - Quick Launcher
# Fixed version with proper error handling
cd "$(dirname "$0")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Error handling
error_exit() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
    exit 1
}

# Check if virtual environment exists
echo -e "${BLUE}🔍 Checking installation...${NC}"
if [ ! -d "venv" ]; then
    echo -e "${RED}❌ Virtual environment not found!${NC}"
    echo -e "${YELLOW}Please run the installer first:${NC}"
    echo -e "${CYAN}bash install.sh${NC}"
    echo -e "${YELLOW}Or create manually:${NC}"
    echo -e "${CYAN}python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt${NC}"
    exit 1
fi

# Check if main script exists
if [ ! -f "slowhttp_c2.py" ]; then
    error_exit "Main script (slowhttp_c2.py) not found in $(pwd)"
fi

# Check if requirements.txt exists
if [ ! -f "requirements.txt" ]; then
    error_exit "Requirements file (requirements.txt) not found"
fi

# Activate virtual environment
echo -e "${BLUE}🔧 Activating Python environment...${NC}"
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
else
    error_exit "Virtual environment activation script not found"
fi

# Verify virtual environment is active
if [ -z "$VIRTUAL_ENV" ]; then
    error_exit "Failed to activate virtual environment"
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))' 2>/dev/null)
if [ $? -ne 0 ]; then
    error_exit "Python3 not available in virtual environment"
fi

echo -e "${GREEN}✅ Python ${PYTHON_VERSION} environment activated${NC}"

# Check and install dependencies
echo -e "${BLUE}🔍 Checking dependencies...${NC}"
python3 -c "import paramiko, cryptography, colorama" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}⚠️  Dependencies missing or incomplete. Installing...${NC}"
    
    # Upgrade pip first
    python3 -m pip install --upgrade pip
    
    # Install requirements
    if ! pip install -r requirements.txt; then
        error_exit "Failed to install Python dependencies"
    fi
    
    # Verify again
    python3 -c "import paramiko, cryptography, colorama" 2>/dev/null
    if [ $? -ne 0 ]; then
        error_exit "Dependencies still missing after installation attempt"
    fi
fi

echo -e "${GREEN}✅ All dependencies verified${NC}"

# Check system requirements
echo -e "${BLUE}🔍 Checking system requirements...${NC}"

# Check SSH client
if ! command -v ssh &> /dev/null; then
    echo -e "${YELLOW}⚠️  SSH client not found. This may cause issues with VPS connections.${NC}"
    echo -e "${YELLOW}Install it with: sudo apt install openssh-client (Debian/Ubuntu)${NC}"
fi

# Create necessary directories
mkdir -p logs config data
echo -e "${GREEN}✅ Created necessary directories${NC}"

# Set proper permissions
chmod 700 . 2>/dev/null || true
chmod 600 *.py 2>/dev/null || true
chmod 600 config/* 2>/dev/null || true

# Check for configuration files
if [ ! -f "config.ini" ] && [ -f "config.ini.example" ]; then
    echo -e "${YELLOW}⚠️  No config.ini found. Consider copying from config.ini.example${NC}"
fi

# Clear screen and show startup banner
clear
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║                    🎯 DISTRIBUTED SLOW HTTP C2                              ║${NC}"
echo -e "${CYAN}${BOLD}║                           Starting System...                                ║${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}📂 Working Directory: ${BOLD}$(pwd)${NC}"
echo -e "${GREEN}🐍 Python Environment: ${BOLD}$(which python3)${NC}"
echo -e "${GREEN}📊 Python Version: ${BOLD}$(python3 --version)${NC}"
echo -e "${GREEN}💾 Virtual Environment: ${BOLD}${VIRTUAL_ENV}${NC}"
echo ""
echo -e "${RED}${BOLD}⚠️  WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️${NC}"
echo -e "${RED}   Unauthorized use against systems you don't own is ILLEGAL!${NC}"
echo -e "${RED}   You are fully responsible for how you use this tool.${NC}"
echo ""

# Check if this is the first run
if [ ! -f ".first_run_done" ]; then
    echo -e "${YELLOW}🎉 First time setup detected!${NC}"
    echo -e "${CYAN}📖 Quick Start Guide:${NC}"
    echo -e "${CYAN}   1. Add VPS nodes in the VPS Management menu${NC}"
    echo -e "${CYAN}   2. Test connections to ensure they work${NC}"
    echo -e "${CYAN}   3. Deploy agents to your VPS nodes${NC}"
    echo -e "${CYAN}   4. Launch distributed attacks${NC}"
    echo ""
    echo -e "${YELLOW}Press Enter to continue to the application...${NC}"
    read -r
    touch .first_run_done
fi

# Countdown
echo -e "${YELLOW}🚀 Initializing C2 system...${NC}"
for i in 3 2 1; do
    echo -ne "${YELLOW}$i...${NC} "
    sleep 1
done
echo ""

# Handle Ctrl+C gracefully
trap 'echo -e "\n${YELLOW}🛑 Shutting down C2 system...${NC}"; echo -e "${CYAN}👋 Goodbye!${NC}"; exit 0' INT TERM

# Pre-flight check
echo -e "${BLUE}🔍 Pre-flight system check...${NC}"

# Check available disk space (at least 100MB)
AVAILABLE_SPACE=$(df . | awk 'NR==2 {print $4}')
if [ "$AVAILABLE_SPACE" -lt 102400 ]; then
    echo -e "${YELLOW}⚠️  Low disk space: $((AVAILABLE_SPACE/1024))MB available${NC}"
fi

# Check memory usage
if command -v free &> /dev/null; then
    AVAILABLE_MEMORY=$(free -m | awk 'NR==2{print $7}')
    if [ "$AVAILABLE_MEMORY" -lt 256 ]; then
        echo -e "${YELLOW}⚠️  Low available memory: ${AVAILABLE_MEMORY}MB${NC}"
    fi
fi

# Launch main application
echo -e "${GREEN}🎯 Starting Distributed Slow HTTP C2...${NC}"
echo ""

# Check if we can run the main script
if ! python3 -m py_compile slowhttp_c2.py; then
    error_exit "Main script has syntax errors"
fi

# Run the main application with all arguments
exec python3 slowhttp_c2.py "$@"

# This should never be reached due to exec, but just in case
echo ""
echo -e "${CYAN}👋 Thank you for using Distributed Slow HTTP C2!${NC}"
echo -e "${YELLOW}Remember to use responsibly and legally.${NC}"
