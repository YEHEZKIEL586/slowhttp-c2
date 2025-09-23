#!/bin/bash

# Distributed Slow HTTP C2 - Quick Launcher
# This script handles all the setup and launches the C2 system

cd "$(dirname "$0")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${RED}❌ Virtual environment not found!${NC}"
    echo -e "${YELLOW}Please run the installer first:${NC}"
    echo -e "${CYAN}./install.sh${NC}"
    echo -e "${YELLOW}Or create manually:${NC}"
    echo -e "${CYAN}python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt${NC}"
    exit 1
fi

# Activate virtual environment
echo -e "${BLUE}🔧 Activating Python environment...${NC}"
source venv/bin/activate

# Check if main script exists
if [ ! -f "slowhttp_c2.py" ]; then
    echo -e "${RED}❌ Main script (slowhttp_c2.py) not found!${NC}"
    echo -e "${YELLOW}Please ensure the file exists in: $(pwd)${NC}"
    exit 1
fi

# Check Python dependencies
echo -e "${BLUE}🔍 Checking dependencies...${NC}"
python3 -c "import paramiko, cryptography" 2>/dev/null || {
    echo -e "${YELLOW}⚠️  Dependencies missing or outdated. Installing...${NC}"
    pip install --upgrade -r requirements.txt
    
    # Check again
    python3 -c "import paramiko, cryptography" 2>/dev/null || {
        echo -e "${RED}❌ Failed to install dependencies!${NC}"
        echo -e "${YELLOW}Try manual installation:${NC}"
        echo -e "${CYAN}pip install paramiko cryptography${NC}"
        exit 1
    }
}

# Check system requirements
echo -e "${BLUE}🔍 Checking system requirements...${NC}"

# Check SSH client
if ! command -v ssh &> /dev/null; then
    echo -e "${YELLOW}⚠️  SSH client not found. Installing...${NC}"
    case "$(uname -s)" in
        Linux*)
            if [ -f /etc/debian_version ]; then
                sudo apt update && sudo apt install -y openssh-client
            elif [ -f /etc/redhat-release ]; then
                sudo yum install -y openssh-clients
            fi
            ;;
        Darwin*)
            echo -e "${GREEN}✅ SSH should be available on macOS${NC}"
            ;;
    esac
fi

# Create necessary directories
mkdir -p logs config

# Set proper permissions
chmod 700 . 2>/dev/null
chmod 600 *.py 2>/dev/null

# Clear screen and show startup banner
clear
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    🎯 DISTRIBUTED SLOW HTTP C2                              ║${NC}"
echo -e "${CYAN}║                           Starting System...                                ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}📂 Working Directory: $(pwd)${NC}"
echo -e "${GREEN}🐍 Python Environment: $(which python)${NC}"
echo -e "${GREEN}📊 Python Version: $(python --version)${NC}"
echo ""
echo -e "${RED}⚠️  WARNING: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️${NC}"
echo -e "${RED}   Unauthorized use against systems you don't own is ILLEGAL!${NC}"
echo ""
echo -e "${YELLOW}🚀 Initializing C2 system in 3 seconds...${NC}"

# Countdown
for i in 3 2 1; do
    echo -ne "${YELLOW}$i...${NC} "
    sleep 1
done
echo ""

# Run the main application
echo -e "${GREEN}🎯 Starting Distributed Slow HTTP C2...${NC}"
echo ""

# Handle Ctrl+C gracefully
trap 'echo -e "\n${YELLOW}🛑 Shutting down C2 system...${NC}"; exit 0' INT

# Launch main application
python3 slowhttp_c2.py "$@"

# Exit message
echo ""
echo -e "${CYAN}👋 Thank you for using Distributed Slow HTTP C2!${NC}"
echo -e "${YELLOW}Remember to use responsibly and legally.${NC}"