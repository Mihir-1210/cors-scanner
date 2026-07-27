#!/bin/bash

# CORS Scanner - One Command Setup
# This script will automatically set up everything

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   CORS Scanner - Auto Setup${NC}"
echo -e "${BLUE}========================================${NC}"

# Detect OS
OS="$(uname -s)"
echo -e "${GREEN}[+] Detected OS: $OS${NC}"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install Docker on Linux
install_docker_linux() {
    echo -e "${YELLOW}[*] Installing Docker...${NC}"
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
    echo -e "${GREEN}[+] Docker installed successfully${NC}"
    echo -e "${YELLOW}[!] Please log out and back in for group changes to take effect${NC}"
}

# Function to install Docker Compose
install_docker_compose() {
    echo -e "${YELLOW}[*] Installing Docker Compose...${NC}"
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    echo -e "${GREEN}[+] Docker Compose installed successfully${NC}"
}

# Check and install Docker
if ! command_exists docker; then
    echo -e "${YELLOW}[!] Docker not found${NC}"
    if [ "$OS" = "Linux" ]; then
        install_docker_linux
    else
        echo -e "${RED}[!] Please install Docker manually from https://docs.docker.com/get-docker/${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}[+] Docker is installed${NC}"
fi

# Check and install Docker Compose
if ! command_exists docker-compose; then
    echo -e "${YELLOW}[!] Docker Compose not found${NC}"
    install_docker_compose
else
    echo -e "${GREEN}[+] Docker Compose is installed${NC}"
fi

# Create project directories
echo -e "${GREEN}[+] Creating project structure...${NC}"
mkdir -p wordlists output

# Create default wordlist if it doesn't exist
if [ ! -f wordlists/common_origins.txt ]; then
    cat > wordlists/common_origins.txt << 'EOF'
https://evil.com
https://attacker.com
null
https://evil.com;https://legitimate.com
http://localhost
http://127.0.0.1
file://
https://sub.legitimate.com
https://evil.legitimate.com
http://evil.com
EOF
    echo -e "${GREEN}[+] Created default wordlist${NC}"
fi

# Create example URLs file
if [ ! -f urls.txt ]; then
    cat > urls.txt << 'EOF'
# Add your URLs here (one per line)
# Lines starting with # are ignored
# Example:
# example.com
# api.example.com
EOF
    echo -e "${GREEN}[+] Created example urls.txt file${NC}"
fi

# Build Docker image
echo -e "${GREEN}[+] Building Docker image...${NC}"
docker-compose build

# Create alias for easy use
ALIAS_CMD="alias cors-scanner='docker run --rm -v \$(pwd)/output:/app/output -v \$(pwd)/urls.txt:/app/urls.txt:ro cors-scanner:latest'"

if [ -f ~/.bashrc ]; then
    if ! grep -q "alias cors-scanner=" ~/.bashrc; then
        echo "$ALIAS_CMD" >> ~/.bashrc
        echo -e "${GREEN}[+] Added alias to ~/.bashrc${NC}"
    fi
fi

if [ -f ~/.zshrc ]; then
    if ! grep -q "alias cors-scanner=" ~/.zshrc; then
        echo "$ALIAS_CMD" >> ~/.zshrc
        echo -e "${GREEN}[+] Added alias to ~/.zshrc${NC}"
    fi
fi

# Create quick start script
cat > cors-scan << 'EOF'
#!/bin/bash
docker run --rm \
  -v $(pwd)/output:/app/output \
  -v $(pwd)/urls.txt:/app/urls.txt:ro \
  cors-scanner:latest \
  "$@"
EOF

chmod +x cors-scan
echo -e "${GREEN}[+] Created quick start script: ./cors-scan${NC}"

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}   Setup Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e ""
echo -e "Usage examples:"
echo -e ""
echo -e "${YELLOW}1. Using Docker directly:${NC}"
echo -e "   docker run --rm -v \$(pwd)/output:/app/output cors-scanner:latest -u https://example.com"
echo -e ""
echo -e "${YELLOW}2. Using quick script:${NC}"
echo -e "   ./cors-scan -f urls.txt -o output/results.json -of json"
echo -e ""
echo -e "${YELLOW}3. Using alias (restart terminal first):${NC}"
echo -e "   cors-scanner -u https://example.com"
echo -e ""
echo -e "${YELLOW}4. Scan from stdin:${NC}"
echo -e "   cat urls.txt | docker run --rm -i cors-scanner:latest -stdin"
echo -e ""
echo -e "${GREEN}[!] Edit urls.txt to add your targets${NC}"
echo -e "${GREEN}[!] Run 'source ~/.bashrc' to activate aliases${NC}"
