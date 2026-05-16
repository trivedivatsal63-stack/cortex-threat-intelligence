#!/bin/bash
# =============================================================================
# Cyber Threat Intelligence Platform - Setup Script
# =============================================================================
# This script automates the complete setup process:
# 1. Creates Python virtual environment
# 2. Installs dependencies
# 3. Sets up environment variables
# 4. Initializes database schema
# 5. Verifies installation
# =============================================================================

set -e  # Exit on error

echo "============================================"
echo "  Cyber Threat Intelligence Platform Setup"
echo "============================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
check_python() {
    echo "🔍 Checking Python installation..."
    if command -v python3 &> /dev/null; then
        PYTHON=python3
    elif command -v python &> /dev/null; then
        PYTHON=python
    else
        echo -e "${RED}❌ Python not found. Please install Python 3.12+${NC}"
        exit 1
    fi
    
    PYTHON_VERSION=$($PYTHON --version 2>&1 | grep -oP '\d+\.\d+')
    echo "   Found Python $PYTHON_VERSION"
    
    if (( $(echo "$PYTHON_VERSION < 3.10" | bc -l) )); then
        echo -e "${RED}❌ Python 3.10+ required. Found $PYTHON_VERSION${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Python $PYTHON_VERSION${NC}"
}

# Create virtual environment
create_venv() {
    echo ""
    echo "🔧 Creating virtual environment..."
    if [ -d "venv" ]; then
        echo "   Virtual environment already exists. Skipping."
    else
        $PYTHON -m venv venv
        echo -e "${GREEN}✅ Virtual environment created${NC}"
    fi
}

# Activate virtual environment and install dependencies
install_deps() {
    echo ""
    echo "📦 Installing dependencies..."
    
    # Activate virtual environment
    if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        source venv/Scripts/activate 2>/dev/null || . venv/Scripts/activate
    else
        source venv/bin/activate
    fi
    
    # Upgrade pip
    pip install --upgrade pip -q
    
    # Install requirements
    pip install -r requirements.txt -q
    
    echo -e "${GREEN}✅ Dependencies installed${NC}"
}

# Setup environment variables
setup_env() {
    echo ""
    echo "🔑 Setting up environment variables..."
    
    if [ ! -f ".env" ]; then
        if [ -f ".env.example" ]; then
            cp .env.example .env
            echo -e "${YELLOW}⚠️  Created .env from .env.example${NC}"
            echo -e "${YELLOW}   Please edit .env with your credentials before running${NC}"
        else
            echo -e "${RED}❌ .env.example not found${NC}"
            exit 1
        fi
    else
        echo "   .env already exists. Skipping."
    fi
}

# Initialize database schema
init_database() {
    echo ""
    echo "🗄️  Initializing database schema..."
    echo -e "${YELLOW}   ⚠️  Make sure your .env has valid DATABASE_URL${NC}"
    
    if [ -f ".env" ]; then
        source .env 2>/dev/null || true
    fi
    
    # Use psql to apply schema if available
    if command -v psql &> /dev/null; then
        if [ -n "$DATABASE_URL" ]; then
            psql "$DATABASE_URL" -f database/schema.sql 2>/dev/null && \
                echo -e "${GREEN}✅ Database schema applied${NC}" || \
                echo -e "${YELLOW}   Could not apply schema. Apply manually via Supabase SQL editor.${NC}"
        else
            echo -e "${YELLOW}   DATABASE_URL not set. Apply schema manually via Supabase SQL editor.${NC}"
        fi
    else
        echo -e "${YELLOW}   psql not found. Apply schema.sql manually via Supabase SQL editor.${NC}"
    fi
}

# Create necessary directories
create_dirs() {
    echo ""
    echo "📁 Creating required directories..."
    mkdir -p logs reports data
    echo -e "${GREEN}✅ Directories created${NC}"
}

# Verify installation
verify() {
    echo ""
    echo "🔍 Verifying installation..."
    
    # Check critical files exist
    critical_files=(
        "main.py"
        "requirements.txt"
        ".env"
        "database/schema.sql"
        "config/settings.py"
        "collectors/orchestrator.py"
    )
    
    for file in "${critical_files[@]}"; do
        if [ -f "$file" ]; then
            echo -e "   ${GREEN}✅ $file${NC}"
        else
            echo -e "   ${RED}❌ $file not found${NC}"
        fi
    done
}

# Test Python imports
test_imports() {
    echo ""
    echo "🧪 Testing Python imports..."
    
    if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        source venv/Scripts/activate 2>/dev/null || . venv/Scripts/activate
    else
        source venv/bin/activate
    fi
    
    $PYTHON -c "
import sys
modules = [
    'requests', 'aiohttp', 'feedparser', 'bs4',
    'sqlalchemy', 'supabase', 'loguru', 'tenacity',
    'jinja2', 'fastapi', 'streamlit', 'pandas',
]
missing = []
for m in modules:
    try:
        __import__(m)
    except ImportError:
        missing.append(m)
if missing:
    print(f'   ${RED}❌ Missing modules: {missing}${NC}')
    sys.exit(1)
else:
    print(f'   ${GREEN}✅ All modules import successfully${NC}')
"
}

# =============================================================================
# Main Setup Flow
# =============================================================================

main() {
    check_python
    create_venv
    install_deps
    setup_env
    create_dirs
    init_database
    verify
    test_imports
    
    echo ""
    echo "============================================"
    echo -e "${GREEN}  ✅ Setup Complete!${NC}"
    echo "============================================"
    echo ""
    echo "  Next steps:"
    echo "  1. Edit .env with your API keys"
    echo "  2. Apply schema.sql to Supabase"
    echo "  3. Run: python main.py"
    echo "  4. Or use GitHub Actions for automation"
    echo ""
    echo "  See README.md for detailed documentation"
    echo "============================================"
}

main
