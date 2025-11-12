#!/bin/bash

# Script untuk membuat struktur folder Lazy Framework
# Usage: ./create_folder_structure.sh

echo "=========================================="
echo "  LAZY FRAMEWORK FOLDER STRUCTURE"
echo "=========================================="

# Base directory
BASE_DIR="modules"

echo "Creating main module directory: $BASE_DIR"
mkdir -p "$BASE_DIR"

# Buat main categories
mkdir -p "$BASE_DIR/recon"
mkdir -p "$BASE_DIR/strike" 
mkdir -p "$BASE_DIR/hold"
mkdir -p "$BASE_DIR/ops"
mkdir -p "$BASE_DIR/auxiliary"
mkdir -p "$BASE_DIR/payloads"

# Buat support directories
mkdir -p "$BASE_DIR/core"
mkdir -p "$BASE_DIR/examples"
mkdir -p "$BASE_DIR/banner"
mkdir -p "$BASE_DIR/bin"
mkdir -p "$BASE_DIR/data"
mkdir -p "$BASE_DIR/logs"

# ==================== RECON SUBDIRECTORIES ====================
echo "Creating recon subdirectories..."
mkdir -p "$BASE_DIR/recon/network"
mkdir -p "$BASE_DIR/recon/web"
mkdir -p "$BASE_DIR/recon/wireless" 
mkdir -p "$BASE_DIR/recon/social"
mkdir -p "$BASE_DIR/recon/osint"

# ==================== STRIKE SUBDIRECTORIES ====================
echo "Creating strike subdirectories..."
mkdir -p "$BASE_DIR/strike/remote"
mkdir -p "$BASE_DIR/strike/client"
mkdir -p "$BASE_DIR/strike/web"
mkdir -p "$BASE_DIR/strike/wireless"
mkdir -p "$BASE_DIR/strike/local"

# ==================== HOLD SUBDIRECTORIES ====================
echo "Creating hold subdirectories..."
mkdir -p "$BASE_DIR/hold/backdoor"
mkdir -p "$BASE_DIR/hold/rootkit"
mkdir -p "$BASE_DIR/hold/persistence"
mkdir -p "$BASE_DIR/hold/evasion"

# ==================== OPS SUBDIRECTORIES ====================
echo "Creating ops subdirectories..."
mkdir -p "$BASE_DIR/ops/post"
mkdir -p "$BASE_DIR/ops/payload"
mkdir -p "$BASE_DIR/ops/pivot"
mkdir -p "$BASE_DIR/ops/loot"

# ==================== AUXILIARY SUBDIRECTORIES ====================
echo "Creating auxiliary subdirectories..."
mkdir -p "$BASE_DIR/auxiliary/scanner"
mkdir -p "$BASE_DIR/auxiliary/fuzzer"
mkdir -p "$BASE_DIR/auxiliary/dos"
mkdir -p "$BASE_DIR/auxiliary/spoof"

# ==================== PAYLOADS SUBDIRECTORIES ====================
echo "Creating payloads subdirectories..."
mkdir -p "$BASE_DIR/payloads/reverse"
mkdir -p "$BASE_DIR/payloads/bind"
mkdir -p "$BASE_DIR/payloads/meterpreter"
mkdir -p "$BASE_DIR/payloads/shellcode"

# ==================== CORE SUBDIRECTORIES ====================
echo "Creating core subdirectories..."
mkdir -p "$BASE_DIR/core/utils"
mkdir -p "$BASE_DIR/core/handlers"
mkdir -p "$BASE_DIR/core/encoders"

# ==================== CREATE README FILES ====================
echo "Creating README files..."

cat > "$BASE_DIR/README.md" << 'EOF'
# Lazy Framework

Professional Penetration Testing Framework

## Structure
- `recon/` - Intelligence Gathering
- `strike/` - Exploitation & Attacks  
- `hold/` - Persistence & Maintain Access
- `ops/` - Operations & Post-Exploitation
- `auxiliary/` - Support Modules
- `payloads/` - Payload Generation
- `core/` - Core Framework Components
- `examples/` - Usage Examples
- `banner/` - Banner Files
- `bin/` - Binary Tools
- `data/` - Data Storage
- `logs/` - Log Files
EOF

# Buat README untuk setiap kategori utama
for category in recon strike hold ops auxiliary payloads; do
    cat > "$BASE_DIR/$category/README.md" << EOF
# ${category^^}

Place your $category modules in the appropriate subdirectories.

## Subdirectories
$(ls -d $BASE_DIR/$category/*/ 2>/dev/null | sed 's|.*/||g' | sed 's|/$||g' | sed 's/^/- /g')
EOF
done

# ==================== FINAL OUTPUT ====================
echo ""
echo "=========================================="
echo "  FOLDER STRUCTURE CREATED SUCCESSFULLY"
echo "=========================================="
echo ""
echo "Main Categories:"
echo "├── recon/          # Intelligence Gathering"
echo "├── strike/         # Exploitation & Attacks"
echo "├── hold/           # Persistence & Maintain Access" 
echo "├── ops/            # Operations & Post-Exploitation"
echo "├── auxiliary/      # Support Modules"
echo "├── payloads/       # Payload Generation"
echo "├── core/           # Core Framework Components"
echo "├── examples/       # Usage Examples"
echo "├── banner/         # Banner Files"
echo "├── bin/            # Binary Tools"
echo "├── data/           # Data Storage"
echo "└── logs/           # Log Files"
echo ""
echo "Total directories created:"
find "$BASE_DIR" -type d | wc -l
echo ""
echo "Run: tree . (if tree command is available)"
echo "Or: find . -type d | sort"
echo "=========================================="
