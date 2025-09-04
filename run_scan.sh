#!/bin/bash

# Wrapper script to run the codacy-trivy tool with proper environment setup

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Tool path
TOOL_PATH="./codacy-trivy"

# Check if tool exists
if [ ! -f "$TOOL_PATH" ]; then
    echo -e "${RED}Error: codacy-trivy tool not found at $TOOL_PATH${NC}"
    echo "Please build the tool first with: CGO_ENABLED=0 go build -o codacy-trivy cmd/tool/main.go"
    exit 1
fi

# Create a temporary directory structure that mimics the Docker environment
TEMP_ROOT=$(mktemp -d)
echo "Creating temporary environment at: $TEMP_ROOT"

# Create the /docs directory structure
mkdir -p "$TEMP_ROOT/docs"
cp docs/patterns.json "$TEMP_ROOT/docs/"

# Create a symlink to the docs directory at the root level
ln -sf "$TEMP_ROOT/docs" "$TEMP_ROOT/docs"

# Create cache directories
mkdir -p "$TEMP_ROOT/dist/cache/codacy-trivy"
mkdir -p "$TEMP_ROOT/dist/cache"

# Copy the OpenSSF index if it exists
if [ -f "openssf-index.json.gz" ]; then
    cp openssf-index.json.gz "$TEMP_ROOT/dist/cache/"
fi

# Function to run scan on a repository
run_scan_on_repo() {
    local repo_path="$1"
    local repo_name=$(basename "$repo_path")
    
    echo -e "${YELLOW}Scanning repository: $repo_name${NC}"
    
    # Create a temporary directory for the scan
    temp_dir=$(mktemp -d)
    
    # Copy the repository to temp directory
    cp -r "$repo_path" "$temp_dir/"
    temp_repo_path="$temp_dir/$repo_name"
    
    # Find package files
    package_files=()
    while IFS= read -r file; do
        if [ -n "$file" ]; then
            package_files+=("$file")
        fi
    done < <(find "$temp_repo_path" -type f \( \
        -name "package.json" -o \
        -name "go.mod" -o \
        -name "requirements.txt" -o \
        -name "pom.xml" \) \
        ! -path "*/node_modules/*" \
        ! -path "*/vendor/*" \
        ! -path "*/.git/*" \
        2>/dev/null)
    
    if [ ${#package_files[@]} -eq 0 ]; then
        echo -e "${YELLOW}  No package files found, skipping...${NC}"
        rm -rf "$temp_dir"
        return
    fi
    
    echo -e "${BLUE}  Found ${#package_files[@]} package files${NC}"
    
    # Create a JSON configuration for the tool
    config_json=$(cat <<EOF
{
  "sourceDir": "$temp_repo_path",
  "patterns": [
    {
      "id": "malicious_packages"
    }
  ],
  "files": [
EOF
)
    
    # Add package files to the configuration
    for i in "${!package_files[@]}"; do
        relative_path=$(echo "${package_files[$i]}" | sed "s|^$temp_repo_path/||")
        config_json+="    \"$relative_path\""
        if [ $i -lt $((${#package_files[@]} - 1)) ]; then
            config_json+=","
        fi
        config_json+=$'\n'
    done
    
    config_json+="  ]"$'\n'"}"
    
    # Write configuration to temporary file
    config_file=$(mktemp)
    echo "$config_json" > "$config_file"
    
    # Run the scan with proper environment
    echo -e "${BLUE}  Running malicious package scan...${NC}"
    
    # Set environment variables to mimic Docker environment
    export OPENSSF_INDEX_PATH="$TEMP_ROOT/dist/cache/openssf-index.json.gz"
    export OPENSSF_CACHE_DIR="$TEMP_ROOT/dist/cache/openssf-malicious-packages"
    
    # Change to the temp root directory and run the tool
    cd "$TEMP_ROOT"
    
    if output=$("$OLDPWD/$TOOL_PATH" 2>&1 < "$config_file"); then
        echo -e "${GREEN}  Scan completed successfully${NC}"
        
        # Check if any malicious packages were found
        if echo "$output" | grep -q "malicious_packages"; then
            echo -e "${RED}  ⚠️  MALICIOUS PACKAGES FOUND!${NC}"
            echo "$output" | grep -A 5 -B 5 "malicious_packages" || true
            return 1
        else
            echo -e "${GREEN}  ✅ No malicious packages found${NC}"
        fi
    else
        echo -e "${RED}  ❌ Scan failed:${NC}"
        echo "$output"
        return 1
    fi
    
    # Return to original directory
    cd "$OLDPWD"
    
    # Cleanup
    rm -f "$config_file"
    rm -rf "$temp_dir"
}

# Main scanning logic
echo -e "${BLUE}Starting malicious package scan of all git repositories in ../${NC}"
echo ""

# Counter for repositories
total_repos=0
scanned_repos=0
found_malicious=0

# Find all git repositories in parent directory
while IFS= read -r repo_path; do
    total_repos=$((total_repos + 1))
    
    if run_scan_on_repo "$repo_path"; then
        scanned_repos=$((scanned_repos + 1))
    else
        found_malicious=$((found_malicious + 1))
    fi
    
    echo ""
    
done < <(find "$(pwd)/../" -maxdepth 2 -type d -name ".git" | sed 's|/.git$||' | sort)

# Cleanup
rm -rf "$TEMP_ROOT"

# Summary
echo -e "${BLUE}=== SCAN SUMMARY ===${NC}"
echo -e "Total repositories found: ${YELLOW}$total_repos${NC}"
echo -e "Repositories scanned: ${GREEN}$scanned_repos${NC}"
echo -e "Repositories with malicious packages: ${RED}$found_malicious${NC}"
echo ""

if [ $found_malicious -gt 0 ]; then
    echo -e "${RED}⚠️  MALICIOUS PACKAGES WERE FOUND! Please review the results above.${NC}"
    exit 1
else
    echo -e "${GREEN}✅ No malicious packages found in any repository.${NC}"
    exit 0
fi
