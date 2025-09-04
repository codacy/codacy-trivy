#!/bin/bash

# Script to scan all git repositories in the parent directory for malicious packages
# using the codacy-trivy tool

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

# Parent directory
PARENT_DIR="../"
SCAN_RESULTS_FILE="malicious_packages_scan_results.txt"

echo -e "${BLUE}Starting malicious package scan of all git repositories in $PARENT_DIR${NC}"
echo "Results will be saved to: $SCAN_RESULTS_FILE"
echo ""

# Clear previous results
> "$SCAN_RESULTS_FILE"

# Counter for repositories
total_repos=0
scanned_repos=0
found_malicious=0

# Find all git repositories in parent directory
while IFS= read -r -d '' repo_path; do
    total_repos=$((total_repos + 1))
    repo_name=$(basename "$repo_path")
    
    echo -e "${YELLOW}[$total_repos] Scanning repository: $repo_name${NC}"
    
    # Create a temporary directory for the scan
    temp_dir=$(mktemp -d)
    
    # Copy the repository to temp directory (to avoid modifying the original)
    cp -r "$repo_path" "$temp_dir/"
    temp_repo_path="$temp_dir/$repo_name"
    
    # Find all package files in the repository
    package_files=()
    
    # Look for common package files (excluding node_modules and other vendor directories)
    while IFS= read -r -d '' file; do
        package_files+=("$file")
    done < <(find "$temp_repo_path" -type f \( \
        -name "package.json" -o \
        -name "package-lock.json" -o \
        -name "yarn.lock" -o \
        -name "go.mod" -o \
        -name "go.sum" -o \
        -name "requirements.txt" -o \
        -name "Pipfile" -o \
        -name "poetry.lock" -o \
        -name "pom.xml" -o \
        -name "build.gradle" -o \
        -name "Cargo.toml" -o \
        -name "Cargo.lock" -o \
        -name "Gemfile" -o \
        -name "Gemfile.lock" -o \
        -name "composer.json" -o \
        -name "composer.lock" -o \
        -name "pubspec.yaml" -o \
        -name "pubspec.lock" -o \
        -name "mix.exs" -o \
        -name "mix.lock" -o \
        -name "*.csproj" -o \
        -name "*.sln" -o \
        -name "Podfile" -o \
        -name "Podfile.lock" -o \
        -name "*.swift" -o \
        -name "Package.swift" -o \
        -name "Package.resolved" \) \
        ! -path "*/node_modules/*" \
        ! -path "*/vendor/*" \
        ! -path "*/.git/*" \
        ! -path "*/dist/*" \
        ! -path "*/build/*" \
        ! -path "*/target/*" \
        ! -path "*/__pycache__/*" \
        ! -path "*/.venv/*" \
        ! -path "*/venv/*" \
        ! -path "*/env/*" \
        ! -path "*/.env/*" \
        2>/dev/null | head -100)
    
    if [ ${#package_files[@]} -eq 0 ]; then
        echo -e "${YELLOW}  No package files found, skipping...${NC}"
        rm -rf "$temp_dir"
        continue
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
        relative_path=$(realpath --relative-to="$temp_repo_path" "${package_files[$i]}")
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
    
    # Run the scan
    echo -e "${BLUE}  Running malicious package scan...${NC}"
    
    if output=$("$TOOL_PATH" 2>&1 < "$config_file"); then
        scanned_repos=$((scanned_repos + 1))
        
        # Check if any malicious packages were found
        if echo "$output" | grep -q "malicious_packages"; then
            found_malicious=$((found_malicious + 1))
            echo -e "${RED}  ⚠️  MALICIOUS PACKAGES FOUND!${NC}"
            
            # Save results
            echo "=== MALICIOUS PACKAGES FOUND IN: $repo_name ===" >> "$SCAN_RESULTS_FILE"
            echo "Repository: $repo_path" >> "$SCAN_RESULTS_FILE"
            echo "Scan output:" >> "$SCAN_RESULTS_FILE"
            echo "$output" >> "$SCAN_RESULTS_FILE"
            echo "" >> "$SCAN_RESULTS_FILE"
            echo "----------------------------------------" >> "$SCAN_RESULTS_FILE"
            echo "" >> "$SCAN_RESULTS_FILE"
            
            # Display the malicious packages found
            echo "$output" | grep -A 5 -B 5 "malicious_packages" || true
        else
            echo -e "${GREEN}  ✅ No malicious packages found${NC}"
        fi
    else
        echo -e "${RED}  ❌ Scan failed:${NC}"
        echo "$output"
    fi
    
    # Cleanup
    rm -f "$config_file"
    rm -rf "$temp_dir"
    
    echo ""
    
done < <(find "$PARENT_DIR" -maxdepth 2 -type d -name ".git" -print0 | sed 's|/.git$||' | sort -z)

# Summary
echo -e "${BLUE}=== SCAN SUMMARY ===${NC}"
echo -e "Total repositories found: ${YELLOW}$total_repos${NC}"
echo -e "Repositories scanned: ${GREEN}$scanned_repos${NC}"
echo -e "Repositories with malicious packages: ${RED}$found_malicious${NC}"
echo ""
echo -e "${BLUE}Detailed results saved to: ${YELLOW}$SCAN_RESULTS_FILE${NC}"

if [ $found_malicious -gt 0 ]; then
    echo -e "${RED}⚠️  MALICIOUS PACKAGES WERE FOUND! Please review the results above.${NC}"
    exit 1
else
    echo -e "${GREEN}✅ No malicious packages found in any repository.${NC}"
    exit 0
fi
