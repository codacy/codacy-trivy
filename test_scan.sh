#!/bin/bash

# Simple test script to debug the scanning issue

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Tool path
TOOL_PATH="./codacy-trivy"

# Test with a single repository
TEST_REPO="../cppcheck"
REPO_NAME=$(basename "$TEST_REPO")

echo -e "${BLUE}Testing scan with repository: $REPO_NAME${NC}"

# Create a temporary directory for the scan
temp_dir=$(mktemp -d)
echo "Temp directory: $temp_dir"

# Copy the repository to temp directory
cp -r "$TEST_REPO" "$temp_dir/"
temp_repo_path="$temp_dir/$REPO_NAME"

# Find package files
echo -e "${BLUE}Looking for package files...${NC}"
package_files=()
while IFS= read -r file; do
    if [ -n "$file" ]; then
        package_files+=("$file")
        echo "Found: $file"
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

echo -e "${BLUE}Found ${#package_files[@]} package files${NC}"

if [ ${#package_files[@]} -eq 0 ]; then
    echo -e "${YELLOW}No package files found${NC}"
    rm -rf "$temp_dir"
    exit 0
fi

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

echo -e "${BLUE}Configuration:${NC}"
echo "$config_json"

# Write configuration to temporary file
config_file=$(mktemp)
echo "$config_json" > "$config_file"

# Run the scan
echo -e "${BLUE}Running malicious package scan...${NC}"

if output=$("$TOOL_PATH" 2>&1 < "$config_file"); then
    echo -e "${GREEN}Scan completed successfully${NC}"
    echo "Output:"
    echo "$output"
    
    # Check if any malicious packages were found
    if echo "$output" | grep -q "malicious_packages"; then
        echo -e "${RED}⚠️  MALICIOUS PACKAGES FOUND!${NC}"
    else
        echo -e "${GREEN}✅ No malicious packages found${NC}"
    fi
else
    echo -e "${RED}❌ Scan failed:${NC}"
    echo "$output"
fi

# Cleanup
rm -f "$config_file"
rm -rf "$temp_dir"
