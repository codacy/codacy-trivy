#!/bin/bash

# Final script to scan all git repositories in the parent directory for malicious packages
# using the codacy-trivy Docker container with proper configuration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Docker image name
DOCKER_IMAGE="codacy-trivy"

# Check if Docker image exists
if ! docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
    echo -e "${RED}Error: Docker image $DOCKER_IMAGE not found${NC}"
    echo "Please build the Docker image first with: docker build -t codacy-trivy ."
    exit 1
fi

# Results file
SCAN_RESULTS_FILE="malicious_packages_scan_results.txt"

echo -e "${BLUE}Starting malicious package scan of all git repositories in ../${NC}"
echo "Results will be saved to: $SCAN_RESULTS_FILE"
echo ""

# Clear previous results
> "$SCAN_RESULTS_FILE"

# Counter for repositories
total_repos=0
scanned_repos=0
found_malicious=0

# Function to create .codacyrc configuration
create_codacyrc() {
    local repo_path="$1"
    local config_file="$2"
    
    # Find package files in the repository
    local files=()
    while IFS= read -r line; do
        # strip leading ./
        line="${line#./}"
        if [ -n "$line" ]; then
            files+=("$line")
        fi
    done < <(cd "$repo_path" && \
        find . -type f \( \
            -name go.mod -o \
            -name 'package.json' -o -name 'package-lock.json' -o -name yarn.lock -o \
            -name requirements.txt -o -name Pipfile -o -name Pipfile.lock -o \
            -name composer.lock -o -name Gemfile.lock -o -name Cargo.lock -o \
            -name pom.xml -o -name 'build.sbt.lock' -o \
            -name gradle.lockfile -o -name Package.resolved -o -name Package.swift \
        \) ! -path "*/node_modules/*" ! -path "*/vendor/*" ! -path "*/.git/*" 2>/dev/null)
    
    if [ "${#files[@]}" -eq 0 ]; then
        return 1
    fi
    
    # Create the .codacyrc configuration
    {
        echo '{'
        echo '  "files": ['
        local first=1
        for f in "${files[@]}"; do
            if [ $first -eq 1 ]; then first=0; else echo ','; fi
            printf '    "%s"' "$f"
        done
        echo
        echo '  ],'
        echo '  "tools": ['
        echo '    { "name": "trivy", "patterns": ['
        echo '        { "patternId": "malicious_packages" }'
        echo '      ] }'
        echo '  ]'
        echo '}'
    } > "$config_file"
    
    return 0
}

# Function to run scan on a repository
run_scan_on_repo() {
    local repo_path="$1"
    local repo_name=$(basename "$repo_path")
    
    echo -e "${YELLOW}[$total_repos] Scanning repository: $repo_name${NC}"
    
    # Create temporary configuration file
    local config_file=$(mktemp)
    
    # Create .codacyrc configuration
    if ! create_codacyrc "$repo_path" "$config_file"; then
        echo -e "${YELLOW}  No package files found, skipping...${NC}"
        rm -f "$config_file"
        return 0
    fi
    
    echo -e "${BLUE}  Created configuration with package files${NC}"
    
    # Run the scan using Docker
    echo -e "${BLUE}  Running malicious package scan...${NC}"
    
    if output=$(docker run --rm \
        -v "$repo_path:/src" \
        -v "$config_file:/.codacyrc:ro" \
        "$DOCKER_IMAGE" 2>&1); then
        
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
            rm -f "$config_file"
            return 1
        else
            echo -e "${GREEN}  ✅ No malicious packages found${NC}"
        fi
    else
        echo -e "${RED}  ❌ Scan failed:${NC}"
        echo "$output"
        rm -f "$config_file"
        return 1
    fi
    
    # Cleanup
    rm -f "$config_file"
    return 0
}

# Find all git repositories in parent directory
while IFS= read -r repo_path; do
    total_repos=$((total_repos + 1))
    
    if run_scan_on_repo "$repo_path"; then
        :
    else
        found_malicious=$((found_malicious + 1))
    fi
    
    echo ""
    
done < <(find "$(pwd)/../" -maxdepth 2 -type d -name ".git" | sed 's|/.git$||' | sort)

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
