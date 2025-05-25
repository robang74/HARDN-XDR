#!/bin/bash

# Test script to verify CSV parsing logic
printf "Testing CSV parsing logic for progs.csv format...\n\n"

# Test the parsing logic with sample data
test_csv_content="name,version
git,1:2.49.0-0ubuntu1~ubuntu24.04.1
dpkg-dev,1.22.6ubuntu6.1
ufw,0.36.2-6
libvirt-daemon-system,
libvirt-clients,
openssh-server,1:9.6p1-3ubuntu13.11"

echo "$test_csv_content" | while IFS= read -r line || [[ -n "$line" ]]; do
    # Skip empty lines and comments
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    
    # Skip header line
    [[ "$line" == "name,version" ]] && continue
    
    # Handle both formats: CSV (name,version) or simple list (name)
    if [[ "$line" == *","* ]]; then
        # CSV format: extract name from first column
        name=$(echo "$line" | cut -d',' -f1 | tr -d '"' | xargs)
        version=$(echo "$line" | cut -d',' -f2 | tr -d '"' | xargs)
    else
        # Simple format: line is the package name
        name=$(echo "$line" | xargs)
        version=""
    fi
    
    if [[ -n "$name" ]]; then
        if [[ -n "$version" ]]; then
            printf "Package: %s, Version: %s\n" "$name" "$version"
        else
            printf "Package: %s, Version: (empty)\n" "$name"
        fi
    fi
done

printf "\n✓ CSV parsing test completed successfully!\n"
