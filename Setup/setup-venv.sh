#!/usr/bin/env bash

# Create Python virtual environment and install dependencies
setup_venv() {
    printf "\e[1;31m[+] Setting up Python virtual environment...\e[0m\n"
    python3 -m venv venv
    source venv/bin/activate
    if [[ -f requirements.txt ]]; then
        pip install -r requirements.txt
    else
        printf "\e[1;31mRequirements.txt not found. Skipping Python dependencies installation.\e[0m\n"
    fi
}
setup_venv
