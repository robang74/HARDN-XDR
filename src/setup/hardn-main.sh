#!/bin/bash

# HARDN-XDR - The Linux Security Hardening Sentinel
# Developed and built by chris Bingham and Tim Burns
# credit due: larbs.xyz

repo="https://github.com/OpenSource-For-Freedom/HARDN/"
progsfile="https://github.com/OpenSource-For-Freedom/HARDN/progs.csv"
repobranch="main-patch"
name=$(whoami)

CUSTOM_LOG_FILE="/var/log/HARDN.lg"

############# ADD MENU HERE #############



print_ascii_banner() {
    log_event "INFO" "Displaying ASCII banner."
    cat << "EOF"

   ▄█    █▄            ▄████████         ▄████████      ████████▄       ███▄▄▄▄   
  ███    ███          ███    ███        ███    ███      ███   ▀███      ███▀▀▀██▄ 
  ███    ███          ███    ███        ███    ███      ███    ███      ███   ███ 
 ▄███▄▄▄▄███▄▄        ███    ███       ▄███▄▄▄▄██▀      ███    ███      ███   ███ 
▀▀███▀▀▀▀███▀       ▀███████████      ▀▀███▀▀▀▀▀        ███    ███      ███   ███ 
  ███    ███          ███    ███      ▀███████████      ███    ███      ███   ███ 
  ███    ███          ███    ███        ███    ███      ███   ▄███      ███   ███ 
  ███    █▀           ███    █▀         ███    ███      ████████▀        ▀█   █▀  
                                        ███    ███ 
                           
                            Extended Detection and Response
                            by Security International Group
                                   Version 1.1.8
EOF
}


# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
        echo ""
        echo "This script must be run as root."
        exit 1
fi

installpkg() {
    log_event "INFO" "Attempting to install package: $1 (via installpkg function)."
    if dpkg -s "$1" >/dev/null 2>&1; then
        log_event "INFO" "Package $1 already installed (checked by installpkg)."
    else
        if sudo apt install -y "$1"; then
            log_event "INFO" "Package $1 installed successfully (by installpkg)."
        else
            log_event "ERROR" "Failed to install package $1 (by installpkg)."
            return 1
        fi
    fi
    return 0
}

error() {
    log_event "FATAL" "Error function called: $1"
    printf "%s\\n" "$1" >&2
    exit 1
}

welcomemsg() {
    log_event "INFO" "Displaying welcome message."

        whiptail --title "HARDN-XDR" --backtitle "HARDN OS Security" --fb \
            --msgbox "\n\n Welcome to HARDN-XDR a Debian Security tool for System Hardening" 15 60

        whiptail --title "HARDN-XDR" --backtitle "HARDN OS Security" --fb \
            --yes-button "HARDN" \
            --no-button "RETURN..." \
            --yesno "\n\n\nThis installer will update your system first..\n\n" 12 70
    # Log user choice from whiptail
    local choice_status=$?
    if [ $choice_status -ne 0 ]; then
        log_event "INFO" "User chose 'RETURN...' or closed welcome message."
    else
        log_event "INFO" "User chose 'HARDN' on welcome message."
    fi
    return $choice_status
}

preinstallmsg() {
    log_event "INFO" "Displaying pre-install message."
    whiptail --title "Welcome to HARDN. A Linux Security Hardening program." --yes-button "HARDN" \
            --no-button "RETURN" \
            --yesno "\n\n\nThe Building the Debian System to ensure STIG and Security compliance\n\n" 13 60 || {
            clear
            exit 1
    }
    local choice_status=$?
    if [ $choice_status -ne 0 ]; then
        log_event "INFO" "User aborted at pre-install message (chose RETURN or closed)."
        clear
        exit 1
    else
        log_event "INFO" "User proceeded past pre-install message (chose HARDN)."
    fi
}

update_system_packages() {
    log_event "INFO" "Starting system package update/upgrade."
    printf "\\033[1;31m[+] Updating system packages...\\033[0m\\n"
    whiptail --title "System Update" --infobox "Updating package lists..." 8 70
    if ! apt-get update -y; then
        log_event "ERROR" "Failed to update package lists."
        whiptail --title "Error" --msgbox "Failed to update package lists. Please check your network connection and APT sources." 10 70
        printf "\\033[1;31m[-] Failed to update package lists.\\033[0m\\n"
        return 1
    fi
    log_event "INFO" "Package lists updated successfully."
    whiptail --title "System Update" --infobox "Upgrading installed packages... This may take a while." 8 70
    if ! apt-get upgrade -y; then
        log_event "WARN" "Failed to upgrade all packages. Some packages might not have been upgraded."
        whiptail --title "Warning" --msgbox "Failed to upgrade all packages. Some packages might not have been upgraded. Please check for errors." 10 70
        printf "\\033[1;33m[!] Failed to upgrade all packages. Continuing script execution.\\033[0m\\n"
    else
        log_event "INFO" "System packages upgraded successfully."
    fi
    printf "\\033[1;32m[+] System package update/upgrade process completed.\\033[0m\\n"
    log_event "INFO" "System package update/upgrade process finished."
}

install_package_dependencies() {
    printf "\\033[1;31m[+] Checking package: %s...\\033[0m\\n" "$1"
    local package_name="$1"
    # Assuming $2 is a description passed by the caller, as in the original whiptail message.

    if dpkg -s "$package_name" >/dev/null 2>&1; then
        whiptail --infobox "$package_name is already installed." 7 60
        return 0
    else
        whiptail --infobox "Installing $package_name... ($2)" 7 60 # $2 is from the original function's usage
        if sudo apt install -y "$package_name" >/dev/null 2>&1; then
            # Verify installation
            if dpkg -s "$package_name" >/dev/null 2>&1; then
                whiptail --title "Success" --msgbox "$package_name installed successfully." 7 60
                return 0
            else
                whiptail --title "Error" --msgbox "Installation of $package_name reported success, but package not found post-install. Check logs." 10 78
                return 1
            fi
        else
            whiptail --title "Error" --msgbox "Failed to install $package_name. Please check APT logs." 10 70
            return 1
        fi
    fi
}


aptinstall() {
    local package="$1"
    local comment="$2"
    log_event "INFO" "aptinstall: Processing package '$package' ($n of $total). Comment: $comment"

    if dpkg -s "$package" >/dev/null 2>&1; then
        log_event "INFO" "aptinstall: Package '$package' is already installed."
        whiptail --title "HARDN Package Processing" \\
            --infobox "\`$package\` ($n of $total) is already installed. $comment" 9 70
        return 0 
    else
        log_event "INFO" "aptinstall: Attempting to install '$package'."
        whiptail --title "HARDN Package Installation" \\
            --infobox "Installing \`$package\` ($n of $total) from repository. $comment" 9 70
        if apt-get install -y "$package" >/dev/null 2>&1; then
            if dpkg -s "$package" >/dev/null 2>&1; then
                log_event "INFO" "aptinstall: Successfully installed '$package'."
                whiptail --title "HARDN Package Installation" \\
                    --infobox "Successfully installed \`$package\` ($n of $total). $comment" 9 70
                return 0
            else
                log_event "ERROR" "aptinstall: Installation of '$package' reported success, but package not found post-install."
                whiptail --title "HARDN Package Installation" --msgbox "Installation of \`$package\` ($n of $total) reported success, but package not found post-install. $comment. Please check logs." 10 78
                return 1
            fi
        else
            log_event "ERROR" "aptinstall: Failed to install '$package'."
            whiptail --title "HARDN Package Installation" --msgbox "Failed to install \`$package\` ($n of $total). $comment. Please check logs." 9 70
            return 1 
        fi
    fi
}

maininstall() {
    log_event "INFO" "maininstall: Queuing package '$1' for installation ($n of $total). Comment: $2"
    whiptail --title "HARDN Installation" --infobox "Installing \`$1\` ($n of $total). $1 $2" 9 70
    installpkg "$1"
}

gitdpkgbuild() {
    repo_url="$1"
    description="$2"
    dir="/tmp/$(basename "$repo_url" .git)"
    log_event "INFO" "gitdpkgbuild: Starting build for $description from $repo_url."

    whiptail --infobox "Cloning $repo_url... ($description)" 7 70
    if ! git clone --depth=1 "$repo_url" "$dir" >/dev/null 2>&1; then
        log_event "ERROR" "gitdpkgbuild: Failed to clone $repo_url."
        whiptail --msgbox "Failed to clone $repo_url" 8 60
        return 1
    fi
    log_event "INFO" "gitdpkgbuild: Cloned $repo_url to $dir."

    cd "$dir" || { 
        log_event "ERROR" "gitdpkgbuild: Failed to enter $dir."
        whiptail --msgbox "Failed to enter $dir" 8 60; 
        return 1; 
    }
    log_event "INFO" "gitdpkgbuild: Changed directory to $dir."

    whiptail --infobox "Building and installing $description..." 7 70
    log_event "INFO" "gitdpkgbuild: Checking build dependencies for $description."
    build_deps=$(dpkg-checkbuilddeps 2>&1 | grep -oP 'Unmet build dependencies: \K.*')
    if [ -n "$build_deps" ]; then
        log_event "INFO" "gitdpkgbuild: Installing build dependencies: $build_deps"
        whiptail --infobox "Installing build dependencies: $build_deps" 7 70
        if ! apt-get install -y $build_deps >/dev/null 2>&1; then
            log_event "ERROR" "gitdpkgbuild: Failed to install build dependencies: $build_deps"
            whiptail --msgbox "Failed to install build dependencies for $description. Check logs." 8 70
            # Optionally return 1 here, or let the build fail
        else
            log_event "INFO" "gitdpkgbuild: Successfully installed build dependencies: $build_deps"
        fi
    else
        log_event "INFO" "gitdpkgbuild: No unmet build dependencies for $description."
    fi

    if [ -f debian/source/format ]; then
        log_event "INFO" "gitdpkgbuild: Running dpkg-source --before-build for $description."
        dpkg-source --before-build . >/dev/null 2>&1
    fi

    log_event "INFO" "gitdpkgbuild: Attempting to build $description using dpkg-buildpackage."
    if dpkg-buildpackage -us -uc >/dev/null 2>&1; then
        log_event "INFO" "gitdpkgbuild: Build successful for $description."
        debfile=$(ls ../*.deb | head -n1)
        if [ -n "$debfile" ]; then
            log_event "INFO" "gitdpkgbuild: Found .deb file: $debfile. Installing..."
            if dpkg -i "$debfile"; then
                log_event "INFO" "gitdpkgbuild: Successfully installed $debfile for $description."
            else
                log_event "ERROR" "gitdpkgbuild: Failed to install $debfile for $description."
                whiptail --msgbox "Failed to install $debfile for $description." 8 60
                return 1
            fi
        else
            log_event "ERROR" "gitdpkgbuild: No .deb file found after successful build for $description."
            whiptail --msgbox "No .deb file found after build for $description." 8 60
            return 1
        fi
    else
        log_event "WARN" "gitdpkgbuild: Initial build failed for $description. Attempting to install common build dependencies and retry."
        whiptail --infobox "$description failed to build. Installing common build dependencies and retrying..." 10 60
        COMMON_BUILD_DEPS="build-essential debhelper libpam-tmpdir apt-listbugs devscripts git-buildpackage"
        log_event "INFO" "gitdpkgbuild: Installing common build deps: $COMMON_BUILD_DEPS"
        if ! apt-get install -y $COMMON_BUILD_DEPS >/dev/null 2>&1; then
            log_event "ERROR" "gitdpkgbuild: Failed to install common build dependencies. Build for $description will likely fail."
        else 
            log_event "INFO" "gitdpkgbuild: Installed common build dependencies. Retrying build."
        fi
        
        if dpkg-buildpackage -us -uc >/dev/null 2>&1; then
            log_event "INFO" "gitdpkgbuild: Build successful for $description after retry."
            debfile=$(ls ../*.deb | head -n1)
            if [ -n "$debfile" ]; then
                log_event "INFO" "gitdpkgbuild: Found .deb file after retry: $debfile. Installing..."
                if dpkg -i "$debfile"; then
                    log_event "INFO" "gitdpkgbuild: Successfully installed $debfile for $description after retry."
                else
                    log_event "ERROR" "gitdpkgbuild: Failed to install $debfile for $description after retry."
                    whiptail --msgbox "Failed to install $debfile for $description after retry." 8 60
                    return 1
                fi
            else
                log_event "ERROR" "gitdpkgbuild: No .deb file found after successful retry build for $description."
                whiptail --msgbox "No .deb file found after retry for $description." 8 60
                return 1
            fi
        else
            log_event "ERROR" "gitdpkgbuild: Build for $description failed after retry and installing common dependencies."
            whiptail --msgbox "$description failed to build after retry. Please check build dependencies and logs." 10 60
            return 1
        fi
    fi
    log_event "INFO" "gitdpkgbuild: Finished processing $description."
    cd -
    rm -rf "$dir"
    return 0
}

build_hardn_package() {
    log_event "INFO" "Starting HARDN package build process."
    set -e  
    build_deps="debhelper-compat devscripts git-buildpackage"
    log_event "INFO" "Required build dependencies: $build_deps."
    whiptail --infobox "Installing build dependencies: $build_deps" 7 60
    for pkg in $build_deps; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            log_event "INFO" "Installing missing build dependency: $pkg."
            echo "[+] Installing missing dependencies: $pkg" 
            if ! apt-get install -y "$pkg" >/dev/null 2>&1; then
                log_event "ERROR" "Failed to install build dependency: $pkg. Build may fail."
                whiptail --msgbox "Failed to install build dependency $pkg. The HARDN package build might fail." 8 78
            else
                log_event "INFO" "Successfully installed build dependency: $pkg."
            fi
        else
            log_event "INFO" "Build dependency $pkg already installed."
        fi
    done 

    log_event "INFO" "Building HARDN Debian package..."
    whiptail --infobox "Building HARDN Debian package..." 7 60

    temp_dir=$(mktemp -d)
    log_event "INFO" "Created temporary directory for build: $temp_dir."
    cd "$temp_dir"

    log_event "INFO" "Cloning repository $repo (branch $repobranch) into $temp_dir/HARDN."
    if ! git clone --depth=1 -b "$repobranch" "$repo" HARDN; then # Added HARDN to clone into specific subdir
        log_event "ERROR" "Failed to clone repository $repo."
        whiptail --msgbox "Failed to clone the HARDN repository. Cannot build package." 8 78
        cd /
        rm -rf "$temp_dir"
        return 1
    fi
    cd HARDN

    log_event "INFO" "Running dpkg-buildpackage in $temp_dir/HARDN."
    whiptail --infobox "Running dpkg-buildpackage..." 7 60
    if ! dpkg-buildpackage -us -uc; then
        log_event "ERROR" "dpkg-buildpackage failed for HARDN."
        whiptail --msgbox "dpkg-buildpackage failed. Cannot create HARDN package. Check build logs." 8 78
        cd /
        rm -rf "$temp_dir"
        return 1
    fi

    cd .. # Back to $temp_dir
    log_event "INFO" "Installing HARDN package from $temp_dir."
    whiptail --infobox "Installing HARDN package..." 7 60
    local deb_file
    deb_file=$(ls hardn_*.deb 2>/dev/null | head -n1)
    if [ -z "$deb_file" ]; then
        log_event "ERROR" "No .deb file found in $temp_dir after build."
        whiptail --msgbox "No HARDN .deb package found after build. Installation failed." 8 78
        cd /
        rm -rf "$temp_dir"
        return 1
    fi

    log_event "INFO" "Found HARDN package: $deb_file. Attempting installation."
    if ! dpkg -i "$deb_file"; then # Removed || true to catch actual errors
        log_event "WARN" "dpkg -i $deb_file failed. Attempting to fix broken dependencies."
        if ! apt-get install -f -y; then # This will try to fix and install
            log_event "ERROR" "Failed to install HARDN package $deb_file even after apt-get -f install."
            whiptail --msgbox "Failed to install HARDN package $deb_file. Check logs." 8 78
            cd /
            rm -rf "$temp_dir"
            return 1
        else 
            log_event "INFO" "Successfully installed HARDN package $deb_file after apt-get -f install."
        fi
    else
        log_event "INFO" "Successfully installed HARDN package $deb_file."
    fi

    cd /
    rm -rf "$temp_dir"
    log_event "INFO" "Cleaned up temporary build directory $temp_dir."

    whiptail --infobox "HARDN package installed successfully" 7 60
    log_event "INFO" "HARDN package build and installation process completed."
    set +e # Reset set -e if it was set locally for this function
}

installationloop() {
    log_event "INFO" "Starting installation loop from progsfile: $progsfile."
    if [[ "$progsfile" == http* ]]; then
        log_event "INFO" "Fetching progs.csv from URL: $progsfile."
        if ! curl -Ls "$progsfile" | sed '/^#/d' > /tmp/progs.csv; then
            log_event "ERROR" "Failed to download progs.csv from $progsfile."
            whiptail --title "Error" --msgbox "Failed to download progs.csv from $progsfile." 8 70
            return 1
        fi
    elif [ -f "$progsfile" ]; then
        log_event "INFO" "Using local progs.csv file: $progsfile."
        if ! sed '/^#/d' < "$progsfile" > /tmp/progs.csv; then
            log_event "ERROR" "Failed to process local progs.csv file $progsfile."
            whiptail --title "Error" --msgbox "Failed to process local progs.csv $progsfile." 8 70
            return 1
        fi
    else
        log_event "ERROR" "progs.csv file not found at $progsfile and not a valid URL."
        whiptail --title "Error" --msgbox "progs.csv file not found at $progsfile and not a valid URL." 8 70
        return 1
    fi

    total=$(wc -l </tmp/progs.csv)
    log_event "INFO" "Found $total entries to process in progs.csv."
    echo "[INFO] Found $total entries to process."
    n=0 
    while IFS=, read -r tag program comment; do
        n=$((n + 1))
        log_event "DEBUG" "Processing entry $n/$total: Tag='$tag', Program='$program', Comment='$comment'"
        echo "➤ Processing: $program [$tag]"

        echo "$comment" | grep -q "^\".*\"$" && \
            comment="$(echo "$comment" | sed -E "s/(^\"|\"$)//g")"

        case "$tag" in
            a) aptinstall "$program" "$comment" ;;
            G) gitdpkgbuild "$program" "$comment" ;;
            *) 
               if [ -z "$program" ]; then
                   log_event "WARN" "Skipping empty program entry (Tag: $tag, Line: $n) in progs.csv."
                   whiptail --title "Warning" --msgbox "Skipping empty program entry (Tag: $tag, Line: $n)" 8 70
               else
                   log_event "INFO" "Defaulting to aptinstall for program '$program' (Tag: $tag, Line: $n)."
                   aptinstall "$program" "$comment"
               fi
               ;;
        esac
    done </tmp/progs.csv
    log_event "INFO" "Finished installation loop."
}

putgitrepo() {
    local repo_url="$1"
    local target_dir="$2"
    local branch_name="$3"

    log_event "INFO" "putgitrepo: Starting process for $repo_url into $target_dir (branch: ${branch_name:-master})."
    printf "\\033[1;32m[+] Downloading and installing files from $repo_url...\\033[0m\\n"
    
    [ -z "$branch_name" ] && branch_name="master"
    
    local temp_clone_dir
    temp_clone_dir=$(mktemp -d)
    log_event "DEBUG" "putgitrepo: Created temp clone directory $temp_clone_dir."

    if [ -z "$target_dir" ]; then
        log_event "ERROR" "putgitrepo: Target directory not specified for $repo_url."
        whiptail --title "Error" --msgbox "Target directory for git repository is not specified." 8 70
        rm -rf "$temp_clone_dir"
        return 1
    fi
   
    if ! mkdir -p "$target_dir"; then
        log_event "ERROR" "putgitrepo: Failed to create target directory $target_dir."
        whiptail --title "Error" --msgbox "Failed to create target directory $target_dir. Check permissions." 8 70
        rm -rf "$temp_clone_dir"
        return 1
    fi
    log_event "DEBUG" "putgitrepo: Ensured target directory $target_dir exists."

    # Set ownership for temp and target dirs to current user to allow git clone as user
    if ! chown "$name":"$(id -gn "$name")" "$temp_clone_dir"; then 
        log_event "WARN" "putgitrepo: Failed to chown temp_clone_dir $temp_clone_dir. Git clone might fail if run as non-root user."
    fi
    if ! chown "$name":"$(id -gn "$name")" "$target_dir"; then
        log_event "WARN" "putgitrepo: Failed to chown target_dir $target_dir. Copy might fail if run as non-root user."
    fi

    if [ -z "$repo_url" ]; then
        log_event "ERROR" "putgitrepo: Git repository URL is not specified."
        whiptail --title "Error" --msgbox "Git repository URL is not specified." 8 70
        rm -rf "$temp_clone_dir"
        return 1
    fi

    log_event "INFO" "putgitrepo: Cloning $repo_url (branch $branch_name) as user $name into $temp_clone_dir."
    if ! sudo -u "$name" git clone --depth 1 \
        --single-branch --no-tags -q --recursive -b "$branch_name" \
        --recurse-submodules "$repo_url" "$temp_clone_dir"; then
        log_event "ERROR" "putgitrepo: Failed to clone repository: $repo_url."
        whiptail --title "Error" --msgbox "Failed to clone repository: $repo_url" 8 70
        rm -rf "$temp_clone_dir"
        return 1
    fi
    log_event "INFO" "putgitrepo: Successfully cloned $repo_url."
      
    log_event "INFO" "putgitrepo: Copying files from $temp_clone_dir to $target_dir as user $name."
    if ! sudo -u "$name" cp -rfT "$temp_clone_dir/" "$target_dir/"; then # Added trailing slashes for clarity
        log_event "ERROR" "putgitrepo: Failed to copy files from $temp_clone_dir to $target_dir."
        whiptail --title "Error" --msgbox "Failed to copy files from $temp_clone_dir to $target_dir. Check permissions and paths." 8 70
        rm -rf "$temp_clone_dir"
        return 1
    fi
    log_event "INFO" "putgitrepo: Successfully copied files to $target_dir."
    
    rm -rf "$temp_clone_dir"
    log_event "DEBUG" "putgitrepo: Cleaned up temp clone directory $temp_clone_dir."
    log_event "INFO" "putgitrepo: Process for $repo_url completed."
    return 0
}

enable_selinux() {
    log_event "INFO" "Starting SELinux status check and configuration (MACF-6208)."
    printf "\\033[1;31m[+] Checking and configuring SELinux (MACF-6208)...\\033[0m\\n"

    if ! command -v sestatus > /dev/null 2>&1 || ! command -v getenforce > /dev/null 2>&1 || ! command -v setenforce > /dev/null 2>&1; then
        log_event "INFO" "SELinux tools (sestatus, getenforce, setenforce) not found. Attempting to install policycoreutils."
        whiptail --title "SELinux Tools Missing" --infobox "SELinux tools not found. Installing policycoreutils..." 8 78
        aptinstall "policycoreutils" "SELinux core utilities"
        if ! command -v sestatus > /dev/null 2>&1; then
            log_event "ERROR" "Failed to install policycoreutils. Cannot manage SELinux."
            whiptail --title "Error" --msgbox "Failed to install SELinux utilities (policycoreutils). SELinux configuration aborted." 8 78
            return 1
        fi
    fi

    local current_status
    current_status=$(getenforce)
    log_event "INFO" "Current SELinux status: $current_status."
    whiptail --title "SELinux Status" --infobox "Current SELinux status: $current_status" 8 78
    sleep 1

    if [ "$current_status" != "Enforcing" ]; then
        log_event "WARN" "SELinux is not in Enforcing mode. Attempting to set to Enforcing."
        whiptail --title "SELinux Configuration" --infobox "SELinux is not Enforcing. Attempting to set to Enforcing mode..." 8 78
        if setenforce 1; then
            log_event "INFO" "Successfully set SELinux to Enforcing mode for the current session."
            whiptail --title "SELinux Configuration" --infobox "SELinux set to Enforcing for current session." 8 78
            current_status=$(getenforce) # Re-check
            log_event "INFO" "New SELinux status: $current_status."
        else
            log_event "ERROR" "Failed to set SELinux to Enforcing mode using setenforce 1."
            whiptail --title "Error" --msgbox "Failed to set SELinux to Enforcing mode. Check system logs. Manual intervention may be required." 10 78
            # Proceed to configure persistent, but warn user
        fi
    else
        log_event "INFO" "SELinux is already in Enforcing mode."
    fi
    sleep 1

    if [ -f /etc/selinux/config ]; then
        log_event "INFO" "Checking persistent SELinux configuration in /etc/selinux/config."
        if grep -q "^SELINUX=enforcing" /etc/selinux/config; then
            log_event "INFO" "SELinux is already configured to be Enforcing at boot in /etc/selinux/config."
            whiptail --title "SELinux Configuration" --infobox "SELinux already set to Enforcing at boot." 8 78
        else
            log_event "WARN" "SELinux is not set to Enforcing at boot. Modifying /etc/selinux/config."
            sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
            if grep -q "^SELINUX=enforcing" /etc/selinux/config; then
                log_event "INFO" "Successfully set SELINUX=enforcing in /etc/selinux/config."
                whiptail --title "SELinux Configuration" --infobox "SELinux configured to Enforcing at boot." 8 78
            else
                log_event "ERROR" "Failed to set SELINUX=enforcing in /etc/selinux/config."
                whiptail --title "Error" --msgbox "Failed to modify /etc/selinux/config to set Enforcing mode. Check permissions." 10 78
            fi
        fi
    else
        log_event "WARN" "/etc/selinux/config not found. Cannot set persistent SELinux mode."
        whiptail --title "Warning" --msgbox "SELinux config file (/etc/selinux/config) not found. Cannot ensure Enforcing mode at boot." 10 78
    fi
    sleep 1

    # Final check with sestatus if available
    if command -v sestatus > /dev/null 2>&1; then
        sestatus_output=$(sestatus)
        log_event "INFO" "Final SELinux status details:\n$sestatus_output"
        whiptail --title "SELinux Final Status" --msgbox "SELinux status:\n$(sestatus | head -n 3)" 10 78 # Show first 3 lines
    fi

    printf "\\033[1;32m[+] SELinux check and configuration (MACF-6208) complete.\\033[0m\\n"
    log_event "INFO" "SELinux status check and configuration (MACF-6208) finished."
}


check_security_tools() {
  log_event "INFO" "Starting check for essential security packages."
  printf "\\033[1;31m[+] Checking for security packages are installed...\\033[0m\\n"
  local all_successful=0 
  local pkg
  local packages_to_check=("ufw" "fail2ban" "apparmor" "apparmor-profiles" "apparmor-utils" "firejail" "tcpd" "lynis" "debsums" "rkhunter" "libpam-pwquality" "libvirt-daemon-system" "libvirt-clients" "qemu-kvm" "docker.io" "docker-compose" "openssh-server")
  log_event "DEBUG" "List of packages to check: ${packages_to_check[*]}"

  for pkg in "${packages_to_check[@]}"; do
    log_event "INFO" "Checking package: $pkg."
    whiptail --title "Security Tool Check" --infobox "Checking $pkg..." 8 70
    if dpkg -s "$pkg" >/dev/null 2>&1; then
      log_event "INFO" "Package $pkg is already installed."
      whiptail --title "Security Tool Check" --infobox "$pkg is already installed." 8 70
      sleep 1
    else
      log_event "WARN" "Package $pkg is not installed. Attempting installation."
      whiptail --title "Security Tool Installation" --infobox "Installing $pkg..." 8 70
      if aptinstall "$pkg" "Essential security tool"; then # aptinstall returns 0 on success
        log_event "INFO" "Successfully installed $pkg via aptinstall wrapper."
        # Whiptail message for success is handled by aptinstall
      else
        log_event "ERROR" "Failed to install $pkg via aptinstall wrapper."
        
        all_successful=1 # Mark that at least one package failed
      fi
    fi
  done

  if [ "$all_successful" -eq 0 ]; then
    log_event "INFO" "All essential security tools checked and are installed/verified."
    whiptail --title "Security Tool Check Complete" --msgbox "All essential security tools checked and installed/verified." 10 70
  else
    log_event "WARN" "Some security tools could not be installed or verified."
    whiptail --title "Security Tool Check Issues" --msgbox "Some security tools could not be installed or verified. Please review the messages above and check logs." 10 70
  fi
  log_event "INFO" "Finished checking essential security packages. Overall status (0=all_ok, 1=issues): $all_successful."
  return "$all_successful"
}

enable_suricata() {
    log_event "INFO" "Starting Suricata setup (enable_suricata function)."
    printf "\\033[1;31m[+] Enabling Suricata...\\033[0m\\n"
    local progress_text="Installing and enabling Suricata..."

    if dpkg -s suricata >/dev/null 2>&1; then
        log_event "INFO" "Suricata is already installed. Verifying service."
        whiptail --title "Suricata Status" --infobox "Suricata is already installed. Verifying service..." 8 70
        progress_text="Verifying and enabling Suricata service..."
    else
        log_event "INFO" "Suricata not installed. Attempting installation."
        whiptail --title "Suricata Installation" --infobox "Installing Suricata..." 8 70
        # Using aptinstall for consistency in logging and user feedback
        if ! aptinstall "suricata" "Network IDS/IPS Suricata"; then
            log_event "ERROR" "Suricata installation failed via aptinstall."
            # aptinstall handles its own whiptail error message
            return 1
        fi
        # aptinstall handles success message
        log_event "INFO" "Suricata installed successfully via aptinstall."
    fi

    log_event "INFO" "Enabling and starting Suricata service."
    local subshell_ret=0
    ( 
        echo 10; sleep 0.1; log_event "DEBUG" "Gauge: Enabling Suricata service..."; echo "Enabling Suricata service...";
        systemctl enable suricata >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            log_event "ERROR" "Failed to enable Suricata service (systemctl enable suricata)."
            echo 100; sleep 0.1; 
            exit 3 # Special return code for enable failure
        fi
        log_event "INFO" "Suricata service enabled."
        echo 50; sleep 0.1; log_event "DEBUG" "Gauge: Starting Suricata service..."; echo "Starting Suricata service...";
        systemctl start suricata >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            log_event "ERROR" "Failed to start Suricata service (systemctl start suricata)."
            echo 100; sleep 0.1; 
            exit 4 # Special return code for start failure
        fi
        log_event "INFO" "Suricata service started."
        echo 100; sleep 0.1
    ) | whiptail --gauge "$progress_text" 8 70 0
    subshell_ret=$?

    if [ $subshell_ret -ne 0 ]; then # Check if subshell exited with non-zero (failure codes 3 or 4)
        if [ $subshell_ret -eq 3 ]; then
             whiptail --title "Error" --msgbox "Failed to ENABLE Suricata service. Please check systemctl status suricata." 10 70
        elif [ $subshell_ret -eq 4 ]; then
             whiptail --title "Error" --msgbox "Failed to START Suricata service. Please check systemctl status suricata." 10 70
        else
             log_event "ERROR" "Suricata service enable/start failed with unknown subshell code: $subshell_ret."
             whiptail --title "Error" --msgbox "Suricata service failed to enable/start (code $subshell_ret). Check logs." 10 70
        fi
        return 1
    fi

    if ! systemctl is-active --quiet suricata; then
        log_event "ERROR" "Suricata service is not active after attempting to enable/start."
        whiptail --title "Error" --msgbox "Suricata service is not active after attempting to enable/start. Please check systemctl status suricata." 10 70
        return 1
    fi

    log_event "INFO" "Suricata is installed, enabled, and running."
    whiptail --title "Success" --msgbox "Suricata is installed and running." 8 70
    printf "\\033[1;32m[+] Suricata enabled and running.\\033[0m\\n"
    return 0
}

enable_rkhunter() {
    log_event "INFO" "Starting rkhunter setup (enable_rkhunter function)."
    {
        echo 10; sleep 0.2
        log_event "DEBUG" "Gauge: Enabling rkhunter..."
        printf "\\033[1;31m[+] Enabling rkhunter...\\033[0m\\n"
        if ! dpkg -s rkhunter >/dev/null 2>&1; then
            log_event "INFO" "rkhunter not installed. Attempting installation."
            whiptail --infobox "Installing rkhunter..." 7 60
            # Using aptinstall for consistency
            if ! aptinstall "rkhunter" "Rootkit Hunter"; then 
                log_event "ERROR" "rkhunter installation failed via aptinstall."
                # aptinstall handles its own whiptail error message
                # To stop the gauge and exit function if install fails:
                echo 100; sleep 0.1; exit 1;
            fi
            log_event "INFO" "rkhunter installed successfully via aptinstall."
        else
            log_event "INFO" "rkhunter is already installed."
            whiptail --infobox "rkhunter is already installed." 7 60
        fi
        echo 40; sleep 0.2; log_event "DEBUG" "Gauge: Configuring rkhunter..."

        log_event "INFO" "Configuring /etc/rkhunter.conf: ENABLE_TESTS=all, MAIL-ON-WARNING/ERROR=root."
        sed -i 's/^#\?ENABLE_TESTS=.*/ENABLE_TESTS=all/' /etc/rkhunter.conf
        sed -i 's/^#\?MAIL-ON-WARNING=.*/MAIL-ON-WARNING="root"/' /etc/rkhunter.conf
        sed -i 's/^#\?MAIL-ON-ERROR=.*/MAIL-ON-ERROR="root"/' /etc/rkhunter.conf
        echo 60; sleep 0.2; log_event "DEBUG" "Gauge: Updating rkhunter data files..."

        log_event "INFO" "Running rkhunter --update."
        if ! rkhunter --update --quiet; then
            log_event "WARN" "rkhunter --update command failed or had warnings."
        fi
        log_event "INFO" "Running rkhunter --propupd."
        if ! rkhunter --propupd --quiet; then
            log_event "WARN" "rkhunter --propupd command failed or had warnings."
        fi
        echo 100; sleep 0.2
    } | whiptail --gauge "Installing and configuring rkhunter..." 8 60 0
    local gauge_status=$?
    if [ $gauge_status -ne 0 ]; then # If aptinstall failed inside gauge and exited with 1
        log_event "ERROR" "rkhunter setup failed during installation phase."
        # No need for whiptail here, aptinstall should have shown it.
        return 1
    fi

    printf "\\033[1;32m[+] rkhunter installed and configured.\\033[0m\\n"
    log_event "INFO" "rkhunter setup finished."
    return 0
}

configure_firejail() {
    log_event "INFO" "Starting Firejail configuration for browsers."
    {
        echo 10; sleep 0.2
        log_event "DEBUG" "Gauge: Configuring Firejail..."
        printf "\\033[1;31m[+] Configuring Firejail for Firefox, Chrome, Brave, and Tor Browser...\\033[0m\\n"

        if ! command -v firejail > /dev/null 2>&1; then
            log_event "ERROR" "Firejail is not installed. Cannot configure browser sandboxing."
            printf "\\033[1;31m[-] Firejail is not installed. Please install it first.\\033[0m\\n"
            whiptail --title "Firejail Error" --msgbox "Firejail is not installed. Please install it first to enable browser sandboxing." 8 78
            echo 100; sleep 0.2
            exit 1 # Exit subshell, which will be caught by main logic
        fi
        log_event "INFO" "Firejail is installed."
        echo 20; sleep 0.2

        local browser_configured=0
        if command -v firefox > /dev/null 2>&1; then
            log_event "INFO" "Setting up Firejail for Firefox."
            printf "\\033[1;31m[+] Setting up Firejail for Firefox...\\033[0m\\n"
            if ! ln -sf /usr/bin/firejail /usr/local/bin/firefox; then 
                log_event "ERROR" "Failed to create symlink for Firefox to Firejail."
            else
                log_event "INFO" "Firejail symlink created for Firefox."
                browser_configured=1
            fi
        else
            log_event "INFO" "Firefox not installed. Skipping Firejail setup for Firefox."
            printf "\\033[1;31m[-] Firefox is not installed. Skipping Firejail setup for Firefox.\\033[0m\\n"
        fi
        echo 40; sleep 0.2

        if command -v google-chrome > /dev/null 2>&1; then
            log_event "INFO" "Setting up Firejail for Google Chrome."
            printf "\\033[1;31m[+] Setting up Firejail for Google Chrome...\\033[0m\\n"
            if ! ln -sf /usr/bin/firejail /usr/local/bin/google-chrome; then
                log_event "ERROR" "Failed to create symlink for Google Chrome to Firejail."
            else
                log_event "INFO" "Firejail symlink created for Google Chrome."
                browser_configured=1
            fi
        else
            log_event "INFO" "Google Chrome not installed. Skipping Firejail setup for Chrome."
            printf "\\033[1;31m[-] Google Chrome is not installed. Skipping Firejail setup for Chrome.\\033[0m\\n"
        fi
        echo 60; sleep 0.2

        if command -v brave-browser > /dev/null 2>&1; then
            log_event "INFO" "Setting up Firejail for Brave Browser."
            printf "\\033[1;31m[+] Setting up Firejail for Brave Browser...\\033[0m\\n"
            if ! ln -sf /usr/bin/firejail /usr/local/bin/brave-browser; then
                log_event "ERROR" "Failed to create symlink for Brave Browser to Firejail."
            else
                log_event "INFO" "Firejail symlink created for Brave Browser."
                browser_configured=1
            fi
        else
            log_event "INFO" "Brave Browser not installed. Skipping Firejail setup for Brave."
            printf "\\033[1;31m[-] Brave Browser is not installed. Skipping Firejail setup for Brave.\\033[0m\\n"
        fi
        echo 80; sleep 0.2

        if command -v torbrowser-launcher > /dev/null 2>&1; then
            log_event "INFO" "Setting up Firejail for Tor Browser Launcher."
            printf "\\033[1;31m[+] Setting up Firejail for Tor Browser...\\033[0m\\n"
            if ! ln -sf /usr/bin/firejail /usr/local/bin/torbrowser-launcher; then
                log_event "ERROR" "Failed to create symlink for Tor Browser Launcher to Firejail."
            else
                log_event "INFO" "Firejail symlink created for Tor Browser Launcher."
                browser_configured=1
            fi
        else
            log_event "INFO" "Tor Browser Launcher not installed. Skipping Firejail setup for Tor Browser."
            printf "\\033[1;31m[-] Tor Browser is not installed. Skipping Firejail setup for Tor Browser.\\033[0m\\n"
        fi
        echo 100; sleep 0.2

        if [ "$browser_configured" -eq 1 ]; then
            printf "\\033[1;32m[+] Firejail configuration completed for available browsers.\\033[0m\\n"
            log_event "INFO" "Firejail configuration completed for one or more browsers."
        else
            printf "\\033[1;33m[!] No compatible browsers found for Firejail setup.\\033[0m\\n"
            log_event "WARN" "No compatible browsers found for Firejail setup."
        fi
    } | whiptail --gauge "Configuring Firejail for browsers..." 8 60 0
    local gauge_status=$?
    if [ $gauge_status -eq 1 ]; then # Check if firejail was not installed and subshell exited
        # Message already shown by subshell
        return 1
    fi
    # If gauge_status is 0, it means the subshell completed without exiting due to missing firejail.
    # The actual success/failure of symlinking is logged internally.
    return 0
}

configure_centralized_logging() {
    log_event "INFO" "Initializing custom logging (LOGG-2154)."
    printf "\\033[1;31m[+] Initializing custom logging (LOGG-2154)...\\033[0m\\n"

    if touch "$CUSTOM_LOG_FILE"; then
        chmod 640 "$CUSTOM_LOG_FILE"
        chown root:adm "$CUSTOM_LOG_FILE" # Or another appropriate group
        log_event "INFO" "Custom log file $CUSTOM_LOG_FILE created and permissions set."
        whiptail --title "Custom Logging" --infobox "Custom log file $CUSTOM_LOG_FILE initialized." 8 78
    else
        log_event "ERROR" "Failed to create custom log file $CUSTOM_LOG_FILE."
        whiptail --title "Error" --msgbox "Failed to create custom log file $CUSTOM_LOG_FILE. Check permissions." 8 78
        return 1
    fi

    # Optional: Configure logrotate for the custom log file
    if whiptail --title "Logrotate for Custom Log" --yesno "Do you want to configure logrotate for $CUSTOM_LOG_FILE to manage its size?" 10 78; then
        log_event "INFO" "User opted to configure logrotate for $CUSTOM_LOG_FILE."
        if ! dpkg -s logrotate >/dev/null 2>&1; then
            log_event "INFO" "logrotate package not found. Attempting to install."
            aptinstall "logrotate" "Log rotation utility" # Assuming aptinstall is defined and logs its own actions
            if ! dpkg -s logrotate >/dev/null 2>&1; then
                log_event "ERROR" "logrotate installation failed. Cannot configure rotation for $CUSTOM_LOG_FILE."
                whiptail --title "Error" --msgbox "logrotate installation failed. Cannot configure rotation for $CUSTOM_LOG_FILE." 8 78
                return 1 # Or handle differently
            fi
        fi

        LOGROTATE_CONF="/etc/logrotate.d/hardn-custom"
        if [ ! -f "$LOGROTATE_CONF" ]; then
            echo "$CUSTOM_LOG_FILE {
    weekly
    missingok
    rotate 4
    compress
    delaycompress
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate # Adjust if not using rsyslog or if path differs
    endscript
}" > "$LOGROTATE_CONF"
            if [ $? -eq 0 ]; then
                log_event "INFO" "logrotate configuration created at $LOGROTATE_CONF for $CUSTOM_LOG_FILE."
                whiptail --title "Logrotate Configured" --msgbox "logrotate configuration for $CUSTOM_LOG_FILE created at $LOGROTATE_CONF." 8 78
            else
                log_event "ERROR" "Failed to create logrotate configuration $LOGROTATE_CONF."
                whiptail --title "Error" --msgbox "Failed to create logrotate configuration $LOGROTATE_CONF. Check permissions." 8 78
            fi
        else
            log_event "INFO" "logrotate configuration $LOGROTATE_CONF already exists."
            whiptail --title "Logrotate Exists" --infobox "logrotate configuration $LOGROTATE_CONF already exists." 8 78
        fi
    else
        log_event "INFO" "User opted not to configure logrotate for $CUSTOM_LOG_FILE."
    fi
    printf "\\033[1;32m[+] Custom logging setup complete.\\033[0m\\n"
    log_event "INFO" "Custom logging (LOGG-2154) setup finished."
    return 0
}

krnl_harden_sysctl() {
    log_event "INFO" "Starting Kernel Hardening via sysctl (KRNL-5788)."
    printf "\\033[1;31m[+] Hardening kernel via sysctl (KRNL-5788)...\\033[0m\\n"
    local SYSCTL_CONF_DIR="/etc/sysctl.d"
    local SYSCTL_HARDENING_CONF="$SYSCTL_CONF_DIR/99-hardening.conf"

    # Ensure sysctl.d directory exists
    if [ ! -d "$SYSCTL_CONF_DIR" ]; then
        mkdir -p "$SYSCTL_CONF_DIR"
        log_event "INFO" "Created directory $SYSCTL_CONF_DIR."
    fi

    local changes_made=0

    # Setting fs.protected_fifos = 2
    if ! grep -q "^fs.protected_fifos\\s*=\\s*2" "$SYSCTL_HARDENING_CONF" 2>/dev/null; then
        echo "fs.protected_fifos = 2" >> "$SYSCTL_HARDENING_CONF"
        log_event "INFO" "Set fs.protected_fifos = 2 in $SYSCTL_HARDENING_CONF."
        changes_made=1
        whiptail --title "Kernel Hardening" --infobox "Setting fs.protected_fifos = 2" 8 78
    else
        log_event "INFO" "fs.protected_fifos is already set to 2 in $SYSCTL_HARDENING_CONF."
        whiptail --title "Kernel Hardening" --infobox "fs.protected_fifos = 2 (already set)" 8 78
    fi
    sleep 1

    # Setting fs.protected_regular = 2
    if ! grep -q "^fs.protected_regular\\s*=\\s*2" "$SYSCTL_HARDENING_CONF" 2>/dev/null; then
        echo "fs.protected_regular = 2" >> "$SYSCTL_HARDENING_CONF"
        log_event "INFO" "Set fs.protected_regular = 2 in $SYSCTL_HARDENING_CONF."
        changes_made=1
        whiptail --title "Kernel Hardening" --infobox "Setting fs.protected_regular = 2" 8 78
    else
        log_event "INFO" "fs.protected_regular is already set to 2 in $SYSCTL_HARDENING_CONF."
        whiptail --title "Kernel Hardening" --infobox "fs.protected_regular = 2 (already set)" 8 78
    fi
    sleep 1

    if [ "$changes_made" -eq 1 ]; then
        whiptail --title "Kernel Hardening" --infobox "Applying sysctl changes..." 8 78
        if sysctl -p "$SYSCTL_HARDENING_CONF"; then
            log_event "INFO" "Applied sysctl settings from $SYSCTL_HARDENING_CONF."
            whiptail --title "Success" --msgbox "Kernel sysctl settings for KRNL-5788 applied and saved." 8 78
        else
            log_event "ERROR" "Failed to apply sysctl settings from $SYSCTL_HARDENING_CONF."
            whiptail --title "Error" --msgbox "Failed to apply sysctl settings. Check $SYSCTL_HARDENING_CONF and system logs." 8 78
            return 1
        fi
    else
        whiptail --title "Kernel Hardening" --msgbox "Kernel sysctl settings for KRNL-5788 were already configured." 8 78
    fi
    printf "\\033[1;32m[+] Kernel sysctl hardening (KRNL-5788) complete.\\033[0m\\n"
    log_event "INFO" "Kernel Hardening via sysctl (KRNL-5788) finished."
    return 0
}

secure_fstab_mounts() {
    log_event "INFO" "Starting fstab mount security check (FILE-6310)."
    printf "\\033[1;31m[+] Securing /etc/fstab mounts (FILE-6310)...\\033[0m\\n"
    local FSTAB="/etc/fstab"
    local FSTAB_BACKUP="/etc/fstab.bak.$(date +%Y%m%d%H%M%S)"
    local changes_made=0

    if [ ! -f "$FSTAB" ]; then
        log_event "ERROR" "$FSTAB not found. Cannot secure mounts."
        whiptail --title "Error" --msgbox "$FSTAB not found. Cannot secure mounts." 8 78
        return 1
    fi

    cp "$FSTAB" "$FSTAB_BACKUP"
    log_event "INFO" "Backed up $FSTAB to $FSTAB_BACKUP."
    whiptail --title "Fstab Backup" --infobox "Backed up $FSTAB to $FSTAB_BACKUP." 8 78
    sleep 1

    # Mount points and their required options
    declare -A MOUNTS_TO_SECURE
    MOUNTS_TO_SECURE=(
        ["/tmp"]="nosuid,nodev,noexec"
        ["/var/tmp"]="nosuid,nodev,noexec" # Often a symlink to /tmp, but check anyway
        ["/dev/shm"]="nosuid,nodev,noexec"
        ["/home"]="nodev" # noexec can be too restrictive for /home, nosuid is often default or inherited
    )

    for mount_point in "${!MOUNTS_TO_SECURE[@]}"; do
        local required_options="${MOUNTS_TO_SECURE[$mount_point]}"
        log_event "INFO" "Checking mount point: $mount_point, required options: $required_options"

        # Check if mount point exists in fstab
        if grep -qE "^\s*[^#]+\s+$mount_point\s+" "$FSTAB"; then
            local current_options
            current_options=$(awk -v mp="$mount_point" '$2 == mp {print $4}' "$FSTAB")
            log_event "INFO" "Current options for $mount_point: $current_options"

            local options_to_add=()
            local all_options_present=true
            IFS=',' read -ra req_opts_array <<< "$required_options"
            for opt in "${req_opts_array[@]}"; do
                if ! grep -qE "(^|,)($opt)(,|$)" <<< "$current_options"; then
                    all_options_present=false
                    options_to_add+=("$opt")
                fi
            done

            if ! $all_options_present; then
                log_event "WARN" "$mount_point needs security options: ${options_to_add[*]}"
                if whiptail --title "Secure Mount Options" --yesno "Mount point $mount_point is missing security options: ${options_to_add[*]}. Apply them to $FSTAB?" 12 78; then
                    log_event "INFO" "User approved applying options for $mount_point."
                    local new_options="$current_options"
                    # Avoid duplicate 'defaults' if it's there and we are adding specific items
                    if [[ "$new_options" == "defaults" && ${#options_to_add[@]} -gt 0 ]]; then
                        new_options="" # Start fresh if only defaults was there
                    fi
                    for opt_to_add in "${options_to_add[@]}"; do
                        if [ -z "$new_options" ]; then
                            new_options="$opt_to_add"
                        elif ! grep -qE "(^|,)($opt_to_add)(,|$)" <<< "$new_options"; then # Double check not already there from a previous iteration if logic is complex
                            new_options="$new_options,$opt_to_add"
                        fi
                    done
                    # Remove leading/trailing commas or duplicate commas if any were formed (basic cleanup)
                    new_options=$(echo "$new_options" | sed 's/,,*/,/g' | sed 's/^,//' | sed 's/,$//')
                    if [ -z "$new_options" ]; then new_options="defaults"; fi # Should not happen if adding specific opts

                    # Use awk to modify the correct line
                    awk -v mp="$mount_point" -v opts="$new_options" '
                    {
                        if ($2 == mp && $0 !~ /^#/) {
                            $4 = opts;
                            print;
                        } else {
                            print;
                        }
                    }' "$FSTAB_BACKUP" > "$FSTAB" # Read from backup, write to original
                    
                    if [ $? -eq 0 ]; then
                        log_event "INFO" "Successfully updated options for $mount_point to $new_options in $FSTAB."
                        whiptail --title "Fstab Updated" --msgbox "Options for $mount_point updated in $FSTAB. A reboot or 'mount -o remount $mount_point' is needed to apply." 10 78
                        changes_made=1
                    else
                        log_event "ERROR" "Failed to update $FSTAB for $mount_point. Restoring from backup."
                        cp "$FSTAB_BACKUP" "$FSTAB" # Restore on failure
                        whiptail --title "Error" --msgbox "Failed to update $FSTAB for $mount_point. Original $FSTAB restored. Check manually." 10 78
                    fi
                else
                    log_event "WARN" "User chose not to apply security options for $mount_point."
                    whiptail --title "Skipped" --msgbox "Skipped applying security options for $mount_point." 8 78
                fi
            else
                log_event "INFO" "$mount_point already has required security options: $required_options."
                whiptail --title "Mount Secure" --infobox "$mount_point already has required options ($required_options)." 8 78
            fi
        else
            log_event "INFO" "Mount point $mount_point not found in $FSTAB or is commented out."
            whiptail --title "Mount Not Found" --infobox "$mount_point not configured in $FSTAB or is commented out. Skipping." 8 78
        fi
        sleep 1
    done

    if [ "$changes_made" -eq 1 ]; then
        whiptail --title "Fstab Security" --msgbox "Fstab security enhancements for FILE-6310 applied. Review $FSTAB. A reboot or manual remounts are required for changes to take effect." 12 78
    else
        whiptail --title "Fstab Security" --msgbox "No changes made to $FSTAB for FILE-6310, or settings were already compliant." 10 78
    fi
    printf "\\033[1;32m[+] Fstab mount security check (FILE-6310) complete.\\033[0m\\n"
    log_event "INFO" "Fstab mount security check (FILE-6310) finished."
    return 0
}

configure_dns_security() {
    log_event "INFO" "Starting DNS configuration review (NAME-4028)."
    printf "\\033[1;31m[+] Configuring DNS Security (NAME-4028)...\\033[0m\\n"
    local RESOLV_CONF="/etc/resolv.conf"

    whiptail --title "DNS Configuration Review" --infobox "Reviewing $RESOLV_CONF..." 8 78
    log_event "INFO" "Reviewing $RESOLV_CONF."
    sleep 1

    if [ -L "$RESOLV_CONF" ]; then
        local target
        target=$(readlink -f "$RESOLV_CONF")
        whiptail --title "DNS Configuration" --msgbox "$RESOLV_CONF is a symbolic link to $target. This often means it's managed by a service like systemd-resolved or NetworkManager." 12 78
        log_event "INFO" "$RESOLV_CONF is a symlink to $target."
        
        if [[ "$target" == *systemd/resolve/stub-resolv.conf ]] || [[ "$target" == *systemd/resolve/resolv.conf ]]; then
            log_event "INFO" "$RESOLV_CONF appears to be managed by systemd-resolved."
            whiptail --title "systemd-resolved" --infobox "$RESOLV_CONF seems to be managed by systemd-resolved. This is generally good for security (local caching stub resolver)." 10 78
            if whiptail --title "systemd-resolved Status" --yesno "Do you want to check the status of systemd-resolved service?" 10 78; then
                log_event "INFO" "User opted to check systemd-resolved status."
                (systemctl status systemd-resolved) | whiptail --title "systemd-resolved Status" --textbox - 20 78
            fi
        elif grep -q "NetworkManager" "$target" || [[ "$target" == *NetworkManager/resolv.conf ]]; then
             log_event "INFO" "$RESOLV_CONF appears to be managed by NetworkManager."
             whiptail --title "NetworkManager" --infobox "$RESOLV_CONF seems to be managed by NetworkManager. Ensure your NetworkManager profiles are configured securely." 10 78
        fi
    else
        log_event "WARN" "$RESOLV_CONF is not a symbolic link. It might be statically configured or managed by other means (e.g. DHCP client)."
        whiptail --title "DNS Configuration" --msgbox "$RESOLV_CONF is not a symbolic link. It might be statically configured or managed by a DHCP client. Manual review is advised if not using a local caching resolver." 12 78
        
        if whiptail --title "Local DNS Caching" --yesno "It's recommended to use a local DNS caching resolver like systemd-resolved or dnsmasq for performance and security. Do you want to explore setting one up? (This script can help with dnsmasq if systemd-resolved is not preferred/available)." 15 78; then
            log_event "INFO" "User wants to explore local DNS caching setup."
            if command -v systemd-resolve >/dev/null 2>&1 && systemctl list-unit-files | grep -q systemd-resolved.service; then
                 if whiptail --title "systemd-resolved Available" --yesno "systemd-resolved is available. Do you want to try enabling and configuring it? (This will typically make /etc/resolv.conf a symlink to its stub resolver)." 12 78; then
                    log_event "INFO" "User chose to try enabling systemd-resolved."
                    # Basic steps to enable systemd-resolved, might need more for full config
                    systemctl enable systemd-resolved.service
                    systemctl start systemd-resolved.service
                    # Backup old resolv.conf and link to stub
                    if [ -f "$RESOLV_CONF" ] && [ ! -L "$RESOLV_CONF" ]; then mv "$RESOLV_CONF" "${RESOLV_CONF}.bak-hardn"; fi
                    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
                    log_event "INFO" "Enabled systemd-resolved and linked $RESOLV_CONF to stub. Network restart might be needed."
                    whiptail --title "systemd-resolved Enabled" --msgbox "systemd-resolved service enabled and $RESOLV_CONF linked to its stub. You may need to restart your networking service or reboot. Verify DNS resolution afterwards." 12 78
                 else
                    log_event "INFO" "User declined enabling systemd-resolved, will offer dnsmasq."
                    install_and_configure_dnsmasq # Call a helper for dnsmasq
                 fi
            else
                log_event "INFO" "systemd-resolved not readily available or user might prefer dnsmasq. Offering dnsmasq."
                install_and_configure_dnsmasq # Call a helper for dnsmasq
            fi
        else
            log_event "INFO" "User declined setting up a local DNS caching resolver at this time."
        fi
    fi

    # Check permissions of resolv.conf
    local perms
    perms=$(stat -c "%a %U:%G" "$RESOLV_CONF")
    log_event "INFO" "Permissions for $RESOLV_CONF: $perms."
    if [[ "$perms" != "644 root:root" && "$perms" != *root:root && $(echo "$perms" | cut -d' ' -f1) -le 644 ]]; then # Allow for symlink perms if target is root:root
        # For symlinks, the link perms are often 777, but the target's perms matter.
        # This check is simplified. A more robust check would stat the target if it's a link.
        if [ -L "$RESOLV_CONF" ]; then
            local target_perms
            target_perms=$(stat -L -c "%a %U:%G" "$RESOLV_CONF") # stat target of link
            log_event "INFO" "Permissions for target of $RESOLV_CONF ($target): $target_perms."
            if [[ "$target_perms" != "644 root:root" ]]; then # Check target perms
                 whiptail --title "DNS Permissions" --msgbox "$RESOLV_CONF (target $target) has permissions $target_perms. Expected 644 root:root. Consider adjusting if appropriate for your setup, but be cautious if managed by a service." 12 78
                 log_event "WARN" "$RESOLV_CONF (target $target) permissions are $target_perms. Expected 644 root:root."
            else
                 whiptail --title "DNS Permissions" --infobox "$RESOLV_CONF target permissions ($target_perms) are secure." 8 78
                 log_event "INFO" "$RESOLV_CONF target permissions ($target_perms) are secure."
            fi
        else # It's a regular file
            whiptail --title "DNS Permissions" --msgbox "$RESOLV_CONF has permissions $perms. Expected 644 root:root. Consider 'chmod 644 $RESOLV_CONF' and 'chown root:root $RESOLV_CONF' if not managed by a service." 12 78
            log_event "WARN" "$RESOLV_CONF permissions are $perms. Expected 644 root:root."
        fi
    else
        whiptail --title "DNS Permissions" --infobox "$RESOLV_CONF permissions ($perms) appear secure." 8 78
        log_event "INFO" "$RESOLV_CONF permissions ($perms) appear secure."
    fi
    sleep 1

    printf "\\033[1;32m[+] DNS Security (NAME-4028) review complete.\\033[0m\\n"
    log_event "INFO" "DNS configuration review (NAME-4028) finished."
    return 0
}

install_and_configure_dnsmasq() {
    log_event "INFO" "Attempting to install and configure dnsmasq."
    if whiptail --title "Install dnsmasq" --yesno "dnsmasq can provide local DNS caching. Do you want to install and configure it with basic settings (listen on 127.0.0.1, no-resolv, add Cloudflare/Google DNS as upstream)?" 15 78; then
        log_event "INFO" "User approved dnsmasq installation."
        if ! dpkg -s dnsmasq >/dev/null 2>&1; then
            log_event "INFO" "dnsmasq package not found. Attempting to install."
            aptinstall "dnsmasq" "Lightweight DNS forwarder and DHCP server" # Assuming aptinstall logs
            if ! dpkg -s dnsmasq >/dev/null 2>&1; then
                log_event "ERROR" "dnsmasq installation failed."
                whiptail --title "Error" --msgbox "dnsmasq installation failed. Cannot configure." 8 78
                return 1
            fi
        fi
        
        # Basic dnsmasq configuration
        local DNSMASQ_CONF="/etc/dnsmasq.conf"
        local DNSMASQ_CUSTOM_CONF="/etc/dnsmasq.d/99-hardn-custom.conf"
        
        if [ -f "$DNSMASQ_CONF" ]; then # Check if main conf needs 'conf-dir'
            if ! grep -q "^conf-dir=/etc/dnsmasq.d" "$DNSMASQ_CONF"; then
                 echo "conf-dir=/etc/dnsmasq.d/,*.conf" >> "$DNSMASQ_CONF"
                 log_event "INFO" "Enabled conf-dir in $DNSMASQ_CONF."
            fi
        fi
        mkdir -p /etc/dnsmasq.d
        
        echo "listen-address=127.0.0.1" > "$DNSMASQ_CUSTOM_CONF"
        echo "no-resolv" >> "$DNSMASQ_CUSTOM_CONF" # We will specify servers directly
        echo "server=1.1.1.1" >> "$DNSMASQ_CUSTOM_CONF" # Cloudflare
        echo "server=1.0.0.1" >> "$DNSMASQ_CUSTOM_CONF"
        echo "server=8.8.8.8" >> "$DNSMASQ_CUSTOM_CONF" # Google
        echo "server=8.8.4.4" >> "$DNSMASQ_CUSTOM_CONF"
        # Add more secure options if desired, e.g., cache-size, min-cache-ttl, etc.
        # echo "cache-size=1000" >> "$DNSMASQ_CUSTOM_CONF"
        
        log_event "INFO" "Created custom dnsmasq config $DNSMASQ_CUSTOM_CONF."
        whiptail --title "dnsmasq Configured" --infobox "dnsmasq configured with local listener and upstream servers. Restarting service..." 8 78
        
        if systemctl restart dnsmasq; then
            log_event "INFO" "dnsmasq service restarted successfully."
            # Now, make /etc/resolv.conf point to local dnsmasq
            if [ -f "/etc/resolv.conf" ] && [ ! -L "/etc/resolv.conf" ]; then
                mv /etc/resolv.conf /etc/resolv.conf.bak-dnsmasq
                log_event "INFO" "Backed up existing /etc/resolv.conf to /etc/resolv.conf.bak-dnsmasq."
            elif [ -L "/etc/resolv.conf" ]; then # If it's a link, remove it
                rm -f /etc/resolv.conf
            fi
            echo "nameserver 127.0.0.1" > /etc/resolv.conf
            chmod 644 /etc/resolv.conf
            chown root:root /etc/resolv.conf
            log_event "INFO" "/etc/resolv.conf now points to 127.0.0.1 for dnsmasq."
            whiptail --title "dnsmasq Active" --msgbox "dnsmasq is now active and /etc/resolv.conf points to 127.0.0.1. Verify DNS resolution." 10 78
        else
            log_event "ERROR" "Failed to restart dnsmasq service. Check 'systemctl status dnsmasq' and 'journalctl -u dnsmasq'."
            whiptail --title "Error" --msgbox "Failed to restart dnsmasq. Check its status and logs. Configuration might be incorrect." 10 78
        fi
    else
        log_event "INFO" "User declined dnsmasq installation."
    fi
}

harden_docker_security() {
    log_event "INFO" "Starting Docker security hardening (CONT-8104)."
    printf "\\033[1;31m[+] Hardening Docker security (CONT-8104)...\\033[0m\\n"

    if ! dpkg -s docker.io >/dev/null 2>&1; then
        whiptail --title "Docker Security" --msgbox "Docker (docker.io) is not installed. Skipping Docker security hardening." 10 70
        log_event "INFO" "Docker (docker.io) not installed. Skipping CONT-8104."
        return 1
    fi

    log_event "INFO" "Docker (docker.io) is installed."

    # Check Docker service status
    if systemctl is-active --quiet docker; then
        whiptail --title "Docker Service" --infobox "Docker service is active." 8 70
        log_event "INFO" "Docker service is active."
    else
        whiptail --title "Docker Service" --yesno "Docker service is not active. Attempt to start it?" 10 70
        if [ $? -eq 0 ]; then
            systemctl start docker
            if systemctl is-active --quiet docker; then
                whiptail --title "Docker Service" --msgbox "Docker service started successfully." 8 70
                log_event "INFO" "Docker service started."
            else
                whiptail --title "Docker Service" --msgbox "Failed to start Docker service. Please check 'systemctl status docker'." 10 70
                log_event "ERROR" "Failed to start Docker service."
            fi
        else
            log_event "WARN" "User chose not to start Docker service."
        fi
    fi
    sleep 1

    if systemctl is-enabled --quiet docker; then
        whiptail --title "Docker Service" --infobox "Docker service is enabled on boot." 8 70
        log_event "INFO" "Docker service is enabled on boot."
    else
        whiptail --title "Docker Service" --yesno "Docker service is not enabled on boot. Attempt to enable it?" 10 70
        if [ $? -eq 0 ]; then
            systemctl enable docker
            if systemctl is-enabled --quiet docker; then
                whiptail --title "Docker Service" --msgbox "Docker service enabled successfully." 8 70
                log_event "INFO" "Docker service enabled on boot."
            else
                whiptail --title "Docker Service" --msgbox "Failed to enable Docker service. Please check 'systemctl status docker'." 10 70
                log_event "ERROR" "Failed to enable Docker service on boot."
            fi
        else
            log_event "WARN" "User chose not to enable Docker service on boot."
        fi
    fi
    sleep 1

    whiptail --title "Docker Security Recommendation" --msgbox "For a comprehensive Docker security audit, it is highly recommended to run the 'docker-bench-security' script from Docker. This script checks for dozens of common best-practices around deploying Docker containers in production." 15 78
    log_event "INFO" "Advised user to run docker-bench-security."

    DAEMON_JSON="/etc/docker/daemon.json"
    ICC_SETTING="\\"icc\\": false" # Escaped for grep and sed

    if [ -f "$DAEMON_JSON" ]; then
        log_event "INFO" "$DAEMON_JSON exists. Checking contents."
        if grep -q "$ICC_SETTING" "$DAEMON_JSON"; then
            whiptail --title "Docker Configuration" --infobox "$DAEMON_JSON already contains '$ICC_SETTING'. Inter-container communication is disabled." 10 78
            log_event "INFO" "icc is already set to false in $DAEMON_JSON."
        else
            whiptail --title "Docker Configuration" --yesno "$DAEMON_JSON exists but does not have '$ICC_SETTING' (or it's not set to false). This is recommended for security. Add/modify it?" 12 78
            if [ $? -eq 0 ]; then
                # Attempt to add or modify icc. This is a simplified approach.
                # A more robust solution would use jq if available.
                if grep -q "\\"icc\\":" "$DAEMON_JSON"; then # icc key exists
                    # Crude way to replace value, assumes "icc": true or "icc": something_else
                    # This might break if the JSON is complex.
                    cp "$DAEMON_JSON" "${DAEMON_JSON}.bak"
                    sed -i.bak "s/\\"icc\\":.*/${ICC_SETTING},/" "$DAEMON_JSON" # attempts to replace the line
                    # Remove trailing comma if it's the last element - this is tricky with sed
                    # For simplicity, we'll just inform the user to check syntax
                    whiptail --title "Docker Configuration" --msgbox "'icc' setting modified in $DAEMON_JSON. A backup is at ${DAEMON_JSON}.bak. Please verify JSON syntax and restart Docker service for changes to take effect." 12 78
                    log_event "WARN" "Attempted to set icc=false in $DAEMON_JSON. User advised to verify and restart Docker."
                else # icc key does not exist, try to add it
                    cp "$DAEMON_JSON" "${DAEMON_JSON}.bak"
                    # Add to the beginning of the JSON object, crude but often works for simple JSON
                    sed -i.bak "s/^{/{ ${ICC_SETTING},/" "$DAEMON_JSON"
                    whiptail --title "Docker Configuration" --msgbox "'$ICC_SETTING' added to $DAEMON_JSON. A backup is at ${DAEMON_JSON}.bak. Please verify JSON syntax and restart Docker service for changes to take effect." 12 78
                    log_event "WARN" "Attempted to add icc=false to $DAEMON_JSON. User advised to verify and restart Docker."
                fi
            else
                log_event "WARN" "User chose not to modify $DAEMON_JSON for icc setting."
            fi
        fi
    else
        log_event "INFO" "$DAEMON_JSON does not exist."
        whiptail --title "Docker Configuration" --yesno "$DAEMON_JSON does not exist. Create it with '$ICC_SETTING' to disable inter-container communication by default (recommended)?" 12 78
        if [ $? -eq 0 ]; then
            echo "{
    $ICC_SETTING
}" > "$DAEMON_JSON"
            if [ $? -eq 0 ]; then
                whiptail --title "Docker Configuration" --msgbox "$DAEMON_JSON created with '$ICC_SETTING'. Restart Docker service for changes to take effect." 10 78
                log_event "INFO" "Created $DAEMON_JSON with icc=false."
            else
                whiptail --title "Error" --msgbox "Failed to create $DAEMON_JSON. Please check permissions." 10 78
                log_event "ERROR" "Failed to create $DAEMON_JSON."
            fi
        else
            log_event "WARN" "User chose not to create $DAEMON_JSON."
        fi
    fi
    sleep 1
    printf "\\033[1;32m[+] Docker security hardening checks completed.\\033[0m\\n"
    log_event "INFO" "Docker security hardening (CONT-8104) finished."
    return 0
}

log_event() {
    local type="$1"
    local message="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$type] $message" >> "$CUSTOM_LOG_FILE"
}

main() {
    print_ascii_banner
    welcomemsg
    if [ $? -ne 0 ]; then
        clear
        exit 0
    fi
    preinstallmsg
    if [ $? -ne 0 ]; then
        clear
        exit 0
    fi

    update_system_packages
    # build_hardn_package # Assuming this is for creating the .deb, not for typical run
    # installationloop # Installs packages from progs.csv

    # Security Configurations
    configure_centralized_logging # Setup logging first
    krnl_harden_sysctl
    secure_fstab_mounts
    configure_dns_security
    configure_ufw
    harden_docker_security # Call the new Docker hardening function
    enable_selinux # Call SELinux hardening (MACF-6208)

    # Lynis suggested checks
    check_world_writable_files # FILE-7524
    check_kernel_strict_devmem # KRNL-6000

    # Final Lynis audit
    run_lynis_audit # TOOL-5002

    # check_security_tools # Checks a line
}

# Function to check for world-writable files and directories (FILE-7524)
check_world_writable_files() {
    log_event "INFO" "Starting check for world-writable files and directories (FILE-7524)."
    printf "\\033[1;31m[+] Checking for world-writable files and directories (FILE-7524)...\\033[0m\\n"
    local found_files=0

    # Common directories to exclude from the search to reduce noise and false positives
    # /proc, /sys, /dev are virtual filesystems. /run contains runtime data.
    # /tmp and /var/tmp often have specific sticky bit settings allowing world-write for file creation.
    # We are looking for inappropriately world-writable files in persistent storage.
    local excluded_paths=("/proc" "/sys" "/dev" "/run" "/tmp" "/var/tmp" "/var/spool/mqueue")
    local find_command="find / -xdev -type f -perm -0002"
    local find_command_dirs="find / -xdev -type d -perm -0002 -a ! -perm -1000" # Dirs that are world-writable but no sticky bit

    for path in "${excluded_paths[@]}"; do
        find_command+=" -not -path '$path/*'"
        find_command_dirs+=" -not -path '$path/*'"
    done

    whiptail --title "World-Writable Check" --infobox "Searching for world-writable files. This may take some time..." 8 78
    
    local world_writable_files
    world_writable_files=$(eval "$find_command")

    if [ -n "$world_writable_files" ]; then
        log_event "WARN" "Found world-writable files (FILE-7524):\n$world_writable_files"
        whiptail --title "World-Writable Files Found" --msgbox "Found the following world-writable files:\n\n$world_writable_files\n\nReview these files and adjust permissions if necessary (e.g., 'chmod o-w /path/to/file')." 20 78
        found_files=1
    else
        log_event "INFO" "No world-writable files found (excluding common system paths)."
        whiptail --title "World-Writable Files" --infobox "No inappropriately world-writable files found (excluding common system paths)." 8 78
    fi
    sleep 1

    whiptail --title "World-Writable Check" --infobox "Searching for world-writable directories (without sticky bit). This may take some time..." 8 78
    local world_writable_dirs
    world_writable_dirs=$(eval "$find_command_dirs")

    if [ -n "$world_writable_dirs" ]; then
        log_event "WARN" "Found world-writable directories without sticky bit (FILE-7524):\n$world_writable_dirs"
        whiptail --title "World-Writable Directories Found" --msgbox "Found the following world-writable directories without the sticky bit:\n\n$world_writable_dirs\n\nReview these directories. Consider 'chmod o-w /path/to/dir' or 'chmod +t /path/to/dir' if appropriate." 20 78
        found_files=1 # Using the same flag, as any finding is notable
    else
        log_event "INFO" "No world-writable directories without sticky bit found (excluding common system paths)."
        whiptail --title "World-Writable Directories" --infobox "No inappropriately world-writable directories (without sticky bit) found." 8 78
    fi
    sleep 1

    if [ "$found_files" -eq 0 ]; then
        printf "\\033[1;32m[+] No inappropriately world-writable files or directories found (FILE-7524).\n\\033[0m"
    else
        printf "\\033[1;33m[!] World-writable files/directories found (FILE-7524). Review output above and log file.\n\\033[0m"
    fi
    log_event "INFO" "World-writable files and directories check (FILE-7524) finished."
    return 0
}

# Function to check kernel config for CONFIG_STRICT_DEVMEM (KRNL-6000)
check_kernel_strict_devmem() {
    log_event "INFO" "Starting kernel /dev/mem access check (KRNL-6000)."
    printf "\\033[1;31m[+] Checking kernel /dev/mem access (KRNL-6000)...\\033[0m\\n"

    local config_file="/boot/config-$(uname -r)"
    local result_msg=""

    if [ -f "$config_file" ]; then
        log_event "INFO" "Kernel config file found: $config_file."
        if grep -q "CONFIG_STRICT_DEVMEM=y" "$config_file"; then
            result_msg="Kernel is configured with CONFIG_STRICT_DEVMEM=y. Access to /dev/mem is restricted."
            log_event "INFO" "$result_msg"
            whiptail --title "KRNL-6000 Check" --msgbox "$result_msg" 8 78
        elif grep -q "CONFIG_DEVMEM=n" "$config_file"; then
            result_msg="Kernel is configured with CONFIG_DEVMEM=n. /dev/mem support is disabled."
            log_event "INFO" "$result_msg"
            whiptail --title "KRNL-6000 Check" --msgbox "$result_msg" 8 78
        else
            result_msg="CONFIG_STRICT_DEVMEM is not set to 'y' (or CONFIG_DEVMEM is not 'n') in $config_file. Access to /dev/mem might not be strictly restricted. This is a security concern."
            log_event "WARN" "$result_msg"
            whiptail --title "KRNL-6000 Warning" --msgbox "$result_msg\n\nConsider recompiling the kernel with CONFIG_STRICT_DEVMEM=y or ensuring your distribution provides this by default." 12 78
        fi
    else
        result_msg="Kernel config file $config_file not found. Cannot verify CONFIG_STRICT_DEVMEM. This check is inconclusive without the kernel config."
        log_event "WARN" "$result_msg"
        whiptail --title "KRNL-6000 Warning" --msgbox "$result_msg\n\nIf this is a production system, ensure strict /dev/mem access is enforced through other means or by kernel default." 12 78
    fi
    printf "\\033[1;32m[+] Kernel /dev/mem access check (KRNL-6000) complete.\\033[0m\\n"
    log_event "INFO" "Kernel /dev/mem access check (KRNL-6000) finished."
    return 0
}

# Function to run Lynis audit (TOOL-5002)
run_lynis_audit() {
    log_event "INFO" "Starting Lynis audit (TOOL-5002)."
    printf "\\033[1;31m[+] Running Lynis audit system (TOOL-5002)...\\033[0m\\n"

    if ! command -v lynis > /dev/null 2>&1; then
        log_event "WARN" "Lynis command not found. Attempting to install."
        whiptail --title "Lynis Not Found" --infobox "Lynis not found. Attempting to install..." 8 78
        aptinstall "lynis" "Security auditing tool Lynis"
        if ! command -v lynis > /dev/null 2>&1; then
            log_event "ERROR" "Failed to install Lynis. Cannot perform audit."
            whiptail --title "Error" --msgbox "Failed to install Lynis. Audit (TOOL-5002) aborted." 8 78
            return 1
        fi
    fi

    if whiptail --title "Run Lynis Audit" --yesno "Do you want to run 'lynis audit system'? This can take several minutes and will output a detailed report. The report will be saved to /var/log/lynis-report.dat and log to /var/log/lynis.log." 12 78; then
        log_event "INFO" "User approved running Lynis audit."
        whiptail --title "Lynis Audit" --infobox "Running 'lynis audit system'. Please wait...\nOutput will be in /var/log/lynis.log and report in /var/log/lynis-report.dat" 10 78
        
        # Run Lynis audit. Use --quiet to reduce terminal output during script, but it still shows progress.
        # Log and report files are standard for Lynis.
        if lynis audit system --quiet; then # --cronjob might be too quiet, --quiet still shows sections
            log_event "INFO" "Lynis audit completed successfully. Report: /var/log/lynis-report.dat, Log: /var/log/lynis.log."
            whiptail --title "Lynis Audit Complete" --msgbox "Lynis audit finished. Please review the report at /var/log/lynis-report.dat and the log at /var/log/lynis.log for findings and suggestions." 12 78
        else
            log_event "WARN" "Lynis audit completed with warnings or errors. Review output and logs."
            whiptail --title "Lynis Audit Issues" --msgbox "Lynis audit finished, but there might have been issues or it was interrupted. Review /var/log/lynis.log and /var/log/lynis-report.dat." 12 78
        fi
    else
        log_event "INFO" "User chose not to run Lynis audit at this time."
        whiptail --title "Lynis Audit Skipped" --infobox "Lynis audit (TOOL-5002) skipped by user." 8 78
    fi
    printf "\\033[1;32m[+] Lynis audit (TOOL-5002) process complete.\\033[0m\\n"
    log_event "INFO" "Lynis audit (TOOL-5002) process finished."
    return 0
}

# Execute the main function
main "$@"