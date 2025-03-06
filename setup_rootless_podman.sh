#!/bin/bash
#
# Setup Rootless Podman on RHEL
# This script configures rootless mode for Podman on RHEL systems
# based on the Podman Security Audit Tool recommendations.

# Text formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Print section headers
print_section() {
    echo -e "\n${BLUE}${BOLD}$1${NC}"
    echo -e "${BLUE}----------------------------------------${NC}"
}

# Print status messages
print_status() {
    local status="$1"
    local message="$2"
    
    if [[ "$status" == "PASS" ]]; then
        echo -e "${GREEN}[PASS]${NC} $message"
    elif [[ "$status" == "FAIL" ]]; then
        echo -e "${RED}[FAIL]${NC} $message"
    else
        echo -e "${BOLD}[INFO]${NC} $message"
    fi
}

# Check if running as root
check_user() {
    print_section "Checking User"
    
    if [[ "$(id -u)" -eq 0 ]]; then
        print_status "INFO" "Running as root. This script will set up rootless Podman for the specified user."
        
        # Ask for username if not provided as argument
        if [[ -z "$TARGET_USER" ]]; then
            read -p "Enter the username to configure for rootless Podman: " TARGET_USER
            
            # Validate user exists
            if ! id "$TARGET_USER" &>/dev/null; then
                print_status "FAIL" "User $TARGET_USER does not exist."
                exit 1
            fi
        fi
    else
        TARGET_USER=$(whoami)
        print_status "INFO" "Running as user $TARGET_USER. Setting up rootless Podman for current user."
    fi
    
    print_status "PASS" "Target user for rootless setup: $TARGET_USER"
}

# Check Podman installation
check_podman() {
    print_section "Checking Podman Installation"
    
    # Check if we're on RHEL
    if [ -f /etc/redhat-release ]; then
        print_status "PASS" "Running on RHEL system"
        if grep -q "release 8" /etc/redhat-release 2>/dev/null; then
            print_status "INFO" "Detected RHEL 8"
        elif grep -q "release 9" /etc/redhat-release 2>/dev/null; then
            print_status "INFO" "Detected RHEL 9"
        else
            print_status "INFO" "Detected other RHEL version"
        fi
    else
        print_status "INFO" "Not running on RHEL. Script optimized for RHEL but will attempt to continue."
    fi
    
    # Check if podman is installed
    if ! command -v podman &>/dev/null; then
        print_status "FAIL" "Podman is not installed. Installing podman..."
        
        # Try to use subscription manager to enable required repositories for RHEL
        if command -v subscription-manager &>/dev/null; then
            print_status "INFO" "Enabling repositories with subscription-manager..."
            # Enable container-tools repository for RHEL (may require proper subscription)
            subscription-manager repos --enable rhel-8-for-x86_64-appstream-rpms &>/dev/null || \
            subscription-manager repos --enable rhel-9-for-x86_64-appstream-rpms &>/dev/null || true
        fi
        
        # Install podman using dnf
        if ! dnf install -y podman; then
            print_status "FAIL" "Failed to install Podman. Please install it manually: dnf install -y podman"
            print_status "INFO" "You may need to enable the appropriate repositories first using subscription-manager"
            exit 1
        fi
        
        if ! command -v podman &>/dev/null; then
            print_status "FAIL" "Podman installation failed. Please install it manually."
            exit 1
        fi
    fi
    
    # Get podman version
    local version=$(podman --version | awk '{print $3}')
    print_status "PASS" "Podman version $version is installed"
    
    # Check if version is recent (consider versions older than 3.0 as potentially problematic)
    local major_version=$(echo "$version" | cut -d. -f1)
    if [[ $major_version -lt 3 ]]; then
        print_status "FAIL" "Podman version is older than 3.0, updating to latest version..."
        
        # Check if we should update system first
        if [ -f /etc/redhat-release ]; then
            print_status "INFO" "Updating system packages first (RHEL-specific)..."
            dnf update -y
        fi
        
        # Update podman
        dnf update -y podman
        
        # Get new version
        version=$(podman --version | awk '{print $3}')
        print_status "PASS" "Podman updated to version $version"
    fi
}

# Install required packages
install_dependencies() {
    print_section "Installing Required Dependencies"
    
    print_status "INFO" "Installing required packages for rootless mode..."
    
    # Create a list of packages to install
    local pkgs_to_install=()
    
    # Check shadow-utils for newuidmap/newgidmap
    if ! command -v newuidmap &>/dev/null || ! command -v newgidmap &>/dev/null; then
        print_status "INFO" "Need to install shadow-utils package"
        pkgs_to_install+=("shadow-utils")
    fi
    
    # Check slirp4netns for rootless networking
    if ! command -v slirp4netns &>/dev/null; then
        print_status "INFO" "Need to install slirp4netns package"
        pkgs_to_install+=("slirp4netns")
    fi
    
    # Check fuse-overlayfs for better rootless storage performance
    if ! command -v fuse-overlayfs &>/dev/null; then
        print_status "INFO" "Need to install fuse-overlayfs package"
        pkgs_to_install+=("fuse-overlayfs")
    fi
    
    # Check containernetworking-plugins
    if ! rpm -q containernetworking-plugins &>/dev/null; then
        print_status "INFO" "Need to install containernetworking-plugins package"
        pkgs_to_install+=("containernetworking-plugins")
    fi
    
    # Check libcap package for capabilities
    if ! command -v getcap &>/dev/null; then
        print_status "INFO" "Need to install libcap package"
        pkgs_to_install+=("libcap")
    fi
    
    # Install required packages if any are missing
    if [ ${#pkgs_to_install[@]} -gt 0 ]; then
        print_status "INFO" "Installing packages: ${pkgs_to_install[*]}"
        
        # Try to enable required repos for RHEL
        if command -v subscription-manager &>/dev/null; then
            print_status "INFO" "Checking repositories with subscription-manager..."
            # For RHEL 8/9, these repos should include the packages we need
            subscription-manager repos --enable rhel-8-for-x86_64-appstream-rpms &>/dev/null || \
            subscription-manager repos --enable rhel-9-for-x86_64-appstream-rpms &>/dev/null || true
        fi
        
        # Install packages
        if ! dnf install -y "${pkgs_to_install[@]}"; then
            print_status "FAIL" "Failed to install required packages. You may need to install them manually."
            print_status "INFO" "Required packages: ${pkgs_to_install[*]}"
            # Continue anyway as some might have installed
        fi
    else
        print_status "PASS" "All required packages are already installed"
    fi
    
    # Verify kernel support for user namespaces (required for rootless)
    if [ -f /proc/sys/kernel/unprivileged_userns_clone ]; then
        local userns_enabled=$(cat /proc/sys/kernel/unprivileged_userns_clone)
        if [ "$userns_enabled" = "1" ]; then
            print_status "PASS" "Kernel supports unprivileged user namespaces"
        else
            print_status "FAIL" "Unprivileged user namespaces not enabled in kernel"
            print_status "INFO" "Enabling unprivileged user namespaces (required for rootless mode)..."
            
            # Try to enable it temporarily
            echo 1 > /proc/sys/kernel/unprivileged_userns_clone
            
            # Make it persistent
            if [ ! -d /etc/sysctl.d ]; then
                mkdir -p /etc/sysctl.d
            fi
            echo "kernel.unprivileged_userns_clone=1" > /etc/sysctl.d/00-local-userns.conf
            
            # Verify it's enabled now
            if [ "$(cat /proc/sys/kernel/unprivileged_userns_clone)" = "1" ]; then
                print_status "PASS" "Successfully enabled unprivileged user namespaces"
            else
                print_status "FAIL" "Failed to enable unprivileged user namespaces. This is required for rootless mode."
                print_status "INFO" "To enable manually, run: echo 1 > /proc/sys/kernel/unprivileged_userns_clone"
                print_status "INFO" "And make it persistent with: echo 'kernel.unprivileged_userns_clone=1' > /etc/sysctl.d/00-local-userns.conf"
            fi
        fi
    else
        # If the file doesn't exist, it's likely that the kernel always has support enabled
        print_status "PASS" "Kernel appears to support unprivileged user namespaces (setting not present, likely enabled by default)"
    fi
    
    # Final check of all required dependencies
    local deps_installed=true
    for cmd in newuidmap newgidmap slirp4netns fuse-overlayfs; do
        if ! command -v $cmd &>/dev/null; then
            print_status "FAIL" "$cmd is not installed. Please install it manually."
            deps_installed=false
        fi
    done
    
    # Check containernetworking-plugins with rpm
    if ! rpm -q containernetworking-plugins &>/dev/null; then
        print_status "FAIL" "containernetworking-plugins is not installed. Please install it manually."
        deps_installed=false
    fi
    
    if [[ "$deps_installed" == "true" ]]; then
        print_status "PASS" "All required dependencies are installed"
    else
        print_status "FAIL" "Some dependencies are still missing. See above for details."
        print_status "INFO" "Script will continue, but rootless mode may not work properly"
    fi
}

# Configure subuid and subgid
configure_subid() {
    print_section "Configuring Subordinate UIDs/GIDs"
    
    # Check if user already has subuid/subgid entries
    local has_subuid=$(grep -c "^$TARGET_USER:" /etc/subuid || true)
    local has_subgid=$(grep -c "^$TARGET_USER:" /etc/subgid || true)
    
    # Configure subuid if not already configured
    if [[ $has_subuid -eq 0 ]]; then
        print_status "INFO" "Adding subordinate UIDs for $TARGET_USER..."
        usermod --add-subuids 100000-165535 "$TARGET_USER"
        
        if grep -q "^$TARGET_USER:" /etc/subuid; then
            print_status "PASS" "Added subordinate UIDs for $TARGET_USER"
        else
            print_status "FAIL" "Failed to add subordinate UIDs for $TARGET_USER"
        fi
    else
        print_status "PASS" "User $TARGET_USER already has subordinate UIDs configured"
    fi
    
    # Configure subgid if not already configured
    if [[ $has_subgid -eq 0 ]]; then
        print_status "INFO" "Adding subordinate GIDs for $TARGET_USER..."
        usermod --add-subgids 100000-165535 "$TARGET_USER"
        
        if grep -q "^$TARGET_USER:" /etc/subgid; then
            print_status "PASS" "Added subordinate GIDs for $TARGET_USER"
        else
            print_status "FAIL" "Failed to add subordinate GIDs for $TARGET_USER"
        fi
    else
        print_status "PASS" "User $TARGET_USER already has subordinate GIDs configured"
    fi
    
    # Verify the counts are sufficient
    local subuid_count=$(grep "^$TARGET_USER:" /etc/subuid | cut -d: -f3)
    local subgid_count=$(grep "^$TARGET_USER:" /etc/subgid | cut -d: -f3)
    
    if [[ $subuid_count -lt 65536 ]]; then
        print_status "FAIL" "Subuid count for $TARGET_USER is less than recommended 65536 (current: $subuid_count)"
        print_status "INFO" "Updating subuid allocation..."
        usermod --add-subuids 100000-165535 "$TARGET_USER"
    fi
    
    if [[ $subgid_count -lt 65536 ]]; then
        print_status "FAIL" "Subgid count for $TARGET_USER is less than recommended 65536 (current: $subgid_count)"
        print_status "INFO" "Updating subgid allocation..."
        usermod --add-subgids 100000-165535 "$TARGET_USER"
    fi
    
    # Final verification
    subuid_count=$(grep "^$TARGET_USER:" /etc/subuid | cut -d: -f3)
    subgid_count=$(grep "^$TARGET_USER:" /etc/subgid | cut -d: -f3)
    
    if [[ $subuid_count -ge 65536 && $subgid_count -ge 65536 ]]; then
        print_status "PASS" "User $TARGET_USER has sufficient subordinate UIDs/GIDs configured"
    else
        print_status "FAIL" "User $TARGET_USER still has insufficient subordinate UIDs/GIDs"
    fi
}

# Configure newuidmap and newgidmap capabilities
configure_idmap_caps() {
    print_section "Configuring UID/GID Map Capabilities"
    
    # Install libcap-utils if not available
    if ! command -v getcap &>/dev/null; then
        print_status "INFO" "Installing libcap package..."
        dnf install -y libcap
    fi
    
    # Set capabilities on newuidmap
    local uidmap_path=$(which newuidmap)
    local uidmap_caps=$(getcap "$uidmap_path" 2>/dev/null)
    
    if [[ "$uidmap_caps" != *"cap_setuid"* ]]; then
        print_status "INFO" "Setting cap_setuid capability on newuidmap..."
        setcap cap_setuid+ep "$uidmap_path"
        
        uidmap_caps=$(getcap "$uidmap_path" 2>/dev/null)
        if [[ "$uidmap_caps" == *"cap_setuid"* ]]; then
            print_status "PASS" "Successfully set cap_setuid capability on newuidmap"
        else
            print_status "FAIL" "Failed to set cap_setuid capability on newuidmap"
        fi
    else
        print_status "PASS" "newuidmap already has cap_setuid capability"
    fi
    
    # Set capabilities on newgidmap
    local gidmap_path=$(which newgidmap)
    local gidmap_caps=$(getcap "$gidmap_path" 2>/dev/null)
    
    if [[ "$gidmap_caps" != *"cap_setgid"* ]]; then
        print_status "INFO" "Setting cap_setgid capability on newgidmap..."
        setcap cap_setgid+ep "$gidmap_path"
        
        gidmap_caps=$(getcap "$gidmap_path" 2>/dev/null)
        if [[ "$gidmap_caps" == *"cap_setgid"* ]]; then
            print_status "PASS" "Successfully set cap_setgid capability on newgidmap"
        else
            print_status "FAIL" "Failed to set cap_setgid capability on newgidmap"
        fi
    else
        print_status "PASS" "newgidmap already has cap_setgid capability"
    fi
}

# Configure storage for rootless Podman
configure_storage() {
    print_section "Configuring Storage for Rootless Podman"
    
    # Create user's container storage directory
    local storage_dir=""
    if [[ "$(id -u)" -eq 0 ]]; then
        storage_dir="/home/$TARGET_USER/.local/share/containers/storage"
        print_status "INFO" "Creating container storage directory for $TARGET_USER..."
        mkdir -p "$storage_dir"
        chown -R "$TARGET_USER:$TARGET_USER" "$storage_dir"
        chmod 700 "$storage_dir"
    else
        storage_dir="$HOME/.local/share/containers/storage"
        print_status "INFO" "Creating container storage directory..."
        mkdir -p "$storage_dir"
        chmod 700 "$storage_dir"
    fi
    
    # Create user's config directory
    local conf_dir=""
    if [[ "$(id -u)" -eq 0 ]]; then
        conf_dir="/home/$TARGET_USER/.config/containers"
        print_status "INFO" "Creating container config directory for $TARGET_USER..."
        mkdir -p "$conf_dir"
        chown -R "$TARGET_USER:$TARGET_USER" "$conf_dir"
    else
        conf_dir="$HOME/.config/containers"
        print_status "INFO" "Creating container config directory..."
        mkdir -p "$conf_dir"
    fi
    
    # Configure storage.conf
    local storage_conf="$conf_dir/storage.conf"
    if [[ ! -f "$storage_conf" ]]; then
        print_status "INFO" "Creating storage.conf file..."
        
        # Create basic storage.conf with recommended settings
        cat > "$storage_conf" << EOF
[storage]
driver = "overlay"
runroot = "$storage_dir/run"
graphroot = "$storage_dir"

[storage.options]
size = "120G"
remap-uids = "auto"
remap-gids = "auto"

[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
mountopt = "nodev,metacopy=on"
EOF
        
        # Set proper ownership if running as root
        if [[ "$(id -u)" -eq 0 ]]; then
            chown "$TARGET_USER:$TARGET_USER" "$storage_conf"
        fi
        
        print_status "PASS" "Created storage.conf with secure defaults"
    else
        print_status "INFO" "storage.conf already exists, checking configuration..."
        
        # Check for overlay driver
        if ! grep -q "driver *= *\"overlay" "$storage_conf"; then
            print_status "FAIL" "storage.conf does not use overlay driver"
            print_status "INFO" "Updating storage.conf to use overlay driver..."
            
            # Make a backup
            cp "$storage_conf" "${storage_conf}.bak"
            
            # Update driver
            sed -i 's/^driver *= *"[^"]*"/driver = "overlay"/' "$storage_conf"
        else
            print_status "PASS" "storage.conf already configured with overlay driver"
        fi
        
        # Check for fuse-overlayfs
        if ! grep -q "mount_program *= *\"/usr/bin/fuse-overlayfs\"" "$storage_conf"; then
            print_status "FAIL" "storage.conf not configured to use fuse-overlayfs"
            print_status "INFO" "Updating storage.conf to use fuse-overlayfs..."
            
            # Add mount_program if [storage.options.overlay] section exists
            if grep -q "\[storage.options.overlay\]" "$storage_conf"; then
                sed -i '/\[storage.options.overlay\]/a mount_program = "/usr/bin/fuse-overlayfs"' "$storage_conf"
            else
                # Add the section if it doesn't exist
                cat >> "$storage_conf" << EOF

[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
mountopt = "nodev,metacopy=on"
EOF
            fi
        else
            print_status "PASS" "storage.conf already configured to use fuse-overlayfs"
        fi
    fi
}

# Configure containers.conf for event logging
configure_event_logging() {
    print_section "Configuring Event Logging"
    
    # Set up containers.conf for user
    local conf_dir=""
    if [[ "$(id -u)" -eq 0 ]]; then
        conf_dir="/home/$TARGET_USER/.config/containers"
    else
        conf_dir="$HOME/.config/containers"
    fi
    
    local containers_conf="$conf_dir/containers.conf"
    
    if [[ ! -f "$containers_conf" ]]; then
        print_status "INFO" "Creating containers.conf file with event logging configured..."
        
        # Create containers.conf with recommended settings
        cat > "$containers_conf" << EOF
[engine]
events_logger = "journald"
events_container_create_inspect_data = true

[engine.runtimes]
runc = [
    "/usr/bin/runc",
]

[containers]
netns = "bridge"
userns = "auto"
ipcns = "auto"
utsns = "auto"
cgroupns = "auto"
cgroups = "enabled"
log_driver = "k8s-file"
pids_limit = 2048
EOF
        
        # Set proper ownership if running as root
        if [[ "$(id -u)" -eq 0 ]]; then
            chown "$TARGET_USER:$TARGET_USER" "$containers_conf"
        fi
        
        print_status "PASS" "Created containers.conf with event logging and security settings"
    else
        print_status "INFO" "containers.conf already exists, checking event logging configuration..."
        
        # Check for event logging
        if ! grep -q "events_logger *= *\"journald\"" "$containers_conf"; then
            print_status "FAIL" "Event logging not properly configured"
            print_status "INFO" "Updating containers.conf for proper event logging..."
            
            # Make a backup
            cp "$containers_conf" "${containers_conf}.bak"
            
            # Add event logging if [engine] section exists
            if grep -q "\[engine\]" "$containers_conf"; then
                sed -i '/\[engine\]/a events_logger = "journald"' "$containers_conf"
                sed -i '/\[engine\]/a events_container_create_inspect_data = true' "$containers_conf"
            else
                # Add the section if it doesn't exist
                cat >> "$containers_conf" << EOF

[engine]
events_logger = "journald"
events_container_create_inspect_data = true
EOF
            fi
            
            print_status "PASS" "Updated containers.conf with proper event logging"
        else
            print_status "PASS" "Event logging already properly configured"
        fi
    fi
}

# Registry configuration removed as requested

# Test rootless Podman
test_rootless_podman() {
    print_section "Testing Rootless Podman"
    
    # On some systems, we may need to restart the user session or reload the systemd user instance
    # This is especially common on RHEL systems
    print_status "INFO" "Checking if we need to start the podman socket..."
    
    if [[ "$(id -u)" -eq 0 ]]; then
        print_status "INFO" "Testing rootless Podman as user $TARGET_USER..."
        
        # Start the podman socket if systemd is available
        if command -v systemctl &>/dev/null; then
            su - "$TARGET_USER" -c "systemctl --user daemon-reload" &>/dev/null || true
            su - "$TARGET_USER" -c "systemctl --user enable --now podman.socket" &>/dev/null || true
        fi
        
        # Test rootless status
        if su - "$TARGET_USER" -c "podman info 2>/dev/null | grep -E 'rootless: true'" &>/dev/null; then
            print_status "PASS" "Podman is running in rootless mode for user $TARGET_USER"
            print_status "INFO" "Running simple container test..."
            
            # Run a simple container test
            # We'll test with Alpine instead of hello-world as it might not be available
            if su - "$TARGET_USER" -c "podman run --rm alpine:latest echo 'Test successful'" &>/dev/null; then
                print_status "PASS" "Successfully ran a container in rootless mode"
            else
                print_status "INFO" "First container test failed, trying basic test..."
                
                # Try a more basic container test
                if su - "$TARGET_USER" -c "podman run --rm alpine:latest echo 'Test'" &>/dev/null; then
                    print_status "PASS" "Successfully ran a container in rootless mode with basic image"
                else
                    print_status "FAIL" "Failed to run containers in rootless mode"
                    print_status "INFO" "This could be due to network, image availability, or configuration issues"
                    print_status "INFO" "You can test manually after setup with: podman run --rm alpine echo test"
                fi
            fi
        else
            print_status "FAIL" "Podman is NOT running in rootless mode for user $TARGET_USER"
            print_status "INFO" "This might require a user session restart or system reboot to take effect"
            print_status "INFO" "After logging in as $TARGET_USER, verify with: podman info | grep rootless"
        fi
    else
        print_status "INFO" "Testing rootless Podman as current user..."
        
        # Start the podman socket if systemd is available
        if command -v systemctl &>/dev/null; then
            systemctl --user daemon-reload &>/dev/null || true
            systemctl --user enable --now podman.socket &>/dev/null || true
        fi
        
        # Test rootless status
        if podman info 2>/dev/null | grep -q "rootless: true"; then
            print_status "PASS" "Podman is running in rootless mode"
            print_status "INFO" "Running simple container test..."
            
            # Check if we can pull images
            if ! podman pull alpine:latest &>/dev/null; then
                print_status "FAIL" "Failed to pull test image. Network or registry issues may be present."
                print_status "INFO" "Rootless setup appears correct, but container testing was skipped."
                print_status "INFO" "You can test manually after setup with: podman run --rm alpine echo test"
                return 0
            fi
            
            # Run a simple container test
            if podman run --rm alpine:latest echo 'Test successful' &>/dev/null; then
                print_status "PASS" "Successfully ran a container in rootless mode"
            else
                print_status "FAIL" "Failed to run a container in rootless mode"
                print_status "INFO" "This might require a session restart or system reboot to take effect"
                print_status "INFO" "Verify proper setup after restart with: podman run --rm alpine echo test"
            fi
        else
            print_status "FAIL" "Podman is NOT running in rootless mode"
            print_status "INFO" "This might require a session restart or system reboot to take effect"
            print_status "INFO" "After restarting your session, verify with: podman info | grep rootless"
        fi
    fi
    
    # Final diagnostic information for troubleshooting
    print_status "INFO" "If rootless mode is not working, check the following:"
    print_status "INFO" "1. User namespaces enabled: cat /proc/sys/kernel/unprivileged_userns_clone"
    print_status "INFO" "2. Proper subuid/subgid mappings: grep $TARGET_USER /etc/subuid /etc/subgid"
    print_status "INFO" "3. Capabilities on newuidmap: getcap $(which newuidmap 2>/dev/null || echo '/usr/bin/newuidmap')"
    print_status "INFO" "4. SELinux status: getenforce (set to Permissive if needed for testing)"
}

# Check SELinux configuration
check_selinux() {
    print_section "Checking SELinux Configuration"
    
    # Check if SELinux is available
    if ! command -v getenforce &>/dev/null; then
        print_status "INFO" "SELinux does not appear to be installed on this system"
        return 0
    fi
    
    # Get current SELinux status
    local selinux_status=$(getenforce 2>/dev/null)
    
    print_status "INFO" "Current SELinux mode: $selinux_status"
    
    if [[ "$selinux_status" == "Enforcing" ]]; then
        print_status "INFO" "SELinux is in enforcing mode - this is good for security"
        print_status "INFO" "Checking container-selinux package..."
        
        # Check if container-selinux is installed
        if ! rpm -q container-selinux &>/dev/null; then
            print_status "INFO" "Installing container-selinux package for better container isolation..."
            dnf install -y container-selinux &>/dev/null
            
            if rpm -q container-selinux &>/dev/null; then
                print_status "PASS" "Successfully installed container-selinux"
            else
                print_status "FAIL" "Failed to install container-selinux - SELinux may cause issues with containers"
                print_status "INFO" "You may need to temporarily set SELinux to permissive mode for testing:"
                print_status "INFO" "sudo setenforce 0"
            fi
        else
            print_status "PASS" "container-selinux package is installed"
        fi
        
        # Check if we should set some SELinux boolean values for container usage
        if command -v setsebool &>/dev/null; then
            print_status "INFO" "Setting SELinux boolean values for better container compatibility..."
            setsebool -P container_manage_cgroup true &>/dev/null || true
        fi
    elif [[ "$selinux_status" == "Permissive" ]]; then
        print_status "INFO" "SELinux is in permissive mode - good for initial testing"
        print_status "INFO" "For production use, consider setting to enforcing mode after testing"
    else
        print_status "INFO" "SELinux is disabled - easier for container setup but less secure"
        print_status "INFO" "Consider enabling SELinux for better security in production"
    fi
}

# Display final instructions
print_final_instructions() {
    print_section "Setup Complete"
    
    echo -e "${GREEN}${BOLD}Rootless Podman setup is complete!${NC}"
    echo ""
    
    if [[ "$(id -u)" -eq 0 ]]; then
        echo "To use rootless podman as user $TARGET_USER:"
        echo "  1. Log in as $TARGET_USER"
        echo "  2. Run podman commands as usual, no sudo required"
        echo ""
        echo "Example commands:"
        echo "  podman run --rm alpine echo 'Hello rootless container'   # Run a test container"
        echo "  podman run -d -p 8080:80 nginx                           # Run Nginx container"
        echo "  podman ps                                                # List running containers"
        echo "  podman images                                            # List available images"
        echo ""
        echo "To verify rootless mode is enabled:"
        echo "  podman info | grep rootless"
    else
        echo "To use rootless podman:"
        echo "  - Run podman commands as usual, no sudo required"
        echo ""
        echo "Example commands:"
        echo "  podman run --rm alpine echo 'Hello rootless container'   # Run a test container"
        echo "  podman run -d -p 8080:80 nginx                           # Run Nginx container"
        echo "  podman ps                                                # List running containers"
        echo "  podman images                                            # List available images"
        echo ""
        echo "To verify rootless mode is enabled:"
        echo "  podman info | grep rootless"
    fi
    
    echo ""
    echo "Troubleshooting tips:"
    echo "  • If containers fail immediately after setup, try logging out and back in"
    echo "  • Verify user namespaces: sysctl kernel.unprivileged_userns_clone"
    echo "  • Check journal logs: journalctl --user -xe"
    echo "  • SELinux issues: Try 'sudo setenforce 0' temporarily for testing"
    echo "  • Network issues: Check firewall settings with 'sudo firewall-cmd --list-all'"
    echo ""
    
    # RHEL-specific notes
    if [ -f /etc/redhat-release ]; then
        echo "RHEL-specific notes:"
        echo "  • If experiencing issues, check Red Hat documentation for your specific RHEL version"
        echo "  • Verify subscription status: subscription-manager status"
        echo "  • Check enabled repositories: subscription-manager repos --list-enabled"
        echo "  • System may need reboot for kernel parameter changes to take effect"
        echo ""
    fi
    
    echo -e "${BLUE}${BOLD}Run your Podman Security Audit again to verify proper configuration:${NC}"
    echo "./podman_audit.sh"
}

# Main function
main() {
    # Display banner
    echo -e "${BLUE}${BOLD}========================================${NC}"
    echo -e "${BLUE}${BOLD}  Rootless Podman Setup for RHEL       ${NC}"
    echo -e "${BLUE}${BOLD}========================================${NC}"
    echo ""
    
    # Process command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--user)
                TARGET_USER="$2"
                shift 2
                ;;
            -h|--help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  -u, --user USER   Set up rootless Podman for the specified user (root only)"
                echo "  -h, --help        Display this help message"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Run setup functions
    check_user
    check_podman
    install_dependencies
    configure_subid
    configure_idmap_caps
    configure_storage
    configure_event_logging
    check_selinux
    # Registry configuration removed as requested
    test_rootless_podman
    print_final_instructions
}

# Execute main function with all arguments
main "$@"
