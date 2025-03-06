#!/bin/bash
#
# Podman Security Audit Tool
# This script performs a comprehensive security audit of Podman deployments
# for security engineers and administrators.

# Removed set -e to prevent script from exiting on errors
# We handle errors within functions and want the script to continue running all checks

# Text formatting - ensure compatibility with RHEL
RED=$(tput setaf 1 2>/dev/null || echo '\033[0;31m')
GREEN=$(tput setaf 2 2>/dev/null || echo '\033[0;32m')
BLUE=$(tput setaf 4 2>/dev/null || echo '\033[0;34m')
NC=$(tput sgr0 2>/dev/null || echo '\033[0m') # No Color
BOLD=$(tput bold 2>/dev/null || echo '\033[1m')

# Headers and results
PASS="${GREEN}[PASS]${NC}"
FAIL="${RED}[FAIL]${NC}"

# Script global variables
OUTPUT_DIR=""
REPORT_FILE=""
FULL_SCAN=false
JSON_OUTPUT=false
VERBOSE=false

# Help function
print_help() {
    echo "Podman Security Audit Tool"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -o, --output DIR     Output directory for reports (default: current directory)"
    echo "  -f, --full           Perform full scan (including more extensive audits)"
    echo "  -j, --json           Output results in JSON format"
    echo "  -v, --verbose        Enable verbose output"
    echo "  -h, --help           Display this help message"
    echo ""
    echo "Example: $0 --output /tmp/podman-audit --full"
    exit 0
}

# Process command line arguments
process_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -f|--full)
                FULL_SCAN=true
                shift
                ;;
            -j|--json)
                JSON_OUTPUT=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                print_help
                ;;
            *)
                echo "Unknown option: $1"
                print_help
                ;;
        esac
    done

    # Set default output directory if not specified
    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="$(pwd)/podman_audit_$(date +%Y%m%d_%H%M%S)"
    fi
    
    # Create output directory if it doesn't exist
    mkdir -p "$OUTPUT_DIR"
    
    # Set report file
    REPORT_FILE="$OUTPUT_DIR/podman_audit_report.txt"
    
    # Initialize report file with header
    echo "# Podman Security Audit Report" > "$REPORT_FILE"
    echo "# Date: $(date)" >> "$REPORT_FILE"
    echo "# Hostname: $(hostname)" >> "$REPORT_FILE"
    echo "# ----------------------------------------" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Initialize recommendations files
    echo "# Security Recommendations" > "$OUTPUT_DIR/recommendations.txt"
    echo "" >> "$OUTPUT_DIR/recommendations.txt"
    echo "# Security Best Practices" > "$OUTPUT_DIR/best_practices.txt"
    echo "" >> "$OUTPUT_DIR/best_practices.txt"
}

# Log to both console and file with optional recommendation
log() {
    local level="$1"
    local message="$2"
    local recommendation="$3"
    local output="${level} ${message}"
    
    echo -e "$output"
    echo "$output" >> "$REPORT_FILE"
    
    # Save recommendation for later if provided
    if [[ -n "$recommendation" && "$level" == "$FAIL" ]]; then
        echo "- $message: $recommendation" >> "$OUTPUT_DIR/recommendations.txt"
    elif [[ -n "$recommendation" && "$level" == "$PASS" ]]; then
        echo "- $message" >> "$OUTPUT_DIR/best_practices.txt"
    fi
}

# Check Podman installation and version
check_podman_installation() {
    # Checking Podman installation
    
    if ! command -v podman &> /dev/null; then
        log "$FAIL" "Podman is not installed" "Install Podman using your system's package manager (dnf install podman for RHEL/Fedora or apt install podman for Debian/Ubuntu)"
        # Don't exit due to set -e, continue with other checks
        return 0
    fi
    
    local version=$(podman version --format "{{.Version}}" 2>/dev/null)
    if [[ -z "$version" ]]; then
        version=$(podman --version | awk '{print $3}')
    fi
    
    log "$PASS" "Podman version $version is installed" "Regularly check for updates to maintain security posture"
    
    # Check if version is recent (example: consider versions older than 3.0 as potentially problematic)
    local major_version=$(echo "$version" | cut -d. -f1)
    if [[ $major_version -lt 3 ]]; then
        log "$FAIL" "Podman version is older than 3.0, consider updating for latest security features" "Update Podman to version 3.0 or higher to benefit from security enhancements and CVE fixes"
    fi
    
    return 0
}

# Check if Podman is running in rootless mode
check_rootless_mode() {
    # Checking if Podman is running in rootless mode
    
    if podman info 2>/dev/null | grep -q "rootless: true"; then
        log "$PASS" "Podman is running in rootless mode" "Rootless mode provides better security by isolating containers from the host system"
    else
        log "$FAIL" "Podman is NOT running in rootless mode - this is a security concern" "Configure Podman to run in rootless mode: https://github.com/containers/podman/blob/main/docs/tutorials/rootless_tutorial.md"
    fi
    # Always return 0 to prevent set -e from stopping the script
    return 0
}

# Check user namespaces configuration
check_user_namespaces() {
    # Checking user namespace configuration
    
    local current_user=$(whoami)
    
    # Check if current user has subuids and subgids configured
    if grep -q "$current_user" /etc/subuid && grep -q "$current_user" /etc/subgid; then
        local subuid_count=$(grep "$current_user" /etc/subuid | cut -d: -f3)
        local subgid_count=$(grep "$current_user" /etc/subgid | cut -d: -f3)
        
        log "$PASS" "User $current_user has subuid and subgid allocations" "Proper UID/GID mappings are essential for rootless container security"
        
        # Check if the counts are sufficient
        if [[ $subuid_count -lt 65536 || $subgid_count -lt 65536 ]]; then
            log "$FAIL" "Subuid/Subgid counts are less than recommended 65536" "Configure at least 65536 subordinate UIDs/GIDs in /etc/subuid and /etc/subgid. Run: usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $current_user"
        fi
    else
        log "$FAIL" "User $current_user does not have proper subuid/subgid mappings" "Add subordinate UIDs/GIDs by running: usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $current_user"
    fi
    
    # Check if newuidmap and newgidmap are available
    if ! command -v newuidmap &> /dev/null || ! command -v newgidmap &> /dev/null; then
        log "$FAIL" "newuidmap or newgidmap tools are missing" "Install shadow-utils package: dnf install shadow-utils (RHEL/Fedora) or apt install uidmap (Debian/Ubuntu)"
    else
        # Check if they have the necessary capabilities
        if command -v getcap &> /dev/null; then
            local uidmap_caps=$(getcap $(which newuidmap) 2>/dev/null)
            local gidmap_caps=$(getcap $(which newgidmap) 2>/dev/null)
            
            if [[ "$uidmap_caps" == *"cap_setuid"* ]]; then
                log "$PASS" "newuidmap has correct capabilities" "Proper capabilities allow secure user namespace mappings"
            else
                log "$FAIL" "newuidmap lacks cap_setuid capability" "Set the capability: sudo setcap cap_setuid+ep $(which newuidmap)"
            fi
            
            if [[ "$gidmap_caps" == *"cap_setgid"* ]]; then
                log "$PASS" "newgidmap has correct capabilities" "Proper capabilities allow secure user namespace mappings"
            else
                log "$FAIL" "newgidmap lacks cap_setgid capability" "Set the capability: sudo setcap cap_setgid+ep $(which newgidmap)"
            fi
        else
            log "$FAIL" "Cannot check capabilities of newuidmap/newgidmap (getcap not available)" "Install libcap-utils package: dnf install libcap (RHEL/Fedora) or apt install libcap2-bin (Debian/Ubuntu)"
        fi
    fi
}

# Check SELinux on host
check_selinux_on_host() {
    # Checking SELinux status on host
    
    # Check if SELinux is available
    if command -v getenforce &> /dev/null; then
        local selinux_status=$(getenforce 2>/dev/null)
        
        if [[ "$selinux_status" == "Enforcing" ]]; then
            log "$PASS" "SELinux is enabled and in enforcing mode" "SELinux enforcing mode provides strong security isolation between containers and host"
        elif [[ "$selinux_status" == "Permissive" ]]; then
            log "$FAIL" "SELinux is in permissive mode" "Set SELinux to enforcing mode by editing /etc/selinux/config and setting SELINUX=enforcing, then reboot"
        else
            log "$FAIL" "SELinux is disabled" "Enable SELinux by editing /etc/selinux/config and setting SELINUX=enforcing, then reboot. May require system relabeling"
        fi
    else
        # Check if AppArmor is available as an alternative
        if command -v aa-status &> /dev/null; then
            if aa-status --enabled &>/dev/null; then
                log "$PASS" "AppArmor is enabled" "AppArmor provides containment mechanism for container security"
            else
                log "$FAIL" "AppArmor is disabled" "Enable AppArmor with: systemctl enable --now apparmor.service"
            fi
        else
            log "$FAIL" "Neither SELinux nor AppArmor is installed" "Install either SELinux (dnf install selinux-policy-targeted) or AppArmor (apt install apparmor apparmor-utils)"
        fi
    fi
}

# Check storage configuration
check_storage_configuration() {
    # Checking Podman storage configuration
    
    # Get storage configuration
    local storage_driver=$(podman info 2>/dev/null | grep "GraphDriverName" | awk '{print $2}')
    local storage_location=$(podman info 2>/dev/null | grep "GraphRoot" | awk '{print $2}')
    
    # Check if preferred storage driver is used
    if [[ "$storage_driver" == "overlay" || "$storage_driver" == "overlay2" ]]; then
        log "$PASS" "Using recommended storage driver: $storage_driver" "Overlay2 provides optimal performance and security for container storage"
    else
        log "$FAIL" "Not using recommended overlay/overlay2 storage driver" "Configure overlay2 storage driver in /etc/containers/storage.conf with driver = \"overlay2\""
    fi
    
    # Check storage location permissions
    if [[ -d "$storage_location" ]]; then
        local owner=$(stat -c '%U' "$storage_location")
        local perms=$(stat -c '%a' "$storage_location")
        
        # Check if storage is owned by current user (for rootless)
        if [[ "$owner" != "$(whoami)" && "$(whoami)" != "root" ]]; then
            log "$FAIL" "Storage directory not owned by current user (may indicate misconfiguration)" "Change ownership of $storage_location to $(whoami): sudo chown -R $(whoami):$(whoami) $storage_location"
        fi
        
        # Check permissions (should be 700 for security)
        if [[ "$perms" != "700" && "$perms" != "7"* ]]; then
            log "$FAIL" "Storage directory has loose permissions: $perms (recommended: 700)" "Secure storage directory permissions: chmod 700 $storage_location"
        else
            log "$PASS" "Storage directory has appropriate permissions" "Maintaining 700 permissions prevents unauthorized access to container data"
        fi
    else
        log "$FAIL" "Storage location does not exist or is not accessible" "Create the storage directory with correct permissions: mkdir -p $storage_location && chmod 700 $storage_location"
    fi
    
    # Check for fuse-overlayfs for rootless (if overlay driver is used)
    if [[ "$storage_driver" == "overlay" || "$storage_driver" == "overlay2" ]]; then
        if podman info 2>/dev/null | grep -q "mount_program: /usr/bin/fuse-overlayfs"; then
            log "$PASS" "Using fuse-overlayfs for rootless overlay storage" "fuse-overlayfs provides better performance for rootless containers"
        else
            # Only warn if running rootless
            if [[ "$(whoami)" != "root" ]]; then
                log "$FAIL" "Not using fuse-overlayfs for rootless overlay storage" "Install fuse-overlayfs: dnf install fuse-overlayfs (RHEL/Fedora) or apt install fuse-overlayfs (Debian/Ubuntu)"
            fi
        fi
    fi
    
    # Check storage configuration file
    local storage_conf="/etc/containers/storage.conf"
    if [[ -f "$storage_conf" ]]; then
        log "$PASS" "Storage configuration file exists at $storage_conf" "Maintain proper storage configuration settings"
        
        # Check for common storage quota settings
        if grep -q "size" "$storage_conf" && grep -q "quota" "$storage_conf"; then
            log "$PASS" "Storage quota configuration found" "Storage quotas prevent container storage from consuming all disk space"
        else
            log "$FAIL" "No storage quota configuration found" "Add quota configuration to $storage_conf to prevent disk space exhaustion"
        fi
    else
        log "$FAIL" "Storage configuration file not found at $storage_conf" "Create storage configuration file: sudo cp /usr/share/containers/storage.conf /etc/containers/storage.conf"
    fi
}

# Check for registry configuration security
check_registry_configuration() {
    # Checking registry configuration
    
    # Check if any insecure registries are configured
    local insecure_registries=$(podman info 2>/dev/null | grep -A 10 "registries:" | grep "insecure" | grep -v "false")
    
    if [[ -n "$insecure_registries" ]]; then
        log "$FAIL" "Insecure registries are configured" "Remove insecure registry settings as they allow unencrypted HTTP connections and bypass certificate validation"
    else
        log "$PASS" "No insecure registries configured" "Using secure registries protects against man-in-the-middle attacks"
    fi
    
    # Check registry configuration files
    local registry_conf="/etc/containers/registries.conf"
    if [[ -f "$registry_conf" ]]; then
        if grep -q "insecure = true" "$registry_conf"; then
            log "$FAIL" "Insecure registry settings found in $registry_conf" "Edit $registry_conf and set insecure = false for all registries, or remove the insecure setting"
        else
            log "$PASS" "Registry configuration file has secure settings" "Maintaining secure registry settings prevents container supply chain attacks"
        fi
        
        # Check for default registry configuration
        if ! grep -q "^default-registry" "$registry_conf" 2>/dev/null; then
            log "$FAIL" "No default registry configured" "Configure a default registry in $registry_conf to ensure known-good image sources"
        fi
    else
        log "$FAIL" "Registry configuration file not found at $registry_conf" "Create registry configuration file: sudo cp /usr/share/containers/registries.conf /etc/containers/registries.conf"
    fi
    
    local registry_conf_d="/etc/containers/registries.conf.d"
    if [[ -d "$registry_conf_d" ]]; then
        if grep -q "insecure = true" "$registry_conf_d"/* 2>/dev/null; then
            log "$FAIL" "Insecure registry settings found in $registry_conf_d" "Edit files in $registry_conf_d to remove any insecure = true settings"
        else
            log "$PASS" "Registry configuration directory has secure settings" "Maintaining secure registry settings in all config files prevents container supply chain attacks"
        fi
    fi
    
    # Check for policy.json configuration
    local policy_json="/etc/containers/policy.json"
    if [[ -f "$policy_json" ]]; then
        log "$PASS" "Container policy file exists at $policy_json" "Policy file controls which image sources are trusted"
        
        # Check for default policy
        if grep -q '"default": \[ { "type": "insecureAcceptAnything" }\]' "$policy_json"; then
            log "$FAIL" "Default policy is set to insecureAcceptAnything" "Configure $policy_json with a more restrictive default policy to improve supply chain security"
        fi
    else
        log "$FAIL" "Container policy file not found at $policy_json" "Create policy file with secure defaults: sudo cp /usr/share/containers/policy.json /etc/containers/policy.json"
    fi
}

# Check if Podman events are being logged
check_event_logging() {
    # Checking Podman event logging
    
    # Check containers.conf for eventslogger
    local containers_conf="/etc/containers/containers.conf"
    local user_containers_conf="$HOME/.config/containers/containers.conf"
    
    if [[ -f "$containers_conf" ]] && grep -q "events_logger" "$containers_conf"; then
        local event_logger=$(grep "events_logger" "$containers_conf" | awk -F= '{print $2}' | tr -d '[:space:]')
        if [[ "$event_logger" == "\"journald\"" || "$event_logger" == "journald" ]]; then
            log "$PASS" "System-wide Podman events are being logged to journald" "Event logging is critical for security auditing and incident response"
        else
            log "$FAIL" "System-wide Podman events are not being logged to journald (current: $event_logger)" "Edit $containers_conf and set events_logger = \"journald\" under [engine] section"
        fi
    elif [[ -f "$user_containers_conf" ]] && grep -q "events_logger" "$user_containers_conf"; then
        local event_logger=$(grep "events_logger" "$user_containers_conf" | awk -F= '{print $2}' | tr -d '[:space:]')
        if [[ "$event_logger" == "\"journald\"" || "$event_logger" == "journald" ]]; then
            log "$PASS" "User Podman events are being logged to journald" "User-level event logging enables auditing of container activities"
        else
            log "$FAIL" "User Podman events are not being logged to journald (current: $event_logger)" "Edit $user_containers_conf and set events_logger = \"journald\" under [engine] section"
        fi
    else
        # Check default
        if podman info 2>/dev/null | grep -q "events_logger: journald"; then
            log "$PASS" "Podman events are being logged to journald (default setting)" "Default journald logging provides basic audit capability"
        else
            log "$FAIL" "Podman events may not be properly logged to journald" "Create containers.conf with explicit journald logging configuration"
        fi
    fi
    
    # Check for detailed container create events
    if grep -q "events_container_create_inspect_data" "$containers_conf" 2>/dev/null; then
        if grep -q "events_container_create_inspect_data *= *true" "$containers_conf" 2>/dev/null; then
            log "$PASS" "Detailed container creation events are enabled" "Detailed events improve container security forensics"
        else
            log "$FAIL" "Detailed container creation events are disabled" "Edit $containers_conf and set events_container_create_inspect_data = true under [engine] section"
        fi
    elif grep -q "events_container_create_inspect_data" "$user_containers_conf" 2>/dev/null; then
        if grep -q "events_container_create_inspect_data *= *true" "$user_containers_conf" 2>/dev/null; then
            log "$PASS" "Detailed container creation events are enabled (user config)" "User-level detailed events improve container security forensics"
        else
            log "$FAIL" "Detailed container creation events are disabled (user config)" "Edit $user_containers_conf and set events_container_create_inspect_data = true under [engine] section"
        fi
    else
        log "$FAIL" "Detailed container creation event logging not configured" "Add events_container_create_inspect_data = true to containers.conf under [engine] section"
    fi
    
    # Try to check recent events in journald
    if command -v journalctl &> /dev/null; then
        local cmd="journalctl"
        if [[ "$(whoami)" != "root" ]]; then
            cmd="journalctl --user"
        fi
        
        if $cmd -n 1 _COMM=podman &>/dev/null; then
            local event_count=$($cmd -b _COMM=podman | wc -l)
        else
            log "$FAIL" "No Podman events found in journal logs" "Verify systemd-journald is running and properly configured: systemctl status systemd-journald"
        fi
    else
        log "$FAIL" "Cannot check journal logs (journalctl not available)" "Install systemd-journal: dnf install systemd (RHEL/Fedora) or apt install systemd (Debian/Ubuntu)"
    fi
}

# This function has been removed as it checks running containers

# This function has been removed as it checks images

# Check for updates and outdated packages
check_updates() {
    # Checking for Podman updates
    
    # Get current Podman version
    local current_version=$(podman --version | awk '{print $3}')
    
    # Check for available updates based on package manager
    if command -v dnf &> /dev/null; then
        # RHEL/Fedora/CentOS
        local updates=$(dnf check-update podman 2>/dev/null)
        local exit_code=$?
        
        if [[ $exit_code -eq 100 ]]; then
            log "$FAIL" "Podman update available: Current version $current_version" "Update Podman to the latest version: sudo dnf update -y podman"
        elif [[ $exit_code -eq 0 ]]; then
            log "$PASS" "Podman is up to date: $current_version" "Regular updates are essential for security maintenance"
        else
            log "$FAIL" "Failed to check for Podman updates" "Verify dnf configuration and network connectivity"
        fi
    elif command -v apt &> /dev/null; then
        # Debian/Ubuntu
        apt update -qq &>/dev/null
        local update_available=$(apt list --upgradable 2>/dev/null | grep -c "podman")
        
        if [[ $update_available -gt 0 ]]; then
            log "$FAIL" "Podman update available: Current version $current_version" "Update Podman to the latest version: sudo apt update && sudo apt upgrade -y podman"
        else
            log "$PASS" "Podman is up to date: $current_version" "Regular updates are essential for security maintenance"
        fi
    else
        log "$FAIL" "Cannot check for Podman updates - unsupported package manager" "Install a supported package manager or manually verify Podman is up to date"
    fi
}

# Check network configurations
check_network_configuration() {
    # Checking Podman network configuration
    
    # List networks
    local networks=$(podman network ls --format "{{.Name}}")
    
    # Check if podman network is properly configured
    if podman network ls 2>/dev/null | grep -q "podman"; then
        log "$PASS" "Podman default network is configured" "Default network configuration enables proper container isolation"
    else
        log "$FAIL" "Podman default network may be misconfigured" "Recreate the default network: podman network rm podman && podman network create podman"
    fi
    
    # Check CNI configuration
    local cni_config_dir="/etc/cni/net.d"
    if [[ -d "$cni_config_dir" ]]; then
        if [[ "$(ls -A $cni_config_dir 2>/dev/null)" ]]; then
            log "$PASS" "CNI network configuration exists in $cni_config_dir" "CNI configuration provides network isolation between containers"
        else
            log "$FAIL" "CNI config directory exists but is empty" "Install CNI plugins: dnf install containernetworking-plugins (RHEL/Fedora) or apt install containernetworking-plugins (Debian/Ubuntu)"
        fi
    else
        log "$FAIL" "CNI configuration directory not found" "Create CNI configuration directory: sudo mkdir -p /etc/cni/net.d"
    fi
    
    # Check if firewall is configured for podman
    if command -v firewall-cmd &> /dev/null; then
        if firewall-cmd --list-all 2>/dev/null | grep -q "podman"; then
            log "$PASS" "Firewall is configured with podman-specific rules" "Firewall configuration prevents unauthorized network access to containers"
        else
            log "$FAIL" "No podman-specific firewall rules detected" "Configure firewall for Podman: firewall-cmd --permanent --zone=trusted --add-interface=cni-podman0 && firewall-cmd --reload"
        fi
    fi
}

# This function has been removed as it checks running containers

# Check for Jenkins security if running in Jenkins environment
check_jenkins_security() {
    # Checking for Jenkins integration with Podman
    
    # Check if Jenkins is installed
    if command -v jenkins &> /dev/null || [[ -d "/var/lib/jenkins" ]]; then
        
        # Check Jenkins user
        local jenkins_user="jenkins"
        if id "$jenkins_user" &>/dev/null; then
            log "$PASS" "Jenkins user exists" "Jenkins CI/CD integration requires proper user configuration"
            
            # Check if Jenkins user has sudo access
            if groups "$jenkins_user" | grep -q "sudo\|wheel"; then
                log "$FAIL" "Jenkins user has sudo group membership" "Remove jenkins from sudo/wheel group for better security: sudo gpasswd -d jenkins sudo"
            else
                log "$PASS" "Jenkins user does not have sudo group membership" "Restricting Jenkins user privileges follows the principle of least privilege"
            fi
            
            # Check if Jenkins user has subuid/subgid mappings
            if grep -q "$jenkins_user" /etc/subuid && grep -q "$jenkins_user" /etc/subgid; then
                log "$PASS" "Jenkins user has subuid/subgid mappings for rootless Podman" "Proper UID/GID mappings allow Jenkins to run Podman in rootless mode"
            else
                log "$FAIL" "Jenkins user lacks subuid/subgid mappings" "Add subordinate UIDs/GIDs: usermod --add-subuids 100000-165535 --add-subgids 100000-165535 jenkins"
            fi
            
            # Check for sudoers entries for jenkins
            if [[ -f "/etc/sudoers" ]] && grep -q "$jenkins_user" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
                log "$FAIL" "Jenkins user has sudoers entries" "Remove Jenkins user from sudoers files to prevent privilege escalation"
                grep "$jenkins_user" /etc/sudoers /etc/sudoers.d/* 2>/dev/null | while read line; do
                    if [[ "$line" == *"ALL"*"ALL"*"NOPASSWD"* ]]; then
                        log "$FAIL" "Jenkins user has unrestricted sudo access" "Remove NOPASSWD sudo access for Jenkins user immediately to prevent privilege escalation"
                    fi
                done
            else
                log "$PASS" "Jenkins user has no sudoers entries" "Jenkins should not have sudo access for better security isolation"
            fi
        fi
    fi
}

# Generate a security summary score
generate_security_score() {
    # Generating security score
    
    # Count fails and passes - using sed to clean ANSI color codes
    local fails=$(grep -c "\[FAIL\]" "$REPORT_FILE")
    local passes=$(grep -c "\[PASS\]" "$REPORT_FILE")
    local total=$((fails + passes))
    
    # Calculate score without using bc (simple weighted calculation)
    # Each pass = 1 point, each fail = 0 points
    local score=0
    if [[ $total -gt 0 ]]; then
        # Integer math: multiply by 100 first to get percentage, then by 100 again for 2 decimal precision
        local weighted_score=$(( passes * 100 * 100 / total ))
        # Format as decimal with 2 places (e.g. 7550 becomes 75.50)
        score=$(printf "%d.%02d" $(( weighted_score / 100 )) $(( weighted_score % 100 )))
    fi
    
    # Security posture summary
    log "$FAIL" "Critical issues: $fails"
    log "$PASS" "Passed checks: $passes"
    log "$PASS" "Total checks: $total"
    log "$PASS" "Security score: $score%"
    
    # Interpret score without using bc
    if [[ -z "$score" ]]; then
        log "$FAIL" "Overall security rating: POOR - No valid checks performed"
    elif (( $(printf "%.0f" "$score") >= 90 )); then
        log "$PASS" "Overall security rating: EXCELLENT"
    elif (( $(printf "%.0f" "$score") >= 75 )); then
        log "$PASS" "Overall security rating: GOOD"
    elif (( $(printf "%.0f" "$score") >= 60 )); then
        log "$FAIL" "Overall security rating: FAIR"
    else
        log "$FAIL" "Overall security rating: POOR - Immediate attention required"
    fi
    
    # Add recommendations based on findings
    echo -e "\n## Security Recommendations" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    if [[ $fails -gt 0 ]]; then
        echo "### Critical Issues to Address:" >> "$REPORT_FILE"
        if [[ -f "$OUTPUT_DIR/recommendations.txt" ]]; then
            cat "$OUTPUT_DIR/recommendations.txt" >> "$REPORT_FILE"
        else
            grep "\[FAIL\]" "$REPORT_FILE" | sed 's/\x1B\[[0-9;]*[mK]//g' | sort | uniq >> "$REPORT_FILE"
        fi
        echo "" >> "$REPORT_FILE"
    fi
    
    # Add best practices section
    echo "### Security Best Practices:" >> "$REPORT_FILE"
    if [[ -f "$OUTPUT_DIR/best_practices.txt" ]]; then
        cat "$OUTPUT_DIR/best_practices.txt" >> "$REPORT_FILE"
    else
        echo "- Follow principle of least privilege for all Podman operations" >> "$REPORT_FILE"
        echo "- Regularly update Podman and container images" >> "$REPORT_FILE"
        echo "- Use rootless Podman for day-to-day operations" >> "$REPORT_FILE"
        echo "- Configure SELinux/AppArmor for stronger container isolation" >> "$REPORT_FILE"
        echo "- Use secure registries with proper authentication" >> "$REPORT_FILE"
    fi
    echo "" >> "$REPORT_FILE"
    
    # Add remediation timeline recommendation based on score
    echo "### Recommended Remediation Timeline:" >> "$REPORT_FILE"
    if [[ -z "$score" || $(printf "%.0f" "$score") -lt 60 ]]; then
        echo "CRITICAL: Address security issues immediately (within 24-48 hours)" >> "$REPORT_FILE"
    elif (( $(printf "%.0f" "$score") < 75 )); then
        echo "HIGH: Address security issues within 1 week" >> "$REPORT_FILE"
    elif (( $(printf "%.0f" "$score") < 90 )); then
        echo "MEDIUM: Address security issues within 2 weeks" >> "$REPORT_FILE"
    else
        echo "LOW: Continue monitoring and maintaining current security posture" >> "$REPORT_FILE"
    fi
    echo "" >> "$REPORT_FILE"
}

# Generate a JSON report if requested
generate_json_report() {
    if [[ "$JSON_OUTPUT" == "true" ]]; then
        # Generating JSON report
        
        local json_file="$OUTPUT_DIR/podman_audit_report.json"
        
        # Convert the report to JSON
        {
            echo "{"
            echo "  \"report_date\": \"$(date -Iseconds)\","
            echo "  \"hostname\": \"$(hostname)\","
            echo "  \"podman_version\": \"$(podman --version | awk '{print $3}')\","
            echo "  \"findings\": ["
            
            # Process each finding
            local first=true
            while IFS= read -r line; do
                if [[ "$line" == *"[PASS]"* || "$line" == *"[FAIL]"* ]]; then
                    local level=""
                    if [[ "$line" == *"[PASS]"* ]]; then
                        level="PASS"
                    elif [[ "$line" == *"[FAIL]"* ]]; then
                        level="FAIL"
                    fi
                    
                    # Extract the message (remove colors and level prefix) - use full pattern match
                    local message=$(echo "$line" | sed 's/\x1B\[[0-9;]*[mK]//g' | sed "s/\[$level\] //")
                    
                    if [[ "$first" == "true" ]]; then
                        first=false
                    else
                        echo ","
                    fi
                    
                    echo "    {"
                    echo "      \"level\": \"$level\","
                    echo "      \"message\": \"$message\""
                    echo -n "    }"
                fi
            done < "$REPORT_FILE"
            
            echo ""
            echo "  ]"
            echo "}"
        } > "$json_file"
        
        # JSON report saved
    fi
}

# Main function
main() {
    echo -e "${BLUE}${BOLD}Podman Security Audit Tool${NC}"
    echo -e "${BLUE}========================================${NC}"
    
    # Process arguments
    process_args "$@"
    
    # Start time
    local start_time=$(date +%s)
    
    # Run checks - only configuration checks, no container scanning
    check_podman_installation
    check_rootless_mode
    check_user_namespaces
    check_selinux_on_host
    check_storage_configuration
    check_registry_configuration
    check_event_logging
    check_network_configuration
    
    # Skip updates check for offline environment
    # check_updates
    log "$FAIL" "Skipping podman updates check for offline environment" "Configure automated updates when online: systemctl enable --now dnf-automatic.timer (RHEL/Fedora) or apt install unattended-upgrades (Debian/Ubuntu)"
    
    # Generate summary
    generate_security_score
    
    # Generate JSON if requested
    generate_json_report
    
    # End time and duration
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Final report
    log "$PASS" "Audit completed in $duration seconds"
    log "$PASS" "Report saved to $REPORT_FILE"
    echo -e "${BLUE}${BOLD}========================================${NC}"
    echo -e "${GREEN}Podman Security Audit complete!${NC}"
    echo -e "Report saved to: ${BOLD}$REPORT_FILE${NC}"
}

# Run main function with all arguments
main "$@"
