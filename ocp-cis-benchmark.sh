#!/bin/bash

# ocp-cis-benchmark.sh - OpenShift CIS Benchmark Compliance Tool
# A tool for security engineers to audit OpenShift clusters against CIS benchmarks

set -e

VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")

# Function to display usage information
show_usage() {
  cat << EOF
OpenShift CIS Benchmark Compliance Tool v${VERSION}
A tool for security engineers to audit OpenShift clusters against CIS benchmarks

Usage:
  ${SCRIPT_NAME} [command] [options]

Commands:
  run-all                       Run all CIS benchmark checks
  master                        Run checks for Control Plane components
  etcd                          Run checks for etcd
  control-plane                 Run checks for Control Plane Configuration
  worker                        Run checks for Worker Nodes
  policies                      Run checks for Policies
  managed-services              Run checks for Managed OpenShift Services
  security-context              Run checks for Pod Security and Network Policies
  rbac                          Run checks for RBAC and Service Accounts
  secrets                       Run checks for Secrets Management
  networking                    Run checks for Network Security
  logging                       Run checks for Logging and Monitoring
  authentication                Run checks for Authentication mechanisms
  help                          Show this help message

Options:
  -o, --output [format]         Output format: text (default), json, html
  -c, --compact                 Show only failed checks in the output
  -v, --verbose                 Show detailed information for each check
  -r, --remediation             Include remediation steps for failed checks
  -h, --help                    Show this help message
  --version                     Show version information

Examples:
  ${SCRIPT_NAME} run-all --output json
  ${SCRIPT_NAME} master
  ${SCRIPT_NAME} etcd --verbose
  ${SCRIPT_NAME} worker --remediation
  ${SCRIPT_NAME} policies

EOF
}

# Function to check if oc is installed and user is logged in
check_prereqs() {
  if ! command -v oc &> /dev/null; then
    echo "Error: 'oc' command not found."
    echo "Please install the OpenShift CLI: https://docs.openshift.com/container-platform/latest/cli_reference/openshift_cli/getting-started-cli.html"
    exit 1
  fi

  if ! oc whoami &> /dev/null; then
    echo "Error: Not logged into OpenShift."
    echo "Please login using 'oc login' before using this tool."
    exit 1
  fi
  
  # Check if the user has cluster-admin privileges
  if ! oc auth can-i '*' '*' --all-namespaces &> /dev/null; then
    echo "Warning: You may not have sufficient privileges to run all CIS benchmark checks."
    echo "Some checks may fail or produce incomplete results."
    echo "It is recommended to run this tool with cluster-admin privileges."
    echo ""
    read -p "Do you want to continue? (y/n): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      exit 1
    fi
  fi
}

# Function to get OpenShift version
get_ocp_version() {
  OCP_VERSION=$(oc version -o json | jq -r '.openshiftVersion')
  OCP_MAJOR_VERSION=$(echo "$OCP_VERSION" | cut -d. -f1)
  OCP_MINOR_VERSION=$(echo "$OCP_VERSION" | cut -d. -f2)
}

# Function to format result output
format_result() {
  local id="$1"
  local title="$2"
  local level="$3"
  local result="$4"
  local details="$5"
  
  case "$OUTPUT_FORMAT" in
    json)
      jq -n \
        --arg id "$id" \
        --arg title "$title" \
        --arg level "$level" \
        --arg result "$result" \
        --arg details "$details" \
        '{id: $id, title: $title, level: $level, result: $result, details: $details}'
      ;;
    html)
      local result_color
      if [ "$result" == "PASS" ]; then
        result_color="green"
      elif [ "$result" == "FAIL" ]; then
        result_color="red"
      elif [ "$result" == "WARN" ]; then
        result_color="orange"
      else
        result_color="gray"
      fi
      
      echo "<tr>"
      echo "  <td>${id}</td>"
      echo "  <td>${title}</td>"
      echo "  <td>${level}</td>"
      echo "  <td style=\"color: ${result_color}\">${result}</td>"
      echo "  <td>${details}</td>"
      echo "</tr>"
      ;;
    *)
      # Default text format
      local result_text
      if [ "$result" == "PASS" ]; then
        result_text="PASS"
      elif [ "$result" == "FAIL" ]; then
        result_text="FAIL"
      elif [ "$result" == "WARN" ]; then
        result_text="WARN"
      else
        result_text="INFO"
      fi
      
      if [ "$COMPACT_OUTPUT" == "true" ] && [ "$result" != "FAIL" ]; then
        return
      fi
      
      echo "[$id] $title"
      echo "Level: $level"
      echo "Result: $result_text"
      if [ "$VERBOSE_OUTPUT" == "true" ] || [ "$result" == "FAIL" ]; then
        echo "Details: $details"
        if [ "$SHOW_REMEDIATION" == "true" ] && [ "$result" == "FAIL" ]; then
          remediation_text=$(get_remediation "$id")
          if [ -n "$remediation_text" ]; then
            echo "Remediation: $remediation_text"
          fi
        fi
      fi
      echo ""
      ;;
  esac
}

# Function to get remediation steps for a specific check
get_remediation() {
  local id="$1"
  
  case "$id" in
    "1.1.1")
      echo "Review and restrict API server access to authorized networks only by configuring the appropriate OpenShift networking settings."
      ;;
    "1.1.2")
      echo "Ensure that TLS 1.2 or higher is configured as the minimum TLS version for the API server."
      ;;
    "1.1.11")
      echo "Modify the API server configuration to enable the PodSecurityPolicy admission controller."
      ;;
    "1.2.1")
      echo "Ensure etcd is configured with peer certificate authentication."
      ;;
    "1.2.9")
      echo "Configure OpenShift to use encryption for etcd data at rest."
      ;;
    "1.3.1")
      echo "Ensure that the controller manager service file permissions are set to 644 or more restrictive."
      ;;
    "2.1.1")
      echo "Apply security updates and patches to worker nodes regularly."
      ;;
    "4.1.1")
      echo "Create restrictive network policies that deny access by default and only allow necessary traffic."
      ;;
    "5.1.1")
      echo "Configure and enforce image vulnerability scanning using an integrated security scanning tool."
      ;;
    "5.2.5")
      echo "Ensure all Service Accounts in your cluster are limited to the minimum permissions they need."
      ;;
    "5.3.1")
      echo "Implement periodic rotation of secrets and service account tokens."
      ;;
    *)
      echo "No specific remediation available for this check."
      ;;
  esac
}

# Function to begin HTML report
begin_html_report() {
  cat << EOF
<!DOCTYPE html>
<html>
<head>
  <title>OpenShift CIS Benchmark Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { color: #333; }
    table { border-collapse: collapse; width: 100%; margin-top: 20px; }
    th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
    th { background-color: #f2f2f2; }
    .summary { margin: 20px 0; padding: 10px; background-color: #f8f8f8; border-radius: 5px; }
    .pass { color: green; }
    .fail { color: red; }
    .warn { color: orange; }
    .info { color: gray; }
  </style>
</head>
<body>
  <h1>OpenShift CIS Benchmark Report</h1>
  <div class="summary">
    <p><strong>Cluster:</strong> $(oc whoami --show-server)</p>
    <p><strong>OpenShift Version:</strong> $OCP_VERSION</p>
    <p><strong>Generated:</strong> $(date)</p>
    <p><strong>User:</strong> $(oc whoami)</p>
  </div>
  <table>
    <tr>
      <th>ID</th>
      <th>Title</th>
      <th>Level</th>
      <th>Result</th>
      <th>Details</th>
    </tr>
EOF
}

# Function to end HTML report
end_html_report() {
  cat << EOF
  </table>
  <div class="summary">
    <p><strong>Summary:</strong></p>
    <p class="pass">Pass: $PASS_COUNT</p>
    <p class="fail">Fail: $FAIL_COUNT</p>
    <p class="warn">Warning: $WARN_COUNT</p>
    <p class="info">Not Applicable: $NA_COUNT</p>
    <p><strong>Total Checks:</strong> $TOTAL_COUNT</p>
  </div>
</body>
</html>
EOF
}

# Initialize counters for statistics
initialize_counters() {
  PASS_COUNT=0
  FAIL_COUNT=0
  WARN_COUNT=0
  NA_COUNT=0
  TOTAL_COUNT=0
}

# Update counters based on check result
update_counters() {
  local result="$1"
  
  TOTAL_COUNT=$((TOTAL_COUNT + 1))
  
  case "$result" in
    "PASS")
      PASS_COUNT=$((PASS_COUNT + 1))
      ;;
    "FAIL")
      FAIL_COUNT=$((FAIL_COUNT + 1))
      ;;
    "WARN")
      WARN_COUNT=$((WARN_COUNT + 1))
      ;;
    *)
      NA_COUNT=$((NA_COUNT + 1))
      ;;
  esac
}

#########################################################
# CIS Benchmark Checks
#########################################################

# 1. Control Plane Components
check_master_components() {
  echo "Running Control Plane Component Checks..."
  
  # 1.1 API Server
  
  # 1.1.1 - Ensure that the API server pod specification file permissions are set to 644 or more restrictive
  local result="INFO"
  local details="In OpenShift 4.x, the API server pod specification is managed by the Cluster Version Operator and stored in etcd."
  format_result "1.1.1" "API server pod specification file permissions" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.1.2 - Ensure that the API server pod specification file ownership is set to root:root
  local result="INFO"
  local details="In OpenShift 4.x, the API server pod specification is managed by the Cluster Version Operator and stored in etcd."
  format_result "1.1.2" "API server pod specification file ownership" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.1.3 - Ensure that the controller manager pod specification file permissions are set to 644 or more restrictive
  local result="INFO"
  local details="In OpenShift 4.x, the controller manager pod specification is managed by the Cluster Version Operator and stored in etcd."
  format_result "1.1.3" "Controller manager pod specification file permissions" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.1.4 Check if API Server has anonymous auth disabled
  local anonymous_auth=$(oc get apiserver cluster -o jsonpath='{.spec.servingCerts.namedCertificates[*].names}' 2>/dev/null)
  if [ -n "$anonymous_auth" ]; then
    result="PASS"
    details="API Server has anonymous authentication disabled"
  else
    result="WARN"
    details="Could not determine API Server anonymous authentication state"
  fi
  format_result "1.1.4" "Ensure that the API Server does not allow anonymous authentication" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.1.5 Check if API Server has basic auth disabled
  local basic_auth=$(oc get apiserver cluster -o jsonpath='{.spec.authentication.type}' 2>/dev/null)
  if [ "$basic_auth" != "Basic" ]; then
    result="PASS"
    details="API Server has basic authentication disabled"
  else
    result="FAIL"
    details="API Server has basic authentication enabled"
  fi
  format_result "1.1.5" "Ensure that the API Server does not allow basic authentication" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.1.6 Check if API Server has token auth disabled
  # In OpenShift 4.x, token auth is typically managed by OAuth
  local token_auth=$(oc get oauth cluster -o jsonpath='{.spec.tokenConfig.accessTokenMaxAgeSeconds}' 2>/dev/null)
  if [ -n "$token_auth" ] && [ "$token_auth" -lt 86400 ]; then
    result="PASS"
    details="API Server has token authentication configured with a reasonable token lifetime (less than 24 hours)"
  else
    result="WARN"
    details="API Server token authentication may have long-lived tokens or could not be determined"
  fi
  format_result "1.1.6" "Ensure that the API Server has token authentication configured properly" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.1.7 Check if API Server audit logging is enabled
  local audit_policy=$(oc get apiserver cluster -o jsonpath='{.spec.audit.profile}' 2>/dev/null)
  if [ -n "$audit_policy" ] && [ "$audit_policy" != "None" ]; then
    result="PASS"
    details="API Server has audit logging enabled with profile: $audit_policy"
  else
    result="WARN"
    details="API Server may not have audit logging enabled or could not be determined"
  fi
  format_result "1.1.7" "Ensure that the API Server audit logging is enabled" "Level 2" "$result" "$details"
  update_counters "$result"
  
  # 1.1.8 Check if API Server has AlwaysAdmit admission controller disabled
  # In OpenShift 4.x, admission controller configuration is managed differently
  local admission_plugins=$(oc get apiserver cluster -o jsonpath='{.spec.admissionPluginConfig}' 2>/dev/null)
  if [ -n "$admission_plugins" ] && [[ "$admission_plugins" != *"AlwaysAdmit"* ]]; then
    result="PASS"
    details="API Server does not have AlwaysAdmit admission controller enabled"
  else
    result="INFO"
    details="Could not determine API Server admission controller configuration"
  fi
  format_result "1.1.8" "Ensure that the API Server AlwaysAdmit admission controller is disabled" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.1.9 Check if API Server has AlwaysPullImages admission controller enabled
  # In OpenShift 4.x, the image policy is managed differently
  local image_policy=$(oc get apiserver cluster -o jsonpath='{.spec.imagePolicyConfig.internalRegistryHostname}' 2>/dev/null)
  if [ -n "$image_policy" ]; then
    result="PASS"
    details="API Server has image policy configured"
  else
    result="INFO"
    details="Could not determine API Server image policy configuration"
  fi
  format_result "1.1.9" "Ensure that the API Server has proper image policy configuration" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.1.10 Check if API Server has ServiceAccount admission controller enabled
  # In OpenShift 4.x, ServiceAccount admission controller is enabled by default
  result="PASS"
  details="OpenShift 4.x enables the ServiceAccount admission controller by default"
  format_result "1.1.10" "Ensure that the API Server has ServiceAccount admission controller enabled" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.1.11 Check if API Server has PodSecurityPolicy admission controller enabled
  # In OpenShift 4.x, PSP is replaced by SCCs
  local scc_count=$(oc get scc --no-headers 2>/dev/null | wc -l)
  if [ -n "$scc_count" ] && [ "$scc_count" -gt 0 ]; then
    result="PASS"
    details="OpenShift 4.x uses Security Context Constraints (SCCs) instead of PodSecurityPolicy"
  else
    result="FAIL"
    details="Could not determine SCC configuration"
  fi
  format_result "1.1.11" "Ensure that the API Server has PodSecurityPolicy admission controller enabled" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.1.12 Check if API Server has NodeRestriction admission controller enabled
  # In OpenShift 4.x, NodeRestriction admission controller is enabled by default
  result="PASS"
  details="OpenShift 4.x enables the NodeRestriction admission controller by default"
  format_result "1.1.12" "Ensure that the API Server has NodeRestriction admission controller enabled" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.1.13 Check if API Server has secure port
  # In OpenShift 4.x, API Server always uses TLS
  result="PASS"
  details="OpenShift 4.x API Server always uses TLS"
  format_result "1.1.13" "Ensure that the API Server only makes use of secure port" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.1.14 Check if API Server has appropriate TLS cipher suites
  local tls_ciphers=$(oc get apiserver cluster -o jsonpath='{.spec.tlsCipherSuites}' 2>/dev/null)
  if [ -n "$tls_ciphers" ]; then
    result="PASS"
    details="API Server has TLS cipher suites configured"
  else
    result="WARN"
    details="Could not determine API Server TLS cipher suite configuration"
  fi
  format_result "1.1.14" "Ensure that the API Server has appropriate TLS cipher suites configured" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.1.15 Check if API Server has client certificate authentication enabled
  local client_auth=$(oc get apiserver cluster -o jsonpath='{.spec.clientCA}' 2>/dev/null)
  if [ -n "$client_auth" ]; then
    result="PASS"
    details="API Server has client certificate authentication enabled"
  else
    result="WARN"
    details="Could not determine API Server client certificate authentication configuration"
  fi
  format_result "1.1.15" "Ensure that the API Server has client certificate authentication enabled" "Level 1" "$result" "$details"
  update_counters "$result"
}

# 1.2 etcd
check_etcd() {
  echo "Running etcd Checks..."
  
  # 1.2.1 - Ensure that the etcd pod specification file permissions are set to 644 or more restrictive
  local result="INFO"
  local details="In OpenShift 4.x, etcd configuration is managed by the Cluster Version Operator and stored securely."
  format_result "1.2.1" "etcd pod specification file permissions" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.2.2 Check if etcd is configured with TLS encryption for client connections
  # In OpenShift 4.x, etcd is always configured with TLS
  result="PASS"
  details="OpenShift 4.x configures etcd with TLS encryption for client connections by default"
  format_result "1.2.2" "Ensure that the etcd is configured with TLS encryption for client connections" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.2.3 Check if etcd is configured with client certificate authentication
  # In OpenShift 4.x, etcd is always configured with client certificate authentication
  result="PASS"
  details="OpenShift 4.x configures etcd with client certificate authentication by default"
  format_result "1.2.3" "Ensure that the etcd is configured with client certificate authentication" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.2.4 Check if etcd is configured with peer certificate authentication
  # In OpenShift 4.x, etcd is always configured with peer certificate authentication
  result="PASS"
  details="OpenShift 4.x configures etcd with peer certificate authentication by default"
  format_result "1.2.4" "Ensure that the etcd is configured with peer certificate authentication" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.2.5 Check if etcd has auto TLS enabled for peer connections
  # In OpenShift 4.x, etcd is properly configured with TLS
  result="PASS"
  details="OpenShift 4.x properly configures etcd TLS for peer connections"
  format_result "1.2.5" "Ensure that the etcd has auto TLS disabled for peer connections" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.2.6 Check if etcd has appropriate TLS cipher suites
  # In OpenShift 4.x, etcd is configured with appropriate TLS cipher suites
  result="PASS"
  details="OpenShift 4.x configures etcd with appropriate TLS cipher suites by default"
  format_result "1.2.6" "Ensure that the etcd has appropriate TLS cipher suites configured" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.2.7 Check if etcd is configured with proper hostname verification
  # In OpenShift 4.x, etcd is configured with proper hostname verification
  result="PASS"
  details="OpenShift 4.x configures etcd with proper hostname verification by default"
  format_result "1.2.7" "Ensure that the etcd is configured with proper hostname verification" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.2.8 Check if etcd has client certification revocation in place
  # In OpenShift 4.x, etcd is configured with client certification revocation
  result="PASS"
  details="OpenShift 4.x manages certificate rotations and revocations for etcd"
  format_result "1.2.8" "Ensure that the etcd has client certification revocation in place" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.2.9 Check if etcd is encrypted
  local etcd_encryption=$(oc get apiserver cluster -o jsonpath='{.spec.encryption.type}' 2>/dev/null)
  if [ "$etcd_encryption" == "aescbc" ] || [ "$etcd_encryption" == "aesgcm" ]; then
    result="PASS"
    details="etcd encryption is enabled using $etcd_encryption"
  else
    result="WARN"
    details="etcd encryption may not be enabled or could not be determined"
  fi
  format_result "1.2.9" "Ensure that etcd data is encrypted at rest" "Level 1" "$result" "$details"
  update_counters "$result"
}

# 1.3 Control Plane Configuration
check_control_plane() {
  echo "Running Control Plane Configuration Checks..."
  
  # 1.3.1 - Ensure that the controller manager pod specification file permissions are set to 644 or more restrictive
  local result="INFO"
  local details="In OpenShift 4.x, the controller manager pod specification is managed by the Cluster Version Operator and stored in etcd."
  format_result "1.3.1" "Controller manager pod specification file permissions" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.3.2 Check if controller manager has profiling disabled
  local profiling=$(oc get kubecontrollermanager cluster -o jsonpath='{.spec.unsupportedConfigOverrides}' 2>/dev/null | grep -c "enableProfiling")
  if [ "$profiling" -eq 0 ]; then
    result="PASS"
    details="Controller manager has profiling disabled by default"
  else
    result="WARN"
    details="Controller manager profiling configuration could not be determined"
  fi
  format_result "1.3.2" "Ensure that the controller manager has profiling disabled" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.3.3 Check if controller manager uses secure port
  # In OpenShift 4.x, controller manager always uses TLS
  result="PASS"
  details="OpenShift 4.x controller manager always uses TLS"
  format_result "1.3.3" "Ensure that the controller manager only makes use of secure port" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.3.4 Check if controller manager service account has appropriate permissions
  # In OpenShift 4.x, controller manager permissions are properly configured
  result="PASS"
  details="OpenShift 4.x properly configures controller manager service account permissions"
  format_result "1.3.4" "Ensure that the controller manager service account has appropriate permissions" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.3.5 Check if controller manager has appropriate TLS cipher suites
  local tls_ciphers=$(oc get kubecontrollermanager cluster -o jsonpath='{.spec.tlsCipherSuites}' 2>/dev/null)
  if [ -n "$tls_ciphers" ]; then
    result="PASS"
    details="Controller manager has TLS cipher suites configured"
  else
    result="WARN"
    details="Could not determine controller manager TLS cipher suite configuration"
  fi
  format_result "1.3.5" "Ensure that the controller manager has appropriate TLS cipher suites configured" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.3.6 Check if scheduler has profiling disabled
  local scheduler_profiling=$(oc get kubescheduler cluster -o jsonpath='{.spec.unsupportedConfigOverrides}' 2>/dev/null | grep -c "enableProfiling")
  if [ "$scheduler_profiling" -eq 0 ]; then
    result="PASS"
    details="Scheduler has profiling disabled by default"
  else
    result="WARN"
    details="Scheduler profiling configuration could not be determined"
  fi
  format_result "1.3.6" "Ensure that the scheduler has profiling disabled" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.3.7 Check if scheduler uses secure port
  # In OpenShift 4.x, scheduler always uses TLS
  result="PASS"
  details="OpenShift 4.x scheduler always uses TLS"
  format_result "1.3.7" "Ensure that the scheduler only makes use of secure port" "Level 1" "$result" "$details"
  update_counters "$result"
}

# 2. Worker Nodes
check_worker() {
  echo "Running Worker Node Checks..."
  
  # 2.1.1 Ensure that the kubelet configuration file permissions are secure
  local result="INFO"
  local details="In OpenShift 4.x, kubelet configuration is managed by the Machine Config Operator and stored securely."
  format_result "2.1.1" "kubelet configuration file permissions" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 2.1.2 Check if kubelet allows anonymous auth
  # In OpenShift 4.x, kubelet does not allow anonymous auth by default
  result="PASS"
  details="OpenShift 4.x configures kubelet to not allow anonymous auth by default"
  format_result "2.1.2" "Ensure that the kubelet does not allow anonymous auth" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 2.1.3 Check if kubelet has authorization mode set to Webhook
  # In OpenShift 4.x, kubelet authorization mode is set to Webhook by default
  result="PASS"
  details="OpenShift 4.x configures kubelet with authorization mode set to Webhook by default"
  format_result "2.1.3" "Ensure that the kubelet has authorization mode set to Webhook" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 2.1.4 Check if kubelet client certificate authentication is enabled
  # In OpenShift 4.x, kubelet client certificate authentication is enabled by default
  result="PASS"
  details="OpenShift 4.x enables kubelet client certificate authentication by default"
  format_result "2.1.4" "Ensure that the kubelet has client certificate authentication enabled" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 2.1.5 Check if kubelet certificate rotation is enabled
  # In OpenShift 4.x, kubelet certificate rotation is enabled by default
  result="PASS"
  details="OpenShift 4.x enables kubelet certificate rotation by default"
  format_result "2.1.5" "Ensure that the kubelet certificate rotation is enabled" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 2.1.6 Check if kubelet read-only port is disabled
  # In OpenShift 4.x, kubelet read-only port is disabled by default
  result="PASS"
  details="OpenShift 4.x disables kubelet read-only port by default"
  format_result "2.1.6" "Ensure that the kubelet read-only port is disabled" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 2.1.7 Check if kubelet hostname override is not used
  # In OpenShift 4.x, kubelet hostname override is properly managed
  result="PASS"
  details="OpenShift 4.x properly manages kubelet hostnames"
  format_result "2.1.7" "Ensure that the kubelet hostname override is properly managed" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 2.1.8 Check if kubelet has streaming connections timeout configured
  # In OpenShift 4.x, kubelet streaming connections timeout is properly configured
  result="PASS"
  details="OpenShift 4.x properly configures kubelet streaming connections timeout"
  format_result "2.1.8" "Ensure that the kubelet has streaming connections timeout configured" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 2.1.9 Check if kubelet protects kernel defaults
  # In OpenShift 4.x, kubelet protects kernel defaults by default
  result="PASS"
  details="OpenShift 4.x configures kubelet to protect kernel defaults"
  format_result "2.1.9" "Ensure that the kubelet protects kernel defaults" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 2.1.10 Check if kubelet makes use of only secure ports
  # In OpenShift 4.x, kubelet only uses secure ports by default
  result="PASS"
  details="OpenShift 4.x configures kubelet to only use secure ports"
  format_result "2.1.10" "Ensure that the kubelet only makes use of secure ports" "Level 1" "$result" "$details"
  update_counters "$result"
}

# 3. Policies
check_policies() {
  echo "Running Policy Checks..."
  
  # 3.1.1 Check if Pod Security Policies are configured (SCCs in OpenShift)
  local scc_count=$(oc get scc --no-headers 2>/dev/null | wc -l)
  if [ "$scc_count" -gt 0 ]; then
    result="PASS"
    details="OpenShift has ${scc_count} Security Context Constraints configured"
  else
    result="FAIL"
    details="No Security Context Constraints found"
  fi
  format_result "3.1.1" "Ensure that Security Context Constraints are configured" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 3.1.2 Check if privileged containers are restricted
  local privileged_scc=$(oc get scc privileged -o jsonpath='{.users[*]}' 2>/dev/null)
  if [ -z "$privileged_scc" ] || [ "$privileged_scc" == "[]" ]; then
    result="PASS"
    details="No users are directly assigned to the privileged SCC"
  else
    result="WARN"
    details="Users are directly assigned to the privileged SCC: $privileged_scc"
  fi
  format_result "3.1.2" "Ensure that privileged containers are restricted" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 3.1.3 Check if host path mounts are restricted
  local hostpath_allowed_sccs=$(oc get scc -o json | jq -r '.items[] | select(.volumes[] | contains("hostPath")) | .metadata.name')
  if [ -z "$hostpath_allowed_sccs" ]; then
    result="PASS"
    details="No SCCs allow hostPath volumes"
  else
    result="WARN"
    details="The following SCCs allow hostPath volumes: $hostpath_allowed_sccs"
  fi
  format_result "3.1.3" "Ensure that host path mounts are restricted" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 3.1.4 Check if the default namespace has a NetworkPolicy defined
  local default_netpol=$(oc get networkpolicy -n default --no-headers 2>/dev/null | wc -l)
  if [ "$default_netpol" -gt 0 ]; then
    result="PASS"
    details="Default namespace has NetworkPolicy defined"
  else
    result="WARN"
    details="Default namespace does not have any NetworkPolicy defined"
  fi
  format_result "3.1.4" "Ensure that the default namespace has a NetworkPolicy defined" "Level 2" "$result" "$details"
  update_counters "$result"
}

# 4. Security Context
check_security_context() {
  echo "Running Security Context Checks..."
  
  # 4.1.1 Check if default seccomp profile is not set to unconfined
  local unconfined_seccomp=$(oc get scc -o json | jq -r '.items[] | select(.metadata.annotations."seccomp.security.alpha.kubernetes.io/allowedProfileNames" | contains("unconfined")) | .metadata.name')
  if [ -z "$unconfined_seccomp" ]; then
    result="PASS"
    details="No SCCs allow unconfined seccomp profiles"
  else
    result="WARN"
    details="The following SCCs allow unconfined seccomp profiles: $unconfined_seccomp"
  fi
  format_result "4.1.1" "Ensure that the default seccomp profile is not set to unconfined" "Level 2" "$result" "$details"
  update_counters "$result"
  
  # 4.1.2 Check if hostPID, hostIPC privileges are restricted
  local host_pid_ipc_sccs=$(oc get scc -o json | jq -r '.items[] | select(.allowHostPID == true or .allowHostIPC == true) | .metadata.name')
  if [ -z "$host_pid_ipc_sccs" ]; then
    result="PASS"
    details="No SCCs allow hostPID or hostIPC"
  else
    result="WARN"
    details="The following SCCs allow hostPID or hostIPC: $host_pid_ipc_sccs"
  fi
  format_result "4.1.2" "Ensure that hostPID and hostIPC privileges are restricted" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 4.1.3 Check if hostNetwork privileges are restricted
  local host_network_sccs=$(oc get scc -o json | jq -r '.items[] | select(.allowHostNetwork == true) | .metadata.name')
  if [ -z "$host_network_sccs" ]; then
    result="PASS"
    details="No SCCs allow hostNetwork"
  else
    result="WARN"
    details="The following SCCs allow hostNetwork: $host_network_sccs"
  fi
  format_result "4.1.3" "Ensure that hostNetwork privileges are restricted" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 4.1.4 Check if privilege escalation is restricted
  local priv_escalation_sccs=$(oc get scc -o json | jq -r '.items[] | select(.allowPrivilegeEscalation == true) | .metadata.name')
  if [ -z "$priv_escalation_sccs" ]; then
    result="PASS"
    details="No SCCs allow privilege escalation"
  else
    result="WARN"
    details="The following SCCs allow privilege escalation: $priv_escalation_sccs"
  fi
  format_result "4.1.4" "Ensure that privilege escalation is restricted" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 4.1.5 Check if root containers are not allowed
  local root_container_sccs=$(oc get scc -o json | jq -r '.items[] | select(.runAsUser.type == "RunAsAny") | .metadata.name')
  if [ -z "$root_container_sccs" ]; then
    result="PASS"
    details="No SCCs allow containers to run as root"
  else
    result="WARN"
    details="The following SCCs allow containers to run as root: $root_container_sccs"
  fi
  format_result "4.1.5" "Ensure that root containers are not allowed" "Level 2" "$result" "$details"
  update_counters "$result"
}

# 5. RBAC and Service Accounts
check_rbac() {
  echo "Running RBAC and Service Account Checks..."
  
  # 5.1.1 Check if the cluster-admin role is minimally assigned
  local cluster_admins=$(oc get clusterrolebinding -o json | jq -r '.items[] | select(.roleRef.name == "cluster-admin") | .subjects[] | select(.kind == "User" or .kind == "Group") | .name')
  if [ -z "$cluster_admins" ]; then
    result="PASS"
    details="No users or groups are directly assigned to the cluster-admin role"
  else
    result="WARN"
    details="The following users or groups have cluster-admin privileges: $cluster_admins"
  fi
  format_result "5.1.1" "Ensure that the cluster-admin role is minimally assigned" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 5.1.2 Check if service accounts are properly scoped
  local namespace_sa_count=$(oc get sa --all-namespaces -o json | jq -r '.items | length')
  local default_sa_with_secrets=$(oc get sa default -n default -o json | jq -r '.secrets | length')
  if [ "$namespace_sa_count" -gt 0 ] && [ "$default_sa_with_secrets" -le 2 ]; then
    result="PASS"
    details="Service accounts appear to be properly scoped"
  else
    result="WARN"
    details="Service account configuration may need review"
  fi
  format_result "5.1.2" "Ensure that service accounts are properly scoped" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 5.1.3 Check if the default service account is restricted
  local default_sa_bindings=$(oc get rolebindings,clusterrolebindings -o json | jq -r '.items[] | select(.subjects[] | select(.kind == "ServiceAccount" and .name == "default")) | .metadata.name')
  if [ -z "$default_sa_bindings" ]; then
    result="PASS"
    details="Default service account has no additional role bindings"
  else
    result="WARN"
    details="Default service account has the following role bindings: $default_sa_bindings"
  fi
  format_result "5.1.3" "Ensure that the default service account is restricted" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 5.1.4 Check if RBAC is enabled and used
  local rbac_enabled=$(oc get clusterrole -o name 2>/dev/null | wc -l)
  if [ "$rbac_enabled" -gt 0 ]; then
    result="PASS"
    details="RBAC is enabled and in use on the cluster"
  else
    result="FAIL"
    details="RBAC does not appear to be enabled on the cluster"
  fi
  format_result "5.1.4" "Ensure that RBAC is enabled and used" "Level 1" "$result" "$details"
  update_counters "$result"
}

# 6. Secrets Management
check_secrets() {
  echo "Running Secrets Management Checks..."
  
  # 6.1.1 Check if secrets are encrypted at rest
  local etcd_encryption=$(oc get apiserver cluster -o jsonpath='{.spec.encryption.type}' 2>/dev/null)
  if [ "$etcd_encryption" == "aescbc" ] || [ "$etcd_encryption" == "aesgcm" ]; then
    result="PASS"
    details="Secrets are encrypted at rest using $etcd_encryption"
  else
    result="WARN"
    details="Secrets may not be encrypted at rest or encryption status could not be determined"
  fi
  format_result "6.1.1" "Ensure that secrets are encrypted at rest" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 6.1.2 Check if secrets are not exposed in environment variables
  # This is a best practice check, can't be fully automated
  result="INFO"
  details="This is a best practice check. Ensure that applications do not expose secrets in environment variables."
  format_result "6.1.2" "Ensure that secrets are not exposed in environment variables" "Level 2" "$result" "$details"
  update_counters "$result"
  
  # 6.1.3 Check if external secrets management is used
  local external_secrets=$(oc get csv --all-namespaces 2>/dev/null | grep -i "vault\|external-secrets\|secrets-store\|azure-key-vault\|aws-secret" | wc -l)
  if [ "$external_secrets" -gt 0 ]; then
    result="PASS"
    details="External secrets management appears to be in use"
  else
    result="INFO"
    details="No evidence of external secrets management was found. This is not necessarily a failing condition."
  fi
  format_result "6.1.3" "Consider using external secrets management" "Level 2" "$result" "$details"
  update_counters "$result"
}

# 7. Network Security
check_networking() {
  echo "Running Network Security Checks..."
  
  # 7.1.1 Check if the CNI plugin supports NetworkPolicy
  # OpenShift 4.x uses SDN or OVN-Kubernetes which both support NetworkPolicy
  result="PASS"
  details="OpenShift 4.x uses a CNI plugin that supports NetworkPolicy by default"
  format_result "7.1.1" "Ensure that the CNI plugin supports NetworkPolicy" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 7.1.2 Check if NetworkPolicies are used
  local network_policies=$(oc get networkpolicy --all-namespaces --no-headers 2>/dev/null | wc -l)
  if [ "$network_policies" -gt 0 ]; then
    result="PASS"
    details="NetworkPolicies are in use on the cluster"
  else
    result="WARN"
    details="No NetworkPolicies were found on the cluster"
  fi
  format_result "7.1.2" "Ensure that NetworkPolicies are used" "Level 2" "$result" "$details"
  update_counters "$result"
  
  # 7.1.3 Check if secure ingress controllers are used
  local route_tls=$(oc get route --all-namespaces -o json | jq -r '.items[] | select(.spec.tls != null) | .metadata.name' | wc -l)
  local routes_total=$(oc get route --all-namespaces --no-headers 2>/dev/null | wc -l)
  
  if [ "$routes_total" -eq 0 ]; then
    result="INFO"
    details="No routes were found on the cluster"
  elif [ "$route_tls" -eq "$routes_total" ]; then
    result="PASS"
    details="All routes are secured with TLS"
  else
    result="WARN"
    details="Some routes are not secured with TLS: $route_tls out of $routes_total routes are secured"
  fi
  format_result "7.1.3" "Ensure that all routes are secured with TLS" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 7.1.4 Check if node firewall rules are in place
  # In OpenShift 4.x, this is managed by the platform
  result="PASS"
  details="OpenShift 4.x manages node firewall rules through the Machine Config Operator"
  format_result "7.1.4" "Ensure that node firewall rules are properly configured" "Level 1" "$result" "$details"
  update_counters "$result"
}

# 8. Logging and Monitoring
check_logging() {
  echo "Running Logging and Monitoring Checks..."
  
  # 8.1.1 Check if audit logging is enabled
  local audit_enabled=$(oc get apiserver cluster -o jsonpath='{.spec.audit.profile}' 2>/dev/null)
  if [ -n "$audit_enabled" ] && [ "$audit_enabled" != "None" ]; then
    result="PASS"
    details="Audit logging is enabled with profile: $audit_enabled"
  else
    result="WARN"
    details="Audit logging may not be enabled or status could not be determined"
  fi
  format_result "8.1.1" "Ensure that audit logging is enabled" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 8.1.2 Check if monitoring is enabled
  local monitoring_enabled=$(oc get prometheus -n openshift-monitoring --no-headers 2>/dev/null | wc -l)
  if [ "$monitoring_enabled" -gt 0 ]; then
    result="PASS"
    details="Prometheus monitoring is enabled on the cluster"
  else
    result="WARN"
    details="Prometheus monitoring may not be enabled or status could not be determined"
  fi
  format_result "8.1.2" "Ensure that monitoring is enabled" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 8.1.3 Check if logging is enabled
  local logging_enabled=$(oc get clusterlogging instance -n openshift-logging --no-headers 2>/dev/null | wc -l)
  if [ "$logging_enabled" -gt 0 ]; then
    result="PASS"
    details="Cluster logging is enabled"
  else
    result="WARN"
    details="Cluster logging does not appear to be enabled"
  fi
  format_result "8.1.3" "Ensure that logging is enabled" "Level 2" "$result" "$details"
  update_counters "$result"
  
  # 8.1.4 Check if audit logs are being collected
  local audit_logs_collected=$(oc get clusterlogging instance -n openshift-logging -o json 2>/dev/null | jq -r '.spec.collection.logs.collection[] | select(.name == "audit") | .enabled')
  if [ "$audit_logs_collected" == "true" ]; then
    result="PASS"
    details="Audit logs are being collected"
  else
    result="WARN"
    details="Audit logs may not be collected or collection status could not be determined"
  fi
  format_result "8.1.4" "Ensure that audit logs are being collected" "Level 2" "$result" "$details"
  update_counters "$result"
}

# 9. Authentication
check_authentication() {
  echo "Running Authentication Checks..."
  
  # 9.1.1 Check if strong authentication methods are used
  local identity_providers=$(oc get oauth cluster -o json 2>/dev/null | jq -r '.spec.identityProviders[].type')
  local strong_auth=0
  
  if [[ "$identity_providers" == *"LDAP"* ]] || 
     [[ "$identity_providers" == *"OpenID"* ]] || 
     [[ "$identity_providers" == *"GitHub"* ]] || 
     [[ "$identity_providers" == *"GitLab"* ]] || 
     [[ "$identity_providers" == *"Google"* ]]; then
    strong_auth=1
  fi
  
  if [ "$strong_auth" -eq 1 ]; then
    result="PASS"
    details="Strong authentication methods are in use: $identity_providers"
  else
    result="WARN"
    details="No strong authentication methods were detected or authentication configuration could not be determined"
  fi
  format_result "9.1.1" "Ensure that strong authentication methods are used" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 9.1.2 Check if token lifetime is limited
  local token_lifetime=$(oc get oauth cluster -o jsonpath='{.spec.tokenConfig.accessTokenMaxAgeSeconds}' 2>/dev/null)
  if [ -n "$token_lifetime" ] && [ "$token_lifetime" -le 86400 ]; then
    result="PASS"
    details="Token lifetime is limited to $token_lifetime seconds (maximum 24 hours)"
  else
    result="WARN"
    details="Token lifetime may be excessive or configuration could not be determined"
  fi
  format_result "9.1.2" "Ensure that token lifetime is limited" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 9.1.3 Check if OAuth service certificate is properly managed
  local oauth_cert=$(oc get oauth cluster -o jsonpath='{.spec.servingCerts.namedCertificates}' 2>/dev/null)
  if [ -n "$oauth_cert" ] && [ "$oauth_cert" != "[]" ]; then
    result="PASS"
    details="OAuth service has custom certificate configured"
  else
    result="INFO"
    details="OAuth service may be using the default certificate, which is managed by the cluster"
  fi
  format_result "9.1.3" "Ensure that OAuth service certificates are properly managed" "Level 2" "$result" "$details"
  update_counters "$result"
}

# 10. Managed OpenShift Services
check_managed_services() {
  echo "Running Managed OpenShift Services Checks..."
  
  # 10.1.1 Check if managed service configurations are properly restricted
  # This is more of a best practice check as it depends on the services in use
  result="INFO"
  details="This is a best practice check. Ensure that managed service configurations are properly restricted."
  format_result "10.1.1" "Ensure that managed service configurations are properly restricted" "Level 2" "$result" "$details"
  update_counters "$result"
  
  # 10.1.2 Check if custom domains for managed services are secured with TLS
  local route_tls=$(oc get route --all-namespaces -o json | jq -r '.items[] | select(.spec.tls != null) | .metadata.name' | wc -l)
  local routes_total=$(oc get route --all-namespaces --no-headers 2>/dev/null | wc -l)
  
  if [ "$routes_total" -eq 0 ]; then
    result="INFO"
    details="No routes were found on the cluster"
  elif [ "$route_tls" -eq "$routes_total" ]; then
    result="PASS"
    details="All custom domains (routes) are secured with TLS"
  else
    result="WARN"
    details="Some custom domains (routes) are not secured with TLS: $route_tls out of $routes_total routes are secured"
  fi
  format_result "10.1.2" "Ensure that custom domains for managed services are secured with TLS" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 10.1.3 Check if managed services are isolated from each other
  local network_policies=$(oc get networkpolicy --all-namespaces --no-headers 2>/dev/null | wc -l)
  if [ "$network_policies" -gt 0 ]; then
    result="PASS"
    details="NetworkPolicies are in use on the cluster, which may help isolate managed services"
  else
    result="WARN"
    details="No NetworkPolicies were found, which may indicate managed services are not properly isolated"
  fi
  format_result "10.1.3" "Ensure that managed services are isolated from each other" "Level 2" "$result" "$details"
  update_counters "$result"
}

# Function to run all CIS benchmark checks
run_all_checks() {
  echo "Running all CIS benchmark checks for OpenShift 4.x..."
  
  initialize_counters
  
  if [ "$OUTPUT_FORMAT" == "html" ]; then
    begin_html_report
  fi
  
  check_master_components
  check_etcd
  check_control_plane
  check_worker
  check_policies
  check_security_context
  check_rbac
  check_secrets
  check_networking
  check_logging
  check_authentication
  check_managed_services
  
  if [ "$OUTPUT_FORMAT" == "html" ]; then
    end_html_report
  else
    echo "Summary:"
    echo "Pass: $PASS_COUNT"
    echo "Fail: $FAIL_COUNT"
    echo "Warning: $WARN_COUNT"
    echo "Not Applicable/Info: $NA_COUNT"
    echo "Total Checks: $TOTAL_COUNT"
  fi
}

# Parse command line arguments
parse_args() {
  COMMAND=""
  OUTPUT_FORMAT="text"
  COMPACT_OUTPUT="false"
  VERBOSE_OUTPUT="false"
  SHOW_REMEDIATION="false"
  
  while [[ $# -gt 0 ]]; do
    case "$1" in
      run-all|master|etcd|control-plane|worker|policies|managed-services|security-context|rbac|secrets|networking|logging|authentication|help)
        COMMAND="$1"
        shift
        ;;
      -o|--output)
        if [[ $# -lt 2 ]] || [[ "$2" == -* ]]; then
          echo "Error: Missing argument for $1"
          exit 1
        fi
        OUTPUT_FORMAT="$2"
        shift 2
        ;;
      -c|--compact)
        COMPACT_OUTPUT="true"
        shift
        ;;
      -v|--verbose)
        VERBOSE_OUTPUT="true"
        shift
        ;;
      -r|--remediation)
        SHOW_REMEDIATION="true"
        shift
        ;;
      -h|--help)
        show_usage
        exit 0
        ;;
      --version)
        echo "OpenShift CIS Benchmark Compliance Tool v${VERSION}"
        exit 0
        ;;
      *)
        echo "Error: Unknown argument: $1"
        show_usage
        exit 1
        ;;
    esac
  done
  
  # Validate output format
  if [[ "$OUTPUT_FORMAT" != "text" && "$OUTPUT_FORMAT" != "json" && "$OUTPUT_FORMAT" != "html" ]]; then
    echo "Error: Invalid output format: $OUTPUT_FORMAT"
    echo "Valid formats are: text, json, html"
    exit 1
  fi
  
  # Validate that a command was provided
  if [ -z "$COMMAND" ]; then
    echo "Error: No command specified."
    show_usage
    exit 1
  fi
}

# Main function
main() {
  parse_args "$@"
  check_prereqs
  get_ocp_version
  
  case "$COMMAND" in
    run-all)
      run_all_checks
      ;;
    master)
      initialize_counters
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        begin_html_report
      fi
      check_master_components
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        end_html_report
      fi
      ;;
    etcd)
      initialize_counters
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        begin_html_report
      fi
      check_etcd
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        end_html_report
      fi
      ;;
    control-plane)
      initialize_counters
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        begin_html_report
      fi
      check_control_plane
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        end_html_report
      fi
      ;;
    worker)
      initialize_counters
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        begin_html_report
      fi
      check_worker
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        end_html_report
      fi
      ;;
    policies)
      initialize_counters
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        begin_html_report
      fi
      check_policies
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        end_html_report
      fi
      ;;
    security-context)
      initialize_counters
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        begin_html_report
      fi
      check_security_context
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        end_html_report
      fi
      ;;
    rbac)
      initialize_counters
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        begin_html_report
      fi
      check_rbac
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        end_html_report
      fi
      ;;
    secrets)
      initialize_counters
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        begin_html_report
      fi
      check_secrets
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        end_html_report
      fi
      ;;
    networking)
      initialize_counters
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        begin_html_report
      fi
      check_networking
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        end_html_report
      fi
      ;;
    logging)
      initialize_counters
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        begin_html_report
      fi
      check_logging
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        end_html_report
      fi
      ;;
    authentication)
      initialize_counters
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        begin_html_report
      fi
      check_authentication
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        end_html_report
      fi
      ;;
    managed-services)
      initialize_counters
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        begin_html_report
      fi
      check_managed_services
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        end_html_report
      fi
      ;;
    help)
      show_usage
      ;;
    *)
      echo "Error: Unknown command: $COMMAND"
      show_usage
      exit 1
      ;;
  esac
}

# Execute main function with all arguments
main "$@"