#!/bin/bash

# ocp-scc-audit.sh - OpenShift SCC Auditing Tool
# A tool for security engineers to audit Security Context Constraints in OpenShift clusters

set -e

VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")

# Define color variables for error messages
RED="\033[0;31m"
NC="\033[0m" # No Color

# Function to display usage information
show_usage() {
  cat << EOF
OpenShift SCC Audit Tool v${VERSION}
A tool for security engineers to audit Security Context Constraints in OpenShift clusters

Usage:
  ${SCRIPT_NAME} [command] [options]

Commands:
  list-sccs                      List all SCCs in the cluster
  check-scc [scc_name]           Show details for a specific SCC
  find-subjects [scc_name]       Find all users, service accounts, and groups using a specific SCC
  high-risk                      List all subjects with high-risk SCCs (privileged, anyuid, hostnetwork, etc.)
  unused                         Find SCCs not assigned to any subjects
  compare [scc1] [scc2]          Compare two SCCs and show differences
  report                         Generate a comprehensive SCC audit report
  sensitive-caps                 Find subjects with SCCs allowing sensitive Linux capabilities
  sensitive-volumes              Find subjects with SCCs allowing sensitive volume types
  sensitive-seccomp              Find subjects with unconfined seccomp profiles
  sensitive-selinux              Find subjects with SCCs having permissive SELinux contexts
  container-security-report      Generate a comprehensive container security posture report
  help                           Show this help message

Options:
  -o, --output [format]          Output format: table (default), json, yaml, html
  -n, --namespace [namespace]    Filter by namespace
  -c, --capability [capability]  Filter by specific Linux capability (for sensitive-caps)
  -h, --help                     Show this help message
  -v, --version                  Show version information

Examples:
  ${SCRIPT_NAME} list-sccs
  ${SCRIPT_NAME} check-scc privileged
  ${SCRIPT_NAME} find-subjects anyuid --namespace app-prod
  ${SCRIPT_NAME} high-risk --output json
  ${SCRIPT_NAME} sensitive-caps --capability SYS_ADMIN
  ${SCRIPT_NAME} container-security-report
  ${SCRIPT_NAME} report

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
}

# Function to format output according to desired format
format_output() {
  local data="$1"
  local format="${OUTPUT_FORMAT:-table}"
  
  case "$format" in
    json)
      echo "$data" | jq -r '.'
      ;;
    yaml)
      echo "$data" | yq -P
      ;;
    html)
      # Basic HTML format with a table
      echo "<html><head><title>OpenShift SCC Audit</title>"
      echo "<style>body{font-family:Arial,sans-serif;margin:20px;}"
      echo "table{border-collapse:collapse;width:100%;margin-top:20px;}"
      echo "th{background-color:#f2f2f2;text-align:left;padding:12px;border:1px solid #ddd;}"
      echo "td{padding:12px;border:1px solid #ddd;}"
      echo "tr:nth-child(even){background-color:#f9f9f9;}"
      echo "tr:hover{background-color:#f2f2f2;}"
      echo "h1,h2{color:#333;}</style></head>"
      echo "<body><h1>OpenShift SCC Audit</h1>"
      echo "<table><tr>"
      
      # Extract headers (assuming tab-delimited)
      echo "$data" | head -n 1 | tr '\t' '\n' | while read -r header; do
        echo "<th>$header</th>"
      done
      echo "</tr>"
      
      # Extract data rows
      echo "$data" | tail -n +2 | while read -r line; do
        echo "<tr>"
        echo "$line" | tr '\t' '\n' | while read -r cell; do
          echo "<td>$cell</td>"
        done
        echo "</tr>"
      done
      
      echo "</table></body></html>"
      ;;
    table|*)
      # Default to table format (using column if available)
      if command -v column &> /dev/null; then
        echo "$data" | column -t -s $'\t'
      else
        echo "$data"
      fi
      ;;
  esac
}

# Function to list all SCCs
list_sccs() {
  echo "Listing all Security Context Constraints in the cluster..."
  
  if [ "$OUTPUT_FORMAT" == "json" ]; then
    oc get scc -o json
  elif [ "$OUTPUT_FORMAT" == "yaml" ]; then
    oc get scc -o yaml
  else
    # Create table data
    local table_data="NAME\tPRIORITY\tUSERS\tGROUPS\tALLOW PRIVILEGED\tALLOW PRIVILEGED ESCALATION\tALLOW HOST NETWORK\tALLOW HOST PORTS"
    local scc_data=$(oc get scc -o custom-columns=NAME:.metadata.name,PRIORITY:.priority,USERS:.users,GROUPS:.groups,ALLOW_PRIVILEGED:.allowPrivilegedContainer,ALLOW_PRIV_ESCALATION:.allowPrivilegeEscalation,ALLOW_HOST_NETWORK:.allowHostNetwork,ALLOW_HOST_PORTS:.allowHostPorts | tail -n +2)
    
    # Combine header and data
    local full_table="${table_data}"$'\n'"${scc_data}"
    
    # Format using the format_output function
    format_output "$full_table"
  fi
}

# Function to check details of a specific SCC
check_scc() {
  local scc_name="$1"
  
  if [ -z "$scc_name" ]; then
    echo "Error: SCC name is required."
    echo "Usage: ${SCRIPT_NAME} check-scc [scc_name]"
    exit 1
  fi
  
  echo "Checking details for SCC: ${scc_name}"
  
  if ! oc get scc "$scc_name" &> /dev/null; then
    echo "Error: SCC '${scc_name}' not found."
    exit 1
  fi
  
  oc get scc "$scc_name" -o "${OUTPUT_FORMAT:-yaml}"
}

# Function to find all subjects using a specific SCC
find_subjects() {
  local scc_name="$1"
  
  if [ -z "$scc_name" ]; then
    echo "Error: SCC name is required."
    echo "Usage: ${SCRIPT_NAME} find-subjects [scc_name]"
    exit 1
  fi
  
  echo "Finding all subjects using SCC: ${scc_name}"
  
  if ! oc get scc "$scc_name" &> /dev/null; then
    echo "Error: SCC '${scc_name}' not found."
    exit 1
  fi
  
  # Get direct assignments from the SCC
  local users=$(oc get scc "$scc_name" -o jsonpath='{.users}')
  local groups=$(oc get scc "$scc_name" -o jsonpath='{.groups}')
  
  # Format and display the results
  echo "Directly assigned Users:"
  if [ "$users" == "[]" ] || [ -z "$users" ]; then
    echo "  None"
  else
    echo "$users" | tr -d '[]"' | tr ',' '\n' | sed 's/^ */  /'
  fi
  
  echo "Directly assigned Groups:"
  if [ "$groups" == "[]" ] || [ -z "$groups" ]; then
    echo "  None"
  else
    echo "$groups" | tr -d '[]"' | tr ',' '\n' | sed 's/^ */  /'
  fi
  
  # Check if namespace is specified to filter service accounts
  if [ -n "$NAMESPACE" ]; then
    echo "Service Accounts in namespace ${NAMESPACE} using this SCC:"
    local sa_list=""
    
    # Get service accounts in specified namespace
    for sa in $(oc get sa -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}'); do
      local sa_full="system:serviceaccount:${NAMESPACE}:${sa}"
      
      # Check if service account is directly assigned
      if echo "$users" | grep -q "$sa_full"; then
        sa_list="${sa_list}  ${sa} (direct assignment)\n"
      fi
      
      # Check if service account belongs to a group that's assigned
      for group in $(echo "$groups" | tr -d '[]"' | tr ',' ' '); do
        if oc get rolebindings,clusterrolebindings -o json | jq -r '.items[] | select(.subjects[] | select(.kind=="ServiceAccount" and .name=="'"$sa"'" and .namespace=="'"$NAMESPACE"'")) | .roleRef.name' | grep -q "$group"; then
          sa_list="${sa_list}  ${sa} (via group ${group})\n"
          break
        fi
      done
    done
    
    if [ -z "$sa_list" ]; then
      echo "  None"
    else
      echo -e "$sa_list" | sort | uniq
    fi
  else
    echo "Specify --namespace to see service accounts using this SCC"
  fi
}

# Function to find subjects with high-risk SCCs
high_risk() {
  echo "Finding subjects with high-risk SCCs..."
  
  # List of high-risk SCCs
  local high_risk_sccs=("privileged" "anyuid" "hostaccess" "hostnetwork" "hostmount-anyuid" "hostpath")
  
  if [ "$OUTPUT_FORMAT" == "html" ]; then
    # Generate HTML output
    cat << EOF
<!DOCTYPE html>
<html>
<head>
    <title>OpenShift High-Risk SCCs</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 40px;
            color: #333;
        }
        h1 {
            color: #cc0000;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        h2 {
            color: #cc0000;
            margin-top: 30px;
            border-bottom: 1px solid #eee;
            padding-bottom: 5px;
        }
        h3 {
            color: #333;
            margin-top: 20px;
        }
        .risk-high {
            color: #cc0000;
            font-weight: bold;
        }
        ul {
            list-style-type: square;
        }
    </style>
</head>
<body>
    <h1>OpenShift High-Risk SCCs</h1>
    <p>The following Security Context Constraints grant elevated privileges and should be carefully audited:</p>
    <div style="margin-top: 15px; margin-bottom: 25px;">
        <p style="margin-bottom: 10px;"><strong>High-Risk SCCs:</strong></p>
        <div style="display: flex; flex-wrap: wrap; gap: 10px;">
            $(for scc in "${high_risk_sccs[@]}"; do echo "<span style=\"background-color: #f8d7da; color: #721c24; padding: 8px 15px; border-radius: 4px; font-weight: bold;\">$scc</span>"; done)
        </div>
    </div>
EOF
    
    for scc in "${high_risk_sccs[@]}"; do
      if oc get scc "$scc" &> /dev/null; then
        local users=$(oc get scc "$scc" -o jsonpath='{.users}' | tr -d '[]"')
        local groups=$(oc get scc "$scc" -o jsonpath='{.groups}' | tr -d '[]"')
        
        cat << EOF
    <h2>Subjects with access to SCC: <span class="risk-high">$scc</span></h2>
    
    <h3>Users:</h3>
    <ul>
EOF
        
        if [ -z "$users" ]; then
          echo "      <li>None</li>" 
        else
          echo "$users" | tr ',' '\n' | while read -r user; do
            echo "      <li>$user</li>"
          done
        fi
        
        cat << EOF
    </ul>
    
    <h3>Groups:</h3>
    <ul>
EOF
        
        if [ -z "$groups" ]; then
          echo "      <li>None</li>"
        else
          echo "$groups" | tr ',' '\n' | while read -r group; do
            echo "      <li>$group</li>"
          done
        fi
        
        echo "    </ul>"
      fi
    done
    
    echo "</body></html>"
  else
    # Regular text output
    echo "High-Risk SCCs: ${high_risk_sccs[*]}"
    echo
    
    for scc in "${high_risk_sccs[@]}"; do
      if oc get scc "$scc" &> /dev/null; then
        echo "=== Subjects with access to SCC: $scc ==="
        local users=$(oc get scc "$scc" -o jsonpath='{.users}')
        local groups=$(oc get scc "$scc" -o jsonpath='{.groups}')
        
        echo "Users:"
        if [ "$users" == "[]" ] || [ -z "$users" ]; then
          echo "  None"
        else
          echo "$users" | tr -d '[]"' | tr ',' '\n' | sed 's/^ */  /'
        fi
        
        echo "Groups:"
        if [ "$groups" == "[]" ] || [ -z "$groups" ]; then
          echo "  None"
        else
          echo "$groups" | tr -d '[]"' | tr ',' '\n' | sed 's/^ */  /'
        fi
        echo ""
      fi
    done
  fi
}

# Function to find unused SCCs
unused() {
  echo "Finding unused SCCs..."
  
  local unused_sccs=""
  
  for scc in $(oc get scc -o jsonpath='{.items[*].metadata.name}'); do
    local users=$(oc get scc "$scc" -o jsonpath='{.users}')
    local groups=$(oc get scc "$scc" -o jsonpath='{.groups}')
    
    if ([ "$users" == "[]" ] || [ -z "$users" ]) && ([ "$groups" == "[]" ] || [ -z "$groups" ]); then
      unused_sccs="${unused_sccs}${scc}\n"
    fi
  done
  
  if [ "$OUTPUT_FORMAT" == "html" ]; then
    # Generate HTML output
    cat << EOF
<!DOCTYPE html>
<html>
<head>
    <title>OpenShift Unused SCCs</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 40px;
            color: #333;
        }
        h1 {
            color: #cc0000;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        ul {
            list-style-type: square;
        }
    </style>
</head>
<body>
    <h1>Unused Security Context Constraints</h1>
    <p>The following SCCs have no direct user or group assignments:</p>
    <ul>
EOF
    
    if [ -z "$unused_sccs" ]; then
      echo "      <li>None</li>"
    else
      echo -e "$unused_sccs" | while read -r scc; do
        if [ -n "$scc" ]; then
          echo "      <li>$scc</li>"
        fi
      done
    fi
    
    cat << EOF
    </ul>
</body>
</html>
EOF
  else
    # Regular text output
    echo "Unused SCCs (no direct user or group assignments):"
    if [ -z "$unused_sccs" ]; then
      echo "  None"
    else
      echo -e "$unused_sccs" | sed 's/^ */  /'
    fi
  fi
}

# Function to compare two SCCs
compare() {
  local scc1="$1"
  local scc2="$2"
  
  if [ -z "$scc1" ] || [ -z "$scc2" ]; then
    echo "Error: Two SCC names are required."
    echo "Usage: ${SCRIPT_NAME} compare [scc1] [scc2]"
    exit 1
  fi
  
  echo "Comparing SCCs: ${scc1} vs ${scc2}"
  
  if ! oc get scc "$scc1" &> /dev/null; then
    echo "Error: SCC '${scc1}' not found."
    exit 1
  fi
  
  if ! oc get scc "$scc2" &> /dev/null; then
    echo "Error: SCC '${scc2}' not found."
    exit 1
  fi
  
  # Extract SCCs to temporary files for comparison
  local temp_dir=$(mktemp -d)
  oc get scc "$scc1" -o yaml > "$temp_dir/$scc1.yaml"
  oc get scc "$scc2" -o yaml > "$temp_dir/$scc2.yaml"
  
  # Use diff to compare the files
  echo "Differences:"
  # Always fall back to regular diff to avoid color output
  diff -y --suppress-common-lines "$temp_dir/$scc1.yaml" "$temp_dir/$scc2.yaml" | grep -v "metadata\|creationTimestamp\|resourceVersion\|uid\|generation"
  
  # Clean up temporary files
  rm -rf "$temp_dir"
}

# Function to generate a comprehensive report
generate_report() {
  local timestamp=$(date +%Y%m%d-%H%M%S)
  local report_file="ocp-scc-audit-report-${timestamp}.md"
  
  # If HTML output format is requested, generate HTML report
  if [ "$OUTPUT_FORMAT" == "html" ]; then
    report_file="ocp-scc-audit-report-${timestamp}.html"
    
    echo "Generating comprehensive HTML SCC audit report: ${report_file}"
    
    # Create HTML report
    cat << EOF > "$report_file"
<!DOCTYPE html>
<html>
<head>
    <title>OpenShift Security Context Constraints Audit Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            color: #333;
            background-color: #f8f9fa;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #fff;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            border-radius: 5px;
        }
        header {
            background-color: #151c39;
            color: white;
            padding: 30px 20px;
            margin-bottom: 30px;
            border-radius: 5px;
            position: relative;
            overflow: hidden;
        }
        header::after {
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            bottom: 0;
            width: 30%;
            background: linear-gradient(135deg, transparent 0%, rgba(255,255,255,0.1) 100%);
            z-index: 1;
        }
        h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 600;
        }
        h2 {
            color: #151c39;
            margin-top: 40px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
            font-size: 22px;
            font-weight: 600;
        }
        h3 {
            color: #333;
            margin-top: 25px;
            margin-bottom: 15px;
            font-size: 18px;
            font-weight: 600;
        }
        h4 {
            color: #4c5b76;
            margin-top: 15px;
            margin-bottom: 10px;
            font-size: 16px;
            font-weight: 600;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
            background-color: #fff;
            border-radius: 5px;
            overflow: hidden;
            box-shadow: 0 0 10px rgba(0,0,0,0.05);
        }
        th, td {
            text-align: left;
            padding: 15px;
            border: 1px solid #eee;
        }
        th {
            background-color: #f2f6fc;
            color: #151c39;
            font-weight: 600;
        }
        tr:nth-child(even) {
            background-color: #f9fbff;
        }
        tr:hover {
            background-color: #f0f4fa;
        }
        .risk-high {
            color: #e53935;
            font-weight: bold;
        }
        .risk-medium {
            color: #f57c00;
            font-weight: bold;
        }
        .risk-low {
            color: #43a047;
        }
        .timestamp {
            color: #767676;
            font-style: italic;
            font-size: 0.9em;
            margin-bottom: 10px;
        }
        .true {
            color: #e53935;
            font-weight: bold;
        }
        .false {
            color: #43a047;
        }
        ul {
            list-style-type: none;
            padding-left: 0;
        }
        ul li {
            padding: 8px 0;
            border-bottom: 1px solid #eee;
        }
        ul li:before {
            content: "•";
            color: #151c39;
            font-weight: bold;
            display: inline-block;
            width: 20px;
        }
        .summary-box {
            background-color: #f2f6fc;
            border-left: 4px solid #151c39;
            padding: 15px;
            margin: 20px 0;
            border-radius: 0 5px 5px 0;
        }
        .cluster-info {
            display: flex;
            flex-wrap: wrap;
            gap: 30px;
            margin-top: 10px;
        }
        .cluster-info p {
            margin: 0;
            background-color: rgba(255,255,255,0.1);
            padding: 8px 15px;
            border-radius: 50px;
            font-size: 14px;
        }
        .section-title {
            display: flex;
            align-items: center;
        }
        .section-title:before {
            content: "";
            display: inline-block;
            width: 10px;
            height: 24px;
            background-color: #151c39;
            margin-right: 10px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>OpenShift Security Context Constraints Audit Report</h1>
        <div class="cluster-info">
            <p>Generated: $(date)</p>
            <p>Cluster: $(oc whoami --show-server)</p>
            <p>User: $(oc whoami)</p>
        </div>
    </header>
    
    <h2 class="section-title">Summary</h2>
    <div class="summary-box">
EOF
    
    # Add summary information
    echo "<p>Total SCCs: <strong>$(oc get scc -o name | wc -l)</strong></p>" >> "$report_file"
    echo "<p>Custom SCCs: <strong>$(oc get scc --no-headers | grep -v -E '^restricted|^nonroot|^hostmount-anyuid|^anyuid|^hostnetwork|^hostaccess|^privileged' | wc -l)</strong></p>" >> "$report_file"
    echo "</div>" >> "$report_file"
    
    # Add high-risk SCCs section
    cat << EOF >> "$report_file"
    <h2 class="section-title">High-Risk SCCs</h2>
    <p>The following Security Context Constraints grant elevated privileges and should be carefully audited:</p>
    
    <div style="display: flex; flex-wrap: wrap; gap: 10px; margin: 20px 0;">
        $(for scc in "${high_risk_sccs[@]}"; do echo "<span style=\"background-color: #f8d7da; color: #721c24; padding: 8px 15px; border-radius: 4px; font-weight: bold;\">$scc</span>"; done)
    </div>
EOF
    
    local high_risk_sccs=("privileged" "anyuid" "hostaccess" "hostnetwork" "hostmount-anyuid" "hostpath")
    
    for scc in "${high_risk_sccs[@]}"; do
      if oc get scc "$scc" &> /dev/null; then
        local users=$(oc get scc "$scc" -o jsonpath='{.users}' | tr -d '[]"')
        local groups=$(oc get scc "$scc" -o jsonpath='{.groups}' | tr -d '[]"')
        local allow_priv=$(oc get scc "$scc" -o jsonpath='{.allowPrivilegedContainer}')
        local allow_host_net=$(oc get scc "$scc" -o jsonpath='{.allowHostNetwork}')
        local allow_host_ports=$(oc get scc "$scc" -o jsonpath='{.allowHostPorts}')
        local allow_host_pid=$(oc get scc "$scc" -o jsonpath='{.allowHostPID}')
        local allow_host_ipc=$(oc get scc "$scc" -o jsonpath='{.allowHostIPC}')
        local allow_priv_esc=$(oc get scc "$scc" -o jsonpath='{.allowPrivilegeEscalation}')
        
        cat << EOF >> "$report_file"
        <div style="background-color: #fff; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.05); margin: 20px 0; padding: 20px;">
            <h3 style="color: #151c39; margin-top: 0;">SCC: <span class="risk-high">$scc</span></h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px; margin-bottom: 20px;">
                <div style="background-color: #f9f9f9; padding: 12px; border-radius: 4px;">
                    <span style="font-weight: bold;">Priority:</span> $(oc get scc "$scc" -o jsonpath='{.priority}')
                </div>
                <div style="background-color: #f9f9f9; padding: 12px; border-radius: 4px;">
                    <span style="font-weight: bold;">Allow Privileged:</span> 
                    <span class="$(if [ \"$allow_priv\" == \"true\" ]; then echo \"true\"; else echo \"false\"; fi)">$allow_priv</span>
                </div>
                <div style="background-color: #f9f9f9; padding: 12px; border-radius: 4px;">
                    <span style="font-weight: bold;">Allow Host Network:</span> 
                    <span class="$(if [ \"$allow_host_net\" == \"true\" ]; then echo \"true\"; else echo \"false\"; fi)">$allow_host_net</span>
                </div>
                <div style="background-color: #f9f9f9; padding: 12px; border-radius: 4px;">
                    <span style="font-weight: bold;">Allow Host Ports:</span> 
                    <span class="$(if [ \"$allow_host_ports\" == \"true\" ]; then echo \"true\"; else echo \"false\"; fi)">$allow_host_ports</span>
                </div>
                <div style="background-color: #f9f9f9; padding: 12px; border-radius: 4px;">
                    <span style="font-weight: bold;">Allow Host PID:</span> 
                    <span class="$(if [ \"$allow_host_pid\" == \"true\" ]; then echo \"true\"; else echo \"false\"; fi)">$allow_host_pid</span>
                </div>
                <div style="background-color: #f9f9f9; padding: 12px; border-radius: 4px;">
                    <span style="font-weight: bold;">Allow Host IPC:</span> 
                    <span class="$(if [ \"$allow_host_ipc\" == \"true\" ]; then echo \"true\"; else echo \"false\"; fi)">$allow_host_ipc</span>
                </div>
                <div style="background-color: #f9f9f9; padding: 12px; border-radius: 4px;">
                    <span style="font-weight: bold;">Allow Privilege Escalation:</span> 
                    <span class="$(if [ \"$allow_priv_esc\" == \"true\" ]; then echo \"true\"; else echo \"false\"; fi)">$allow_priv_esc</span>
                </div>
            </div>
            
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <div>
                    <h4>Assigned Users</h4>
                    <ul style="background-color: #f9fbff; border-radius: 4px; padding: 10px;">
EOF
        
        if [ -z "$users" ]; then
          echo "<li>None</li>" >> "$report_file"
        else
          echo "$users" | tr ',' '\n' | while read -r user; do
            echo "<li>$user</li>" >> "$report_file"
          done
        fi
        
        cat << EOF >> "$report_file"
                    </ul>
                </div>
                <div>
                    <h4>Assigned Groups</h4>
                    <ul style="background-color: #f9fbff; border-radius: 4px; padding: 10px;">
EOF
        
        if [ -z "$groups" ]; then
          echo "<li>None</li>" >> "$report_file"
        else
          echo "$groups" | tr ',' '\n' | while read -r group; do
            echo "<li>$group</li>" >> "$report_file"
          done
        fi
        
        echo "                    </ul>" >> "$report_file"
        echo "                </div>" >> "$report_file"
        echo "            </div>" >> "$report_file"
        echo "        </div>" >> "$report_file"
      fi
    done
    
    # Add custom SCCs section
    cat << EOF >> "$report_file"
    <h2 class="section-title">Custom SCCs</h2>
    <p>The following custom Security Context Constraints have been defined in the cluster:</p>
EOF
    
    for scc in $(oc get scc --no-headers | grep -v -E '^restricted|^nonroot|^hostmount-anyuid|^anyuid|^hostnetwork|^hostaccess|^privileged' | awk '{print $1}'); do
      local allow_priv=$(oc get scc "$scc" -o jsonpath='{.allowPrivilegedContainer}')
      local allow_host_net=$(oc get scc "$scc" -o jsonpath='{.allowHostNetwork}')
      local allow_host_ports=$(oc get scc "$scc" -o jsonpath='{.allowHostPorts}')
      local allow_host_pid=$(oc get scc "$scc" -o jsonpath='{.allowHostPID}')
      local allow_host_ipc=$(oc get scc "$scc" -o jsonpath='{.allowHostIPC}')
      local allow_priv_esc=$(oc get scc "$scc" -o jsonpath='{.allowPrivilegeEscalation}')
      local read_only_root=$(oc get scc "$scc" -o jsonpath='{.readOnlyRootFilesystem}')
      local run_as_user=$(oc get scc "$scc" -o jsonpath='{.runAsUser.type}')
      local selinux_context=$(oc get scc "$scc" -o jsonpath='{.seLinuxContext.type}')
      local users=$(oc get scc "$scc" -o jsonpath='{.users}' | tr -d '[]"')
      local groups=$(oc get scc "$scc" -o jsonpath='{.groups}' | tr -d '[]"')
      
      cat << EOF >> "$report_file"
      <div style="background-color: #fff; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.05); margin: 20px 0; padding: 20px;">
          <h3 style="color: #151c39; margin-top: 0;">SCC: $scc</h3>
          <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px; margin-bottom: 20px;">
              <div style="background-color: #f9f9f9; padding: 12px; border-radius: 4px;">
                  <span style="font-weight: bold;">Priority:</span> $(oc get scc "$scc" -o jsonpath='{.priority}')
              </div>
              <div style="background-color: #f9f9f9; padding: 12px; border-radius: 4px;">
                  <span style="font-weight: bold;">Allow Privileged:</span> 
                  <span class="$(if [ \"$allow_priv\" == \"true\" ]; then echo \"true\"; else echo \"false\"; fi)">$allow_priv</span>
              </div>
              <div style="background-color: #f9f9f9; padding: 12px; border-radius: 4px;">
                  <span style="font-weight: bold;">Allow Host Network:</span> 
                  <span class="$(if [ \"$allow_host_net\" == \"true\" ]; then echo \"true\"; else echo \"false\"; fi)">$allow_host_net</span>
              </div>
              <div style="background-color: #f9f9f9; padding: 12px; border-radius: 4px;">
                  <span style="font-weight: bold;">Allow Host Ports:</span> 
                  <span class="$(if [ \"$allow_host_ports\" == \"true\" ]; then echo \"true\"; else echo \"false\"; fi)">$allow_host_ports</span>
              </div>
              <div style="background-color: #f9f9f9; padding: 12px; border-radius: 4px;">
                  <span style="font-weight: bold;">Allow Host PID:</span> 
                  <span class="$(if [ \"$allow_host_pid\" == \"true\" ]; then echo \"true\"; else echo \"false\"; fi)">$allow_host_pid</span>
              </div>
              <div style="background-color: #f9f9f9; padding: 12px; border-radius: 4px;">
                  <span style="font-weight: bold;">Allow Host IPC:</span> 
                  <span class="$(if [ \"$allow_host_ipc\" == \"true\" ]; then echo \"true\"; else echo \"false\"; fi)">$allow_host_ipc</span>
              </div>
              <div style="background-color: #f9f9f9; padding: 12px; border-radius: 4px;">
                  <span style="font-weight: bold;">Allow Privilege Escalation:</span> 
                  <span class="$(if [ \"$allow_priv_esc\" == \"true\" ]; then echo \"true\"; else echo \"false\"; fi)">$allow_priv_esc</span>
              </div>
              <div style="background-color: #f9f9f9; padding: 12px; border-radius: 4px;">
                  <span style="font-weight: bold;">Read-Only Root Filesystem:</span> 
                  <span class="$(if [ \"$read_only_root\" == \"true\" ]; then echo \"true\"; else echo \"false\"; fi)">$read_only_root</span>
              </div>
              <div style="background-color: #f9f9f9; padding: 12px; border-radius: 4px;">
                  <span style="font-weight: bold;">Run As User Strategy:</span> $run_as_user
              </div>
              <div style="background-color: #f9f9f9; padding: 12px; border-radius: 4px;">
                  <span style="font-weight: bold;">SELinux Context Strategy:</span> $selinux_context
              </div>
          </div>
          
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
              <div>
                  <h4>Assigned Users</h4>
                  <ul style="background-color: #f9fbff; border-radius: 4px; padding: 10px;">
EOF
      
      if [ -z "$users" ]; then
        echo "<li>None</li>" >> "$report_file"
      else
        echo "$users" | tr ',' '\n' | while read -r user; do
          echo "<li>$user</li>" >> "$report_file"
        done
      fi
      
      cat << EOF >> "$report_file"
                  </ul>
              </div>
              <div>
                  <h4>Assigned Groups</h4>
                  <ul style="background-color: #f9fbff; border-radius: 4px; padding: 10px;">
EOF
      
      if [ -z "$groups" ]; then
        echo "<li>None</li>" >> "$report_file"
      else
        echo "$groups" | tr ',' '\n' | while read -r group; do
          echo "<li>$group</li>" >> "$report_file"
        done
      fi
      
      echo "                  </ul>" >> "$report_file"
      echo "              </div>" >> "$report_file"
      echo "          </div>" >> "$report_file"
      echo "      </div>" >> "$report_file"
    done
    
    # Add recommendations section
    cat << EOF >> "$report_file"
    <h2 class="section-title">Recommendations</h2>
    
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(450px, 1fr)); gap: 25px; margin-top: 25px;">
        <div style="background-color: #fff; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.05); padding: 20px;">
            <h3 style="color: #151c39; margin-top: 0;">Principle of Least Privilege</h3>
            <ul style="padding-left: 0;">
                <li>Review all service accounts with access to privileged SCCs</li>
                <li>Remove unnecessary SCC assignments</li>
                <li>Create custom SCCs that grant only the specific privileges required by applications</li>
            </ul>
        </div>
        
        <div style="background-color: #fff; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.05); padding: 20px;">
            <h3 style="color: #151c39; margin-top: 0;">Security Risks to Address</h3>
            <ul style="padding-left: 0;">
EOF
    
    # Check for common security issues
    if oc get scc privileged -o json | jq -r '.users | length' | grep -q '[1-9]'; then
      echo "<li class=\"risk-high\"><strong>HIGH RISK</strong>: Users have direct access to the 'privileged' SCC</li>" >> "$report_file"
    fi
    
    if oc get scc anyuid -o json | jq -r '.users | length' | grep -q '[1-9]'; then
      echo "<li class=\"risk-medium\"><strong>MEDIUM RISK</strong>: Users have direct access to the 'anyuid' SCC</li>" >> "$report_file"
    fi
    
    # Close HTML
    cat << EOF >> "$report_file"
            </ul>
        </div>
    </div>
    
    <div style="margin-top: 40px; text-align: center; color: #777; font-size: 0.9em; padding: 20px 0; border-top: 1px solid #eee;">
        <p>Generated with OpenShift SCC Audit Tool v${VERSION}</p>
    </div>
</div>
</body>
</html>
EOF
    
  else
    # Regular Markdown report (default)
    echo "Generating comprehensive SCC audit report: ${report_file}"
    
    # Create report header
    cat << EOF > "$report_file"
# OpenShift Security Context Constraints Audit Report
Generated: $(date)
Cluster: $(oc whoami --show-server)
User: $(oc whoami)

## Summary
EOF
    
    # Add summary information
    echo -e "Total SCCs: $(oc get scc -o name | wc -l)" >> "$report_file"
    echo -e "Custom SCCs: $(oc get scc --no-headers | grep -v -E '^restricted|^nonroot|^hostmount-anyuid|^anyuid|^hostnetwork|^hostaccess|^privileged' | wc -l)" >> "$report_file"
    
    # Add high-risk SCCs section
    cat << EOF >> "$report_file"

## High-Risk SCCs
The following SCCs grant elevated privileges and should be carefully audited:
EOF
    
    local high_risk_sccs=("privileged" "anyuid" "hostaccess" "hostnetwork" "hostmount-anyuid" "hostpath")
    
    for scc in "${high_risk_sccs[@]}"; do
      if oc get scc "$scc" &> /dev/null; then
        local users=$(oc get scc "$scc" -o jsonpath='{.users}' | tr -d '[]"')
        local groups=$(oc get scc "$scc" -o jsonpath='{.groups}' | tr -d '[]"')
        
        echo -e "### $scc" >> "$report_file"
        echo -e "- Priority: $(oc get scc "$scc" -o jsonpath='{.priority}')" >> "$report_file"
        echo -e "- Allow Privileged: $(oc get scc "$scc" -o jsonpath='{.allowPrivilegedContainer}')" >> "$report_file"
        echo -e "- Allow Host Network: $(oc get scc "$scc" -o jsonpath='{.allowHostNetwork}')" >> "$report_file"
        echo -e "- Allow Host Ports: $(oc get scc "$scc" -o jsonpath='{.allowHostPorts}')" >> "$report_file"
        echo -e "- Allow Host PID: $(oc get scc "$scc" -o jsonpath='{.allowHostPID}')" >> "$report_file"
        echo -e "- Allow Host IPC: $(oc get scc "$scc" -o jsonpath='{.allowHostIPC}')" >> "$report_file"
        echo -e "- Allow Privilege Escalation: $(oc get scc "$scc" -o jsonpath='{.allowPrivilegeEscalation}')" >> "$report_file"
        
        echo -e "\n**Assigned Users:**" >> "$report_file"
        if [ -z "$users" ]; then
          echo -e "- None" >> "$report_file"
        else
          echo "$users" | tr ',' '\n' | sed 's/^/- /' >> "$report_file"
        fi
        
        echo -e "\n**Assigned Groups:**" >> "$report_file"
        if [ -z "$groups" ]; then
          echo -e "- None" >> "$report_file"
        else
          echo "$groups" | tr ',' '\n' | sed 's/^/- /' >> "$report_file"
        fi
        
        echo -e "\n" >> "$report_file"
      fi
    done
    
    # Add custom SCCs section
    cat << EOF >> "$report_file"
## Custom SCCs
The following custom SCCs have been defined in the cluster:
EOF
    
    for scc in $(oc get scc --no-headers | grep -v -E '^restricted|^nonroot|^hostmount-anyuid|^anyuid|^hostnetwork|^hostaccess|^privileged' | awk '{print $1}'); do
      echo -e "### $scc" >> "$report_file"
      echo -e "- Priority: $(oc get scc "$scc" -o jsonpath='{.priority}')" >> "$report_file"
      echo -e "- Allow Privileged: $(oc get scc "$scc" -o jsonpath='{.allowPrivilegedContainer}')" >> "$report_file"
      echo -e "- Allow Host Network: $(oc get scc "$scc" -o jsonpath='{.allowHostNetwork}')" >> "$report_file"
      echo -e "- Allow Host Ports: $(oc get scc "$scc" -o jsonpath='{.allowHostPorts}')" >> "$report_file"
      echo -e "- Allow Host PID: $(oc get scc "$scc" -o jsonpath='{.allowHostPID}')" >> "$report_file"
      echo -e "- Allow Host IPC: $(oc get scc "$scc" -o jsonpath='{.allowHostIPC}')" >> "$report_file"
      echo -e "- Allow Privilege Escalation: $(oc get scc "$scc" -o jsonpath='{.allowPrivilegeEscalation}')" >> "$report_file"
      echo -e "- Read-Only Root Filesystem: $(oc get scc "$scc" -o jsonpath='{.readOnlyRootFilesystem}')" >> "$report_file"
      echo -e "- Run As User Strategy: $(oc get scc "$scc" -o jsonpath='{.runAsUser.type}')" >> "$report_file"
      echo -e "- SELinux Context Strategy: $(oc get scc "$scc" -o jsonpath='{.seLinuxContext.type}')" >> "$report_file"
      echo -e "- Users: $(oc get scc "$scc" -o jsonpath='{.users}' | tr -d '[]"')" >> "$report_file"
      echo -e "- Groups: $(oc get scc "$scc" -o jsonpath='{.groups}' | tr -d '[]"')" >> "$report_file"
      echo -e "\n" >> "$report_file"
    done
    
    # Add recommendations section
    cat << EOF >> "$report_file"
## Recommendations

### Principle of Least Privilege
- Review all service accounts with access to privileged SCCs
- Remove unnecessary SCC assignments
- Create custom SCCs that grant only the specific privileges required by applications

### Security Risks to Address
EOF
    
    # Check for common security issues
    if oc get scc privileged -o json | jq -r '.users | length' | grep -q '[1-9]'; then
      echo -e "- **HIGH RISK**: Users have direct access to the 'privileged' SCC" >> "$report_file"
    fi
    
    if oc get scc anyuid -o json | jq -r '.users | length' | grep -q '[1-9]'; then
      echo -e "- **MEDIUM RISK**: Users have direct access to the 'anyuid' SCC" >> "$report_file"
    fi
  fi
  
  # Finalize report
  echo -e "Report generated: ${report_file}"
}

# Parse command line arguments
parse_args() {
  COMMAND=""
  SCC_NAME1=""
  SCC_NAME2=""
  OUTPUT_FORMAT="table"
  NAMESPACE=""
  CAPABILITY=""
  
  while [[ $# -gt 0 ]]; do
    case "$1" in
      list-sccs|check-scc|find-subjects|high-risk|unused|compare|report|sensitive-caps|sensitive-volumes|sensitive-seccomp|sensitive-selinux|container-security-report|help)
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
      -n|--namespace)
        if [[ $# -lt 2 ]] || [[ "$2" == -* ]]; then
          echo "Error: Missing argument for $1"
          exit 1
        fi
        NAMESPACE="$2"
        shift 2
        ;;
      -c|--capability)
        if [[ $# -lt 2 ]] || [[ "$2" == -* ]]; then
          echo "Error: Missing argument for $1"
          exit 1
        fi
        CAPABILITY="$2"
        shift 2
        ;;
      -h|--help)
        show_usage
        exit 0
        ;;
      -v|--version)
        echo "OpenShift SCC Audit Tool v${VERSION}"
        exit 0
        ;;
      *)
        if [ -z "$SCC_NAME1" ] && [ "$COMMAND" = "check-scc" -o "$COMMAND" = "find-subjects" ]; then
          SCC_NAME1="$1"
        elif [ -z "$SCC_NAME1" ] && [ "$COMMAND" = "compare" ]; then
          SCC_NAME1="$1"
        elif [ -z "$SCC_NAME2" ] && [ "$COMMAND" = "compare" ]; then
          SCC_NAME2="$1"
        else
          echo "Error: Unknown argument: $1"
          show_usage
          exit 1
        fi
        shift
        ;;
    esac
  done
  
  # Validate that a command was provided
  if [ -z "$COMMAND" ]; then
    echo "Error: No command specified."
    show_usage
    exit 1
  fi
}

# Function to find subjects with SCCs allowing sensitive Linux capabilities
sensitive_caps() {
  echo "Finding subjects with SCCs allowing sensitive Linux capabilities..."
  
  # List of sensitive capabilities if not specified
  local sensitive_capabilities=("SYS_ADMIN" "NET_ADMIN" "SYS_PTRACE" "SYS_BOOT" "SYS_CHROOT" "SYS_MODULE" "SYS_RAWIO" "SYS_TIME" "SYS_TTY_CONFIG" "SETPCAP" "LINUX_IMMUTABLE" "NET_BROADCAST" "NET_RAW" "IPC_LOCK" "IPC_OWNER" "KILL" "LEASE" "WAKE_ALARM" "BLOCK_SUSPEND" "AUDIT_CONTROL" "SYSLOG" "DAC_READ_SEARCH" "DAC_OVERRIDE" "FOWNER" "MAC_OVERRIDE" "MAC_ADMIN")
  
  # If a specific capability is provided, just check that one
  if [ -n "$CAPABILITY" ]; then
    sensitive_capabilities=("$CAPABILITY")
  fi
  
  echo "Checking for SCCs with the following sensitive capabilities:"
  for cap in "${sensitive_capabilities[@]}"; do
    echo "  - $cap"
  done
  echo ""
  
  # Iterate through all SCCs
  for scc in $(oc get scc -o jsonpath='{.items[*].metadata.name}'); do
    local allowed_caps=$(oc get scc "$scc" -o jsonpath='{.allowedCapabilities}')
    local defaulted_caps=$(oc get scc "$scc" -o jsonpath='{.defaultAddCapabilities}')
    
    # Check for "ALL" in allowedCapabilities (highest risk)
    if [[ "$allowed_caps" == *"ALL"* ]]; then
      echo "SCC '$scc' allows ALL capabilities (extremely high risk)"
      echo "Assigned to:"
      
      local users=$(oc get scc "$scc" -o jsonpath='{.users}')
      local groups=$(oc get scc "$scc" -o jsonpath='{.groups}')
      
      echo "Users:"
      if [ "$users" == "[]" ] || [ -z "$users" ]; then
        echo "  None"
      else
        echo "$users" | tr -d '[]"' | tr ',' '\n' | sed 's/^ */  /'
      fi
      
      echo "Groups:"
      if [ "$groups" == "[]" ] || [ -z "$groups" ]; then
        echo "  None"
      else
        echo "$groups" | tr -d '[]"' | tr ',' '\n' | sed 's/^ */  /'
      fi
      echo ""
      continue
    fi
    
    # Check for specific sensitive capabilities
    local has_sensitive=false
    local detected_caps=""
    
    for cap in "${sensitive_capabilities[@]}"; do
      if [[ "$allowed_caps" == *"$cap"* ]] || [[ "$defaulted_caps" == *"$cap"* ]]; then
        has_sensitive=true
        detected_caps="${detected_caps}${cap} "
      fi
    done
    
    if [ "$has_sensitive" = true ]; then
      echo "SCC '$scc' allows sensitive capabilities: ${detected_caps}"
      echo "Assigned to:"
      
      local users=$(oc get scc "$scc" -o jsonpath='{.users}')
      local groups=$(oc get scc "$scc" -o jsonpath='{.groups}')
      
      echo "Users:"
      if [ "$users" == "[]" ] || [ -z "$users" ]; then
        echo "  None"
      else
        echo "$users" | tr -d '[]"' | tr ',' '\n' | sed 's/^ */  /'
      fi
      
      echo "Groups:"
      if [ "$groups" == "[]" ] || [ -z "$groups" ]; then
        echo "  None"
      else
        echo "$groups" | tr -d '[]"' | tr ',' '\n' | sed 's/^ */  /'
      fi
      echo ""
    fi
  done
}

# Function to find subjects with SCCs allowing sensitive volume types
sensitive_volumes() {
  echo "Finding subjects with SCCs allowing sensitive volume types..."
  
  # List of sensitive volume types
  local sensitive_volumes=("hostPath" "configMap" "secret" "persistentVolumeClaim" "projected" "downwardAPI" "emptyDir" "gcePersistentDisk" "awsElasticBlockStore" "azureDisk" "azureFile" "cephFS" "cinder" "fc" "flexVolume" "flocker" "nfs" "glusterfs" "iscsi" "portworxVolume" "quobyte" "rbd" "scaleIO" "storageos" "vsphereVolume")
  
  # Iterate through all SCCs
  for scc in $(oc get scc -o jsonpath='{.items[*].metadata.name}'); do
    local allowed_volumes=$(oc get scc "$scc" -o jsonpath='{.volumes}')
    
    # Check for ALL volumes (highest risk)
    if [[ "$allowed_volumes" == *"*"* ]] || [[ "$allowed_volumes" == *"ALL"* ]]; then
      echo "SCC '$scc' allows ALL volume types (high risk)"
      echo "Assigned to:"
      
      local users=$(oc get scc "$scc" -o jsonpath='{.users}')
      local groups=$(oc get scc "$scc" -o jsonpath='{.groups}')
      
      echo "Users:"
      if [ "$users" == "[]" ] || [ -z "$users" ]; then
        echo "  None"
      else
        echo "$users" | tr -d '[]"' | tr ',' '\n' | sed 's/^ */  /'
      fi
      
      echo "Groups:"
      if [ "$groups" == "[]" ] || [ -z "$groups" ]; then
        echo "  None"
      else
        echo "$groups" | tr -d '[]"' | tr ',' '\n' | sed 's/^ */  /'
      fi
      echo ""
      continue
    fi
    
    # Check for specific sensitive volume types
    local sensitive_found=()
    
    for vol in "${sensitive_volumes[@]}"; do
      if [[ "$allowed_volumes" == *"$vol"* ]]; then
        sensitive_found+=("$vol")
      fi
    done
    
    if [ ${#sensitive_found[@]} -gt 0 ]; then
      echo "SCC '$scc' allows sensitive volume types: ${sensitive_found[*]}"
      
      # Special highlight for hostPath volumes, but without color
      if [[ "${sensitive_found[*]}" == *"hostPath"* ]]; then
        echo "CRITICAL: hostPath volumes allow containers to access arbitrary host filesystem paths!"
      fi
      
      echo "Assigned to:"
      
      local users=$(oc get scc "$scc" -o jsonpath='{.users}')
      local groups=$(oc get scc "$scc" -o jsonpath='{.groups}')
      
      echo "Users:"
      if [ "$users" == "[]" ] || [ -z "$users" ]; then
        echo "  None"
      else
        echo "$users" | tr -d '[]"' | tr ',' '\n' | sed 's/^ */  /'
      fi
      
      echo "Groups:"
      if [ "$groups" == "[]" ] || [ -z "$groups" ]; then
        echo "  None"
      else
        echo "$groups" | tr -d '[]"' | tr ',' '\n' | sed 's/^ */  /'
      fi
      echo ""
    fi
  done
}

# Function to find subjects with unconfined seccomp profiles
sensitive_seccomp() {
  echo "Finding subjects with SCCs allowing unconfined seccomp profiles..."
  
  # Iterate through all SCCs
  for scc in $(oc get scc -o jsonpath='{.items[*].metadata.name}'); do
    local seccomp_profile=$(oc get scc "$scc" -o jsonpath='{.seccompProfiles}' 2>/dev/null)
    local annotations=$(oc get scc "$scc" -o jsonpath='{.metadata.annotations}' 2>/dev/null)
    
    # Check for unconfined seccomp profiles
    if [[ "$seccomp_profile" == *"unconfined"* ]] || [[ "$annotations" == *"unconfined"* ]]; then
      echo "SCC '$scc' allows unconfined seccomp profiles (high risk)"
      echo "Assigned to:"
      
      local users=$(oc get scc "$scc" -o jsonpath='{.users}')
      local groups=$(oc get scc "$scc" -o jsonpath='{.groups}')
      
      echo "Users:"
      if [ "$users" == "[]" ] || [ -z "$users" ]; then
        echo "  None"
      else
        echo "$users" | tr -d '[]"' | tr ',' '\n' | sed 's/^ */  /'
      fi
      
      echo "Groups:"
      if [ "$groups" == "[]" ] || [ -z "$groups" ]; then
        echo "  None"
      else
        echo "$groups" | tr -d '[]"' | tr ',' '\n' | sed 's/^ */  /'
      fi
      echo ""
    fi
  done
}

# Function to find subjects with SCCs having permissive SELinux contexts
sensitive_selinux() {
  echo "Finding subjects with SCCs having permissive SELinux contexts..."
  
  # Iterate through all SCCs
  for scc in $(oc get scc -o jsonpath='{.items[*].metadata.name}'); do
    local selinux_context=$(oc get scc "$scc" -o jsonpath='{.seLinuxContext.type}' 2>/dev/null)
    
    # Check for permissive SELinux contexts
    if [[ "$selinux_context" == "RunAsAny" ]]; then
      echo "SCC '$scc' allows RunAsAny SELinux context (high risk)"
      echo "Assigned to:"
      
      local users=$(oc get scc "$scc" -o jsonpath='{.users}')
      local groups=$(oc get scc "$scc" -o jsonpath='{.groups}')
      
      echo "Users:"
      if [ "$users" == "[]" ] || [ -z "$users" ]; then
        echo "  None"
      else
        echo "$users" | tr -d '[]"' | tr ',' '\n' | sed 's/^ */  /'
      fi
      
      echo "Groups:"
      if [ "$groups" == "[]" ] || [ -z "$groups" ]; then
        echo "  None"
      else
        echo "$groups" | tr -d '[]"' | tr ',' '\n' | sed 's/^ */  /'
      fi
      echo ""
    fi
  done
}

# Function to generate a comprehensive container security posture report
container_security_report() {
  local timestamp=$(date +%Y%m%d-%H%M%S)
  local report_file="ocp-container-security-report-${timestamp}.md"
  
  # If HTML output format is requested, generate HTML report
  if [ "$OUTPUT_FORMAT" == "html" ]; then
    report_file="ocp-container-security-report-${timestamp}.html"
    
    echo "Generating comprehensive HTML container security posture report: ${report_file}"
    
    # Create HTML report
    cat << EOF > "$report_file"
<!DOCTYPE html>
<html>
<head>
    <title>OpenShift Container Security Posture Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 40px;
            color: #333;
        }
        h1 {
            color: #cc0000;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        h2 {
            color: #cc0000;
            margin-top: 30px;
            border-bottom: 1px solid #eee;
            padding-bottom: 5px;
        }
        h3 {
            color: #333;
            margin-top: 20px;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
        }
        th, td {
            text-align: left;
            padding: 12px;
            border: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .risk-high {
            color: #cc0000;
            font-weight: bold;
        }
        .risk-medium {
            color: #ec7a08;
            font-weight: bold;
        }
        .risk-low {
            color: #4f9e4f;
        }
        .timestamp {
            color: #666;
            font-style: italic;
            font-size: 0.9em;
        }
        .true {
            color: #cc0000;
            font-weight: bold;
        }
        .false {
            color: #4f9e4f;
        }
        ul {
            list-style-type: square;
        }
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>OpenShift Container Security Posture Report</h1>
        <div class="cluster-info">
            <p>Generated: $(date)</p>
            <p>Cluster: $(oc whoami --show-server)</p>
            <p>User: $(oc whoami)</p>
        </div>
    </header>
    
    <h2 class="section-title">Overview</h2>
    <div class="summary-box">
        <p>This report provides a comprehensive analysis of the security posture of your OpenShift cluster
        with a focus on Security Context Constraints (SCCs) and container security configurations.</p>
    </div>
    
    <h2 class="section-title">Summary</h2>
    <div class="summary-box">
EOF
    
    # Add summary information
    echo "<p>Total SCCs: <strong>$(oc get scc -o name | wc -l)</strong></p>" >> "$report_file"
    
    # Count high-risk SCCs
    local high_risk_count=0
    for scc in $(oc get scc -o jsonpath='{.items[*].metadata.name}'); do
      local privileged=$(oc get scc "$scc" -o jsonpath='{.allowPrivilegedContainer}')
      local host_network=$(oc get scc "$scc" -o jsonpath='{.allowHostNetwork}')
      local host_pid=$(oc get scc "$scc" -o jsonpath='{.allowHostPID}')
      local host_ipc=$(oc get scc "$scc" -o jsonpath='{.allowHostIPC}')
      local volumes=$(oc get scc "$scc" -o jsonpath='{.volumes}')
      
      if [[ "$privileged" == "true" ]] || [[ "$host_network" == "true" ]] || [[ "$host_pid" == "true" ]] || [[ "$host_ipc" == "true" ]] || [[ "$volumes" == *"hostPath"* ]] || [[ "$volumes" == *"ALL"* ]]; then
        high_risk_count=$((high_risk_count+1))
      fi
    done
    echo "<p>High-Risk SCCs: <strong class=\"risk-high\">$high_risk_count</strong></p>" >> "$report_file"
    echo "</div>" >> "$report_file"
    
    # Add section for privileged SCCs
    cat << EOF >> "$report_file"
    <h2 class="section-title">Privileged Access Analysis</h2>
    <p>The following SCCs allow privileged operations:</p>
EOF
    
    for scc in $(oc get scc -o jsonpath='{.items[*].metadata.name}'); do
      local privileged=$(oc get scc "$scc" -o jsonpath='{.allowPrivilegedContainer}')
      
      if [[ "$privileged" == "true" ]]; then
        echo "<h3>SCC: $scc</h3>" >> "$report_file"
        echo "<ul>" >> "$report_file"
        echo "<li>Priority: $(oc get scc "$scc" -o jsonpath='{.priority}')</li>" >> "$report_file"
        
        local users=$(oc get scc "$scc" -o jsonpath='{.users}' | tr -d '[]"')
        local groups=$(oc get scc "$scc" -o jsonpath='{.groups}' | tr -d '[]"')
        
        echo "</ul>" >> "$report_file"
        
        echo "<h4>Users:</h4>" >> "$report_file"
        echo "<ul>" >> "$report_file"
        if [ -z "$users" ]; then
          echo "<li>None</li>" >> "$report_file"
        else
          echo "$users" | tr ',' '\n' | while read -r user; do
            echo "<li>$user</li>" >> "$report_file"
          done
        fi
        echo "</ul>" >> "$report_file"
        
        echo "<h4>Groups:</h4>" >> "$report_file"
        echo "<ul>" >> "$report_file"
        if [ -z "$groups" ]; then
          echo "<li>None</li>" >> "$report_file"
        else
          echo "$groups" | tr ',' '\n' | while read -r group; do
            echo "<li>$group</li>" >> "$report_file"
          done
        fi
        echo "</ul>" >> "$report_file"
      fi
    done
    
    # Add section for host access
    cat << EOF >> "$report_file"
    <h2>Host Access Analysis</h2>
    <p>The following SCCs allow access to host resources:</p>
EOF
    
    for scc in $(oc get scc -o jsonpath='{.items[*].metadata.name}'); do
      local host_network=$(oc get scc "$scc" -o jsonpath='{.allowHostNetwork}')
      local host_pid=$(oc get scc "$scc" -o jsonpath='{.allowHostPID}')
      local host_ipc=$(oc get scc "$scc" -o jsonpath='{.allowHostIPC}')
      local volumes=$(oc get scc "$scc" -o jsonpath='{.volumes}')
      
      if [[ "$host_network" == "true" ]] || [[ "$host_pid" == "true" ]] || [[ "$host_ipc" == "true" ]] || [[ "$volumes" == *"hostPath"* ]]; then
        echo "<h3>SCC: $scc</h3>" >> "$report_file"
        echo "<ul>" >> "$report_file"
        echo "<li>Host Network: <span class=\"$(if [ \"$host_network\" == \"true\" ]; then echo \"true\"; else echo \"false\"; fi)\">$host_network</span></li>" >> "$report_file"
        echo "<li>Host PID: <span class=\"$(if [ \"$host_pid\" == \"true\" ]; then echo \"true\"; else echo \"false\"; fi)\">$host_pid</span></li>" >> "$report_file"
        echo "<li>Host IPC: <span class=\"$(if [ \"$host_ipc\" == \"true\" ]; then echo \"true\"; else echo \"false\"; fi)\">$host_ipc</span></li>" >> "$report_file"
        echo "<li>Host Path Volumes: <span class=\"$(if [[ \"$volumes\" == *\"hostPath\"* ]]; then echo \"true\"; else echo \"false\"; fi)\">$(if [[ \"$volumes\" == *\"hostPath\"* ]]; then echo \"Yes\"; else echo \"No\"; fi)</span></li>" >> "$report_file"
        echo "</ul>" >> "$report_file"
        
        local users=$(oc get scc "$scc" -o jsonpath='{.users}' | tr -d '[]"')
        local groups=$(oc get scc "$scc" -o jsonpath='{.groups}' | tr -d '[]"')
        
        echo "<h4>Users:</h4>" >> "$report_file"
        echo "<ul>" >> "$report_file"
        if [ -z "$users" ]; then
          echo "<li>None</li>" >> "$report_file"
        else
          echo "$users" | tr ',' '\n' | while read -r user; do
            echo "<li>$user</li>" >> "$report_file"
          done
        fi
        echo "</ul>" >> "$report_file"
        
        echo "<h4>Groups:</h4>" >> "$report_file"
        echo "<ul>" >> "$report_file"
        if [ -z "$groups" ]; then
          echo "<li>None</li>" >> "$report_file"
        else
          echo "$groups" | tr ',' '\n' | while read -r group; do
            echo "<li>$group</li>" >> "$report_file"
          done
        fi
        echo "</ul>" >> "$report_file"
      fi
    done
    
    # Add section for Linux capabilities
    cat << EOF >> "$report_file"
    <h2>Linux Capabilities Analysis</h2>
    <p>The following SCCs allow sensitive Linux capabilities:</p>
EOF
    
    for scc in $(oc get scc -o jsonpath='{.items[*].metadata.name}'); do
      local allowed_caps=$(oc get scc "$scc" -o jsonpath='{.allowedCapabilities}')
      local default_caps=$(oc get scc "$scc" -o jsonpath='{.defaultAddCapabilities}')
      
      if [[ "$allowed_caps" != "[]" ]] && [[ ! -z "$allowed_caps" ]]; then
        echo "<h3>SCC: $scc</h3>" >> "$report_file"
        echo "<ul>" >> "$report_file"
        echo "<li>Allowed Capabilities: $allowed_caps</li>" >> "$report_file"
        echo "<li>Default Add Capabilities: $default_caps</li>" >> "$report_file"
        echo "</ul>" >> "$report_file"
        
        local users=$(oc get scc "$scc" -o jsonpath='{.users}' | tr -d '[]"')
        local groups=$(oc get scc "$scc" -o jsonpath='{.groups}' | tr -d '[]"')
        
        echo "<h4>Users:</h4>" >> "$report_file"
        echo "<ul>" >> "$report_file"
        if [ -z "$users" ]; then
          echo "<li>None</li>" >> "$report_file"
        else
          echo "$users" | tr ',' '\n' | while read -r user; do
            echo "<li>$user</li>" >> "$report_file"
          done
        fi
        echo "</ul>" >> "$report_file"
        
        echo "<h4>Groups:</h4>" >> "$report_file"
        echo "<ul>" >> "$report_file"
        if [ -z "$groups" ]; then
          echo "<li>None</li>" >> "$report_file"
        else
          echo "$groups" | tr ',' '\n' | while read -r group; do
            echo "<li>$group</li>" >> "$report_file"
          done
        fi
        echo "</ul>" >> "$report_file"
      fi
    done
    
    # Add security recommendations
    cat << EOF >> "$report_file"
    <h2 class="section-title">Security Recommendations</h2>
    
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 25px; margin-top: 25px;">
        <div style="background-color: #fff; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.05); padding: 20px;">
            <h3 style="color: #151c39; margin-top: 0;">High Priority</h3>
            <ol style="padding-left: 20px;">
                <li><strong>Restrict Privileged Access</strong>: Review all SCCs that allow privileged access and limit them to only essential service accounts.</li>
                <li><strong>Minimize Host Access</strong>: Container workloads should not require host network, PID, or IPC access in most cases.</li>
                <li><strong>Restrict Host Path Volumes</strong>: Avoid allowing hostPath volumes which provide direct access to the host filesystem.</li>
            </ol>
        </div>
        
        <div style="background-color: #fff; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.05); padding: 20px;">
            <h3 style="color: #151c39; margin-top: 0;">Medium Priority</h3>
            <ol style="padding-left: 20px;">
                <li><strong>Limit Linux Capabilities</strong>: Only grant the specific capabilities required for workloads to function.</li>
                <li><strong>Implement SELinux Policies</strong>: Use MustRunAs rather than RunAsAny for SELinux context where possible.</li>
                <li><strong>Restrict Volume Types</strong>: Only allow volume types that are required for your applications.</li>
            </ol>
        </div>
        
        <div style="background-color: #fff; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.05); padding: 20px;">
            <h3 style="color: #151c39; margin-top: 0;">Best Practices</h3>
            <ol style="padding-left: 20px;">
                <li><strong>Create Custom SCCs</strong>: Rather than using privileged or anyuid SCCs, create custom SCCs with only the permissions needed.</li>
                <li><strong>Regular Auditing</strong>: Run this security audit tool regularly to monitor for changes in SCC assignments.</li>
                <li><strong>Namespace Isolation</strong>: Use network policies to isolate namespaces and restrict communication between pods.</li>
                <li><strong>Use Admission Controllers</strong>: Implement admission controllers to enforce security policies.</li>
            </ol>
        </div>
    </div>
    
    <div style="margin-top: 40px; text-align: center; color: #777; font-size: 0.9em; padding: 20px 0; border-top: 1px solid #eee;">
        <p>Generated with OpenShift Container Security Tool v${VERSION}</p>
    </div>
</div>
</body>
</html>
EOF
  
  else
    # Regular Markdown report (default)
    echo "Generating comprehensive container security report: ${report_file}"
    
    # Create report header
    cat << EOF > "$report_file"
# OpenShift Container Security Posture Report
Generated: $(date)
Cluster: $(oc whoami --show-server)
User: $(oc whoami)

## Overview
This report provides a comprehensive analysis of the security posture of your OpenShift cluster
with a focus on Security Context Constraints (SCCs) and container security configurations.

## Summary
EOF
    
    # Add summary information
    echo -e "- Total SCCs: $(oc get scc -o name | wc -l)" >> "$report_file"
    
    # Count high-risk SCCs
    local high_risk_count=0
    for scc in $(oc get scc -o jsonpath='{.items[*].metadata.name}'); do
      local privileged=$(oc get scc "$scc" -o jsonpath='{.allowPrivilegedContainer}')
      local host_network=$(oc get scc "$scc" -o jsonpath='{.allowHostNetwork}')
      local host_pid=$(oc get scc "$scc" -o jsonpath='{.allowHostPID}')
      local host_ipc=$(oc get scc "$scc" -o jsonpath='{.allowHostIPC}')
      local volumes=$(oc get scc "$scc" -o jsonpath='{.volumes}')
      
      if [[ "$privileged" == "true" ]] || [[ "$host_network" == "true" ]] || [[ "$host_pid" == "true" ]] || [[ "$host_ipc" == "true" ]] || [[ "$volumes" == *"hostPath"* ]] || [[ "$volumes" == *"ALL"* ]]; then
        high_risk_count=$((high_risk_count+1))
      fi
    done
    echo -e "- High-Risk SCCs: $high_risk_count" >> "$report_file"
    
    # Add section for privileged SCCs
    cat << EOF >> "$report_file"

## Privileged Access Analysis
The following SCCs allow privileged operations:
EOF
    
    for scc in $(oc get scc -o jsonpath='{.items[*].metadata.name}'); do
      local privileged=$(oc get scc "$scc" -o jsonpath='{.allowPrivilegedContainer}')
      
      if [[ "$privileged" == "true" ]]; then
        echo -e "### SCC: $scc" >> "$report_file"
        echo -e "- Priority: $(oc get scc "$scc" -o jsonpath='{.priority}')" >> "$report_file"
        
        local users=$(oc get scc "$scc" -o jsonpath='{.users}' | tr -d '[]"')
        local groups=$(oc get scc "$scc" -o jsonpath='{.groups}' | tr -d '[]"')
        
        echo -e "\n**Users:**" >> "$report_file"
        if [ -z "$users" ]; then
          echo -e "- None" >> "$report_file"
        else
          echo "$users" | tr ',' '\n' | sed 's/^/- /' >> "$report_file"
        fi
        
        echo -e "\n**Groups:**" >> "$report_file"
        if [ -z "$groups" ]; then
          echo -e "- None" >> "$report_file"
        else
          echo "$groups" | tr ',' '\n' | sed 's/^/- /' >> "$report_file"
        fi
        
        echo -e "\n" >> "$report_file"
      fi
    done
    
    # Add section for host access
    cat << EOF >> "$report_file"
## Host Access Analysis
The following SCCs allow access to host resources:
EOF
    
    for scc in $(oc get scc -o jsonpath='{.items[*].metadata.name}'); do
      local host_network=$(oc get scc "$scc" -o jsonpath='{.allowHostNetwork}')
      local host_pid=$(oc get scc "$scc" -o jsonpath='{.allowHostPID}')
      local host_ipc=$(oc get scc "$scc" -o jsonpath='{.allowHostIPC}')
      local volumes=$(oc get scc "$scc" -o jsonpath='{.volumes}')
      
      if [[ "$host_network" == "true" ]] || [[ "$host_pid" == "true" ]] || [[ "$host_ipc" == "true" ]] || [[ "$volumes" == *"hostPath"* ]]; then
        echo -e "### SCC: $scc" >> "$report_file"
        echo -e "- Host Network: $host_network" >> "$report_file"
        echo -e "- Host PID: $host_pid" >> "$report_file"
        echo -e "- Host IPC: $host_ipc" >> "$report_file"
        echo -e "- Host Path Volumes: $(if [[ "$volumes" == *"hostPath"* ]]; then echo "Yes"; else echo "No"; fi)" >> "$report_file"
        
        local users=$(oc get scc "$scc" -o jsonpath='{.users}' | tr -d '[]"')
        local groups=$(oc get scc "$scc" -o jsonpath='{.groups}' | tr -d '[]"')
        
        echo -e "\n**Users:**" >> "$report_file"
        if [ -z "$users" ]; then
          echo -e "- None" >> "$report_file"
        else
          echo "$users" | tr ',' '\n' | sed 's/^/- /' >> "$report_file"
        fi
        
        echo -e "\n**Groups:**" >> "$report_file"
        if [ -z "$groups" ]; then
          echo -e "- None" >> "$report_file"
        else
          echo "$groups" | tr ',' '\n' | sed 's/^/- /' >> "$report_file"
        fi
        
        echo -e "\n" >> "$report_file"
      fi
    done
    
    # Add section for Linux capabilities
    cat << EOF >> "$report_file"
## Linux Capabilities Analysis
The following SCCs allow sensitive Linux capabilities:
EOF
    
    for scc in $(oc get scc -o jsonpath='{.items[*].metadata.name}'); do
      local allowed_caps=$(oc get scc "$scc" -o jsonpath='{.allowedCapabilities}')
      local default_caps=$(oc get scc "$scc" -o jsonpath='{.defaultAddCapabilities}')
      
      if [[ "$allowed_caps" != "[]" ]] && [[ ! -z "$allowed_caps" ]]; then
        echo -e "### SCC: $scc" >> "$report_file"
        echo -e "- Allowed Capabilities: $allowed_caps" >> "$report_file"
        echo -e "- Default Add Capabilities: $default_caps" >> "$report_file"
        
        local users=$(oc get scc "$scc" -o jsonpath='{.users}' | tr -d '[]"')
        local groups=$(oc get scc "$scc" -o jsonpath='{.groups}' | tr -d '[]"')
        
        echo -e "\n**Users:**" >> "$report_file"
        if [ -z "$users" ]; then
          echo -e "- None" >> "$report_file"
        else
          echo "$users" | tr ',' '\n' | sed 's/^/- /' >> "$report_file"
        fi
        
        echo -e "\n**Groups:**" >> "$report_file"
        if [ -z "$groups" ]; then
          echo -e "- None" >> "$report_file"
        else
          echo "$groups" | tr ',' '\n' | sed 's/^/- /' >> "$report_file"
        fi
        
        echo -e "\n" >> "$report_file"
      fi
    done
    
    # Add security recommendations
    cat << EOF >> "$report_file"
## Security Recommendations

### High Priority
1. **Restrict Privileged Access**: Review all SCCs that allow privileged access and limit them to only essential service accounts.
2. **Minimize Host Access**: Container workloads should not require host network, PID, or IPC access in most cases.
3. **Restrict Host Path Volumes**: Avoid allowing hostPath volumes which provide direct access to the host filesystem.

### Medium Priority
1. **Limit Linux Capabilities**: Only grant the specific capabilities required for workloads to function.
2. **Implement SELinux Policies**: Use MustRunAs rather than RunAsAny for SELinux context where possible.
3. **Restrict Volume Types**: Only allow volume types that are required for your applications.

### Best Practices
1. **Create Custom SCCs**: Rather than using privileged or anyuid SCCs, create custom SCCs with only the permissions needed.
2. **Regular Auditing**: Run this security audit tool regularly to monitor for changes in SCC assignments.
3. **Namespace Isolation**: Use network policies to isolate namespaces and restrict communication between pods.
4. **Use Admission Controllers**: Implement admission controllers to enforce security policies.
EOF
  fi
  
  # Finalize report
  echo -e "Report generated: ${report_file}"
}

# Main function
main() {
  parse_args "$@"
  
  case "$COMMAND" in
    list-sccs)
      check_prereqs
      list_sccs
      ;;
    check-scc)
      check_prereqs
      check_scc "$SCC_NAME1"
      ;;
    find-subjects)
      check_prereqs
      find_subjects "$SCC_NAME1"
      ;;
    high-risk)
      check_prereqs
      high_risk
      ;;
    unused)
      check_prereqs
      unused
      ;;
    compare)
      check_prereqs
      compare "$SCC_NAME1" "$SCC_NAME2"
      ;;
    report)
      check_prereqs
      generate_report
      ;;
    sensitive-caps)
      check_prereqs
      sensitive_caps
      ;;
    sensitive-volumes)
      check_prereqs
      sensitive_volumes
      ;;
    sensitive-seccomp)
      check_prereqs
      sensitive_seccomp
      ;;
    sensitive-selinux)
      check_prereqs
      sensitive_selinux
      ;;
    container-security-report)
      check_prereqs
      container_security_report
      ;;
    help)
      show_usage
      ;;
    *)
      echo -e "${RED}Error: Unknown command: $COMMAND${NC}"
      show_usage
      exit 1
      ;;
  esac
}

# Execute main function with all arguments
main "$@"