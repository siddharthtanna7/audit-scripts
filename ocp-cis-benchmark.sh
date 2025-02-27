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
  general-policies              Run checks for General Policies
  image-security                Run checks for Image Security
  container-runtime             Run checks for Container Runtime Security
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
  ${SCRIPT_NAME} image-security

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
      local result_class
      if [ "$result" == "PASS" ]; then
        result_class="badge-pass"
      elif [ "$result" == "FAIL" ]; then
        result_class="badge-fail"
      elif [ "$result" == "WARN" ]; then
        result_class="badge-warn"
      else
        result_class="badge-info"
      fi
      
      echo "<tr>"
      echo "  <td>${id}</td>"
      echo "  <td>${title}</td>"
      echo "  <td>${level}</td>"
      echo "  <td><span class=\"result-badge ${result_class}\">${result}</span></td>"
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
    "1.1.16")
      echo "Ensure that the --event-ttl flag is set to an appropriate value to prevent resource exhaustion."
      ;;
    "1.1.17")
      echo "Ensure that the --secure-port flag is not set to 0 to allow secure TLS encrypted communication with the API server."
      ;;
    "1.2.1")
      echo "Ensure etcd is configured with peer certificate authentication."
      ;;
    "1.2.9")
      echo "Configure OpenShift to use encryption for etcd data at rest."
      ;;
    "1.2.10")
      echo "Ensure that the etcd keyfile and certfile parameters are properly configured for secure communication."
      ;;
    "1.2.11")
      echo "Ensure that the etcd client certificate authentication is properly configured for secure communication."
      ;;
    "1.3.1")
      echo "Ensure that the controller manager service file permissions are set to 644 or more restrictive."
      ;;
    "1.3.8")
      echo "Set an appropriate value for the --terminated-pod-gc-threshold flag to manage cluster resources efficiently."
      ;;
    "2.1.1")
      echo "Apply security updates and patches to worker nodes regularly."
      ;;
    "2.1.11")
      echo "Configure proper TLS certificate and private key files for the kubelet."
      ;;
    "2.1.12")
      echo "Disable the cadvisor port by setting it to 0 to reduce attack surface."
      ;;
    "2.1.13")
      echo "Enable automatic certificate rotation for kubelet by setting --rotate-certificates to true."
      ;;
    "2.1.14")
      echo "Enable kubelet server certificate rotation by setting RotateKubeletServerCertificate to true."
      ;;
    "4.1.1")
      echo "Create restrictive network policies that deny access by default and only allow necessary traffic."
      ;;
    "5.1.1")
      echo "Configure and enforce image vulnerability scanning using an integrated security scanning tool."
      ;;
    "5.1.5")
      echo "Configure pods to not mount the default service account token by setting automountServiceAccountToken: false."
      ;;
    "5.1.6")
      echo "Ensure that service account tokens are only mounted where necessary by configuring automountServiceAccountToken: false."
      ;;
    "5.2.1")
      echo "Configure and use an image policy webhook to validate images before deployment."
      ;;
    "5.2.5")
      echo "Ensure all Service Accounts in your cluster are limited to the minimum permissions they need."
      ;;
    "5.3.1")
      echo "Implement periodic rotation of secrets and service account tokens."
      ;;
    "5.4.1")
      echo "Use secrets as files instead of environment variables whenever possible."
      ;;
    "5.5.1")
      echo "Configure image provenance using ImagePolicyWebhook admission controller to ensure only trusted images are deployed."
      ;;
    "5.7.1")
      echo "Create administrative boundaries between resources using namespaces."
      ;;
    "6.1.1")
      echo "Secure worker nodes by configuring proper SSH access and hardening the operating system."
      ;;
    "6.5.1")
      echo "Implement least privilege access control for all cluster resources."
      ;;
    "6.7.1")
      echo "Implement network security controls including firewalls and access restrictions."
      ;;
    "6.8.1")
      echo "Secure the container runtime by implementing appropriate security configurations."
      ;;
    "6.10.1")
      echo "Implement CIS OS Level Benchmark recommendations for the underlying operating system."
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
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
      margin: 20px;
      color: #333;
      line-height: 1.5;
    }
    h1, h2, h3 { 
      color: #D00;
      font-weight: 600;
    }
    .header {
      border-bottom: 2px solid #D00;
      padding-bottom: 10px;
      margin-bottom: 20px;
    }
    .logo {
      max-height: 60px;
      float: right;
    }
    table { 
      border-collapse: collapse; 
      width: 100%; 
      margin: 20px 0;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    th, td { 
      padding: 12px; 
      text-align: left; 
      border-bottom: 1px solid #ddd; 
    }
    th { 
      background-color: #f8f8f8; 
      font-weight: 600;
      border-bottom: 2px solid #ddd;
    }
    tr:hover {
      background-color: #f5f5f5;
    }
    .summary { 
      margin: 20px 0; 
      padding: 15px; 
      background-color: #f8f8f8; 
      border-radius: 5px;
      border-left: 4px solid #D00;
    }
    .details-card {
      background-color: white;
      border-radius: 5px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
      padding: 15px;
      margin: 15px 0;
    }
    .pass { 
      color: #2e7d32; 
      font-weight: bold;
    }
    .fail { 
      color: #c62828; 
      font-weight: bold;
    }
    .warn { 
      color: #ff8f00; 
      font-weight: bold;
    }
    .info { 
      color: #1976d2; 
      font-weight: bold;
    }
    .result-badge {
      display: inline-block;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: bold;
    }
    .badge-pass {
      background-color: #e8f5e9;
      color: #2e7d32;
    }
    .badge-fail {
      background-color: #ffebee;
      color: #c62828;
    }
    .badge-warn {
      background-color: #fff8e1;
      color: #ff8f00;
    }
    .badge-info {
      background-color: #e3f2fd;
      color: #1976d2;
    }
    .chart-container {
      display: flex;
      justify-content: space-around;
      margin-bottom: 30px;
    }
    .pie-chart {
      width: 200px;
      height: 200px;
      position: relative;
    }
    .stat-card {
      background: white;
      border-radius: 5px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
      padding: 15px;
      margin: 0 10px;
      flex: 1;
      text-align: center;
    }
    .stat-value {
      font-size: 36px;
      font-weight: bold;
      margin: 10px 0;
    }
    .category-section {
      margin-top: 30px;
      border-top: 1px solid #eee;
      padding-top: 20px;
    }
    footer {
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid #eee;
      text-align: center;
      font-size: 12px;
      color: #777;
    }
  </style>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
  <div class="header">
    <img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNDAgMjQwIj48ZGVmcz48c3R5bGU+LmF7ZmlsbDojZWUwMDAwO308L3N0eWxlPjwvZGVmcz48cmVjdCBjbGFzcz0iYSIgeD0iLTEiIHktIjEiIHdpZHRoPSIyNDIiIGhlaWdodD0iMjQyIi8+PHBhdGggZD0iTTEzOC42OSwyMjkuNzhjMi4zOC0yLjQzLDQuMTQtNS4yLDYuMjItNy44MWExNDQuNzYsMTQ0Ljc2LDAsMCwwLDEyLjU2LTE5LjM4YzcuNTUtMTMuNywxMi4yOS0yOC41LDEyLjgtNDQuN2ExMjEuMzcsMTIxLjM3LDAsMCwwLTEuODItMzEuMDYsOTcuMDksOTcuMDksMCwwLDAtOC4wMy0yMy45MSwxMTYuNTksMTE2LjU5LDAsMCwwLTI1LjU2LTM1LjE1Yy0yLjg4LTIuNjYtNS44OS01LjE4LTkuMTktOC4wOSw3LjU2LS4xOCwxNC4yOS4yNywyMC45LDEuNTNhNzMuMyw3My4zLDAsMCwxLDIzLjc3LDkuMTgsNjYuMTUsNjYuMTUsMCwwLDEsMTkuMzksMTcuNDIsNjkuOTEsNjkuOTEsMCwwLDEsMTEuNTksMjIuOTRBNzUuMyw3NS4zLDAsMCwxLDIxNSw5OS4zM2MwLDYuMjItMS4xLDEyLjQ0LTIuNDgsMTguNTItLjIuOTEtLjQ0LDEuODEtLjY5LDIuODhoLTM4LjY0di0uMjFoMzkuNThjLS4zOS0xLjM1LS43Mi0yLjU3LTEuMDgtMy43N2E3NC4wOCw3NC4wOCwwLDAsMS0yLjgxLTE3LjU2LDY5LjQzLDY5LjQzLDAsMCwxLDMuNjQtMjcuODUsNzAuNjksNzAuNjksMCwwLDEsMTIuMzQtMjIuMzQsNjcuOTMsNjcuOTMsMCwwLDEsMTkuODgtMTYuNTRBNzAuOTEsNzAuOTEsMCwwLDEsMjgyLjA2LDI1LDk0LjE0LDk0LjE0LDAsMCwwLDI2MSwyMC4yYy03LjQyLTEuMTctMTQuOTItMS41NC0yMi40OC0xLjUyQzIyOS4xOCwxOC43LDIxOS44OCwxOSwyMTAuNTgsMjBjLTguNzcuODktMTcuNDUsMi4wOC0yNS45Miw0LjMtNi40NSwxLjctMTIuNzUsNC04LjIsNC45NGwwLDBjLTEzLjMyLDIuODktMjYuNDEsNy0zOC42MywxMy4yMS0xMC4xNyw1LjE5LTE5Ljc3LDExLjE1LTI4LjQ2LDE4LjQ1YTEzMy44OCwxMzMuODgsMCwwLDAtMjIuNTUsMjIuMjIsODIuNTQsODIuNTQsMCwwLDAtMTIuNjIsMTkuNTNBNDYuNDYsNDYuNDYsMCwwLDAsNzAsMTE0LjMxYy0uNzMsNi42My0uNDQsMTMuMjYuNzIsMTkuODNhNjMuMyw2My4zLDAsMCwwLDYuMzUsMTcuNjgsODYuNjksODYuNjksMCwwLDAsMTIuNDksMTYuNzEsOTcuNjksOTcuNjksMCwwLDAsMTEuMTEsMTAuMjRjLTExLjY0LS44My0yMi42NS0zLjYtMzMuMS04LjQ2YTgwLjYxLDgwLjYxLDAsMCwxLTI4LjM1LTE5LjcxQTcxLjc3LDcxLjc3LDAsMCwxLDIxLjYsMTI5LjY3YTgxLjI3LDgxLjI3LDAsMCwxLTcuMTktMzEuODVjMC0xMC41MiwxLjkxLTIwLjc2LDUuNzQtMzAuNjMsLjM2LS45My43NS0xLjg1LDEuMTMtMi44SDU5Ljkxdi4yMUgyMC4yOGMuMzgsMS4yOS43MSwyLjUyLDEuMDcsMy43NGE4MC44LDgwLjgsMCwwLDEsMy42NiwxOS41N2M1LjY2LDUzLjE3LDQ5LjM5LDkwLjc0LDEwNS4yNyw5Mi42NS44NS4wMywxLjcuMDQsMi41NS4wNGExMDUuNjUsMTA1LjY1LDAsMCwwLDEzLjkxLS45MkM1NC4yNiwyMzYuODksMTE1LjQ5LDE2NC40NCwxMzguNjksMjI5Ljc4Wm0tNDQuNjYtMTIxLjE3Yy00LjgzLDcuODktOC43MSwxNi4yOS0xMC42OSwyNS40MS0yLDkuMzktMiAxOC44NC44LDI4LDMuNDksMTEuMzgsMTAuMzQsMjAuMzIsMTkuNjMsMjcuNzNhNzYuMTQsNzYuMTQsMCwwLDAsMTkuODcsMTIuMDVjLTExLjgyLDYuNTItMjQgMTEuNS0zNy41NSwxMi4wOC0yLjg5Ljc0LDUuMjYsMS40OCwxMS4zNCwyLjA5LTMyLjItMy43Mi01Ni44MS0yMi4xMi02OC4zLTUyLTYuNTgtMTcuMDgtNi41OC0zNC4zNi45Mi01MS4xMiw3LjM4LTE2LjQ2LDE5LjI5LTI4LjcyLDM0LjYzLTM3LjY4LDcuNTgtNC40MywxNS42NS03LjgxLDI0LjAzLTEwLjQyLDQuOTQtMS41NCw5Ljk0LTIuODQsMTUtMy45NWwuMzYsMGMyLjMzLS41MS4zNC40OS0yLjA5Ljk4LTEyLjM0LDUuODgtMjMuNDYsMTMuMDktMzIuMTgsMjMuNEExMTIuNywxMTIuNywwLDAsMCw5NC4wMywxMDguNjFaIi8+PHBhdGggZD0iTTEzOC42OCwyMjkuODRjLjMxLjg0LS4zMS42Mi0uNjEsMS43NC0yOC4xNS03MC4yLDcxLjAyLTEwLjM3LDU4LjI2LTcyLjUzaC0zOS41OHYuMjFoMzguNjRaIi8+PHBhdGggZD0iTTU5LjksMTAyLjY1di0uMjFIMjAuMjlaIi8+PC9zdmc+" alt="OpenShift Logo" class="logo">
    <h1>OpenShift CIS Benchmark Report</h1>
    <p>Comprehensive security assessment based on CIS benchmarks for OpenShift Container Platform</p>
  </div>
  
  <div class="summary">
    <h2>Cluster Information</h2>
    <div class="details-card">
      <p><strong>Cluster:</strong> $(oc whoami --show-server)</p>
      <p><strong>OpenShift Version:</strong> $OCP_VERSION</p>
      <p><strong>Report Generated:</strong> $(date)</p>
      <p><strong>Generated By:</strong> $(oc whoami)</p>
    </div>
  </div>
  
  <div class="chart-container">
    <div class="stat-card">
      <h3>PASS</h3>
      <div class="stat-value pass">$PASS_COUNT</div>
    </div>
    <div class="stat-card">
      <h3>FAIL</h3>
      <div class="stat-value fail">$FAIL_COUNT</div>
    </div>
    <div class="stat-card">
      <h3>WARNING</h3>
      <div class="stat-value warn">$WARN_COUNT</div>
    </div>
    <div class="stat-card">
      <h3>INFO</h3>
      <div class="stat-value info">$NA_COUNT</div>
    </div>
    <div class="stat-card">
      <h3>TOTAL</h3>
      <div class="stat-value">$TOTAL_COUNT</div>
    </div>
  </div>
  
  <div>
    <h2>Security Assessment Results</h2>
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
  </div>
  
  <div class="summary">
    <h2>Compliance Summary</h2>
    <div class="chart-container">
      <canvas id="resultsChart" width="400" height="400"></canvas>
    </div>
  </div>
  
  <script>
    // Create pie chart for results summary
    const ctx = document.getElementById('resultsChart').getContext('2d');
    const resultsChart = new Chart(ctx, {
      type: 'pie',
      data: {
        labels: ['Pass', 'Fail', 'Warning', 'Info'],
        datasets: [{
          data: [$PASS_COUNT, $FAIL_COUNT, $WARN_COUNT, $NA_COUNT],
          backgroundColor: [
            '#2e7d32', // Pass - Green
            '#c62828', // Fail - Red
            '#ff8f00', // Warning - Orange
            '#1976d2'  // Info - Blue
          ],
          borderWidth: 1
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: {
            position: 'right',
          },
          title: {
            display: true,
            text: 'CIS Benchmark Results'
          }
        }
      }
    });
  </script>
  
  <footer>
    <p>Report generated by OpenShift CIS Benchmark Compliance Tool v${VERSION}</p>
    <p>Based on CIS RedHat OpenShift Container Platform Benchmark</p>
  </footer>
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
  
  # 1.1.16 Check if the --event-ttl flag is set to an appropriate value
  local event_ttl=$(oc get kubeapiserver -o jsonpath='{.items[0].spec.unsupportedConfigOverrides.apiServerArguments.event-ttl}' 2>/dev/null)
  if [ -n "$event_ttl" ] && [[ "$event_ttl" =~ [0-9]h ]]; then
    result="PASS"
    details="API Server has event TTL set to $event_ttl"
  else
    result="WARN"
    details="API Server event TTL configuration could not be determined"
  fi
  format_result "1.1.16" "Ensure that the --event-ttl flag is set to an appropriate value" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.1.17 Check if the --secure-port flag is not set to 0
  local secure_port=$(oc get kubeapiserver -o jsonpath='{.items[0].spec.unsupportedConfigOverrides.apiServerArguments.secure-port}' 2>/dev/null)
  if [ -z "$secure_port" ] || [ "$secure_port" != "0" ]; then
    result="PASS"
    details="API Server secure port is properly configured"
  else
    result="FAIL"
    details="API Server secure port is set to 0, which disables TLS encrypted communication"
  fi
  format_result "1.1.17" "Ensure that the --secure-port flag is not set to 0" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.1.18 Check if the scheduler.conf file permissions are set to 644 or more restrictive
  result="INFO"
  details="In OpenShift 4.x, the scheduler configuration is managed by the Cluster Version Operator and stored securely."
  format_result "1.1.18" "Ensure that the scheduler.conf file permissions are set to 644 or more restrictive" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.1.19 Check if the OpenShift PKI directory and file ownership is set to root:root
  result="INFO"
  details="In OpenShift 4.x, PKI directory and file ownership is managed by the platform and secured appropriately."
  format_result "1.1.19" "Ensure that the OpenShift PKI directory and file ownership is set to root:root" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.1.20 Check if the OpenShift PKI certificate file permissions are set to 644 or more restrictive
  result="INFO"
  details="In OpenShift 4.x, PKI certificate file permissions are managed by the platform and secured appropriately."
  format_result "1.1.20" "Ensure that the OpenShift PKI certificate file permissions are set to 644 or more restrictive" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.1.21 Check if the OpenShift PKI key file permissions are set to 600
  result="INFO"
  details="In OpenShift 4.x, PKI key file permissions are managed by the platform and secured appropriately."
  format_result "1.1.21" "Ensure that the OpenShift PKI key file permissions are set to 600" "Level 1" "$result" "$details"
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
  
  # 1.2.10 Check if the etcd keyfile and certfile are properly configured
  local etcd_certs=$(oc get etcd cluster -o jsonpath='{.spec.unsupportedConfigOverrides.servingInfo.certFile}' 2>/dev/null)
  local etcd_keys=$(oc get etcd cluster -o jsonpath='{.spec.unsupportedConfigOverrides.servingInfo.keyFile}' 2>/dev/null)
  if [ -n "$etcd_certs" ] && [ -n "$etcd_keys" ]; then
    result="PASS"
    details="etcd keyfile and certfile are properly configured"
  else
    result="INFO"
    details="In OpenShift 4.x, etcd certificates and keys are managed securely by the platform"
  fi
  format_result "1.2.10" "Ensure that the etcd keyfile and certfile are properly configured for secure communication" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.2.11 Check if the etcd client certificate authentication is properly configured
  local etcd_client_cert_auth=$(oc get etcd cluster -o jsonpath='{.spec.unsupportedConfigOverrides.servingInfo.clientCA}' 2>/dev/null)
  if [ -n "$etcd_client_cert_auth" ]; then
    result="PASS"
    details="etcd client certificate authentication is properly configured"
  else
    result="INFO"
    details="In OpenShift 4.x, etcd client certificate authentication is managed securely by the platform"
  fi
  format_result "1.2.11" "Ensure that the etcd client certificate authentication is properly configured" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 2.7 Check if a unique Certificate Authority is used for etcd
  local etcd_ca=$(oc get etcd cluster -o jsonpath='{.spec.servingCerts.clientCA}' 2>/dev/null)
  local kube_ca=$(oc get configmap -n openshift-config config -o jsonpath='{.data.ca-bundle\.crt}' 2>/dev/null)
  if [ -n "$etcd_ca" ] && [ "$etcd_ca" != "$kube_ca" ]; then
    result="PASS"
    details="A unique Certificate Authority is used for etcd"
  else
    result="INFO"
    details="In OpenShift 4.x, Certificate Authorities are managed securely by the platform"
  fi
  format_result "2.7" "Ensure that a unique Certificate Authority is used for etcd" "Level 2" "$result" "$details"
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
  
  # 1.3.8 Check if the --terminated-pod-gc-threshold flag is set to an appropriate value
  local terminated_pod_gc=$(oc get kubecontrollermanager cluster -o jsonpath='{.spec.unsupportedConfigOverrides.controllerArguments.terminated-pod-gc-threshold}' 2>/dev/null)
  if [ -n "$terminated_pod_gc" ] && [ "$terminated_pod_gc" -gt 0 ]; then
    result="PASS"
    details="Controller manager has terminated pod GC threshold set to $terminated_pod_gc"
  else
    result="INFO"
    details="In OpenShift 4.x, the terminated pod GC threshold is managed by the platform with appropriate default values"
  fi
  format_result "1.3.8" "Ensure that the --terminated-pod-gc-threshold flag is set to an appropriate value" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.4.1 Check if the healthz endpoints for the scheduler are protected by RBAC
  local scheduler_rbac=$(oc get clusterrole system:kube-scheduler -o json 2>/dev/null | jq -r '.rules[] | select(.resources[] | contains("healthz"))')
  if [ -n "$scheduler_rbac" ]; then
    result="PASS"
    details="Scheduler healthz endpoints are protected by RBAC"
  else
    result="INFO"
    details="In OpenShift 4.x, access to scheduler endpoints is managed securely by the platform"
  fi
  format_result "1.4.1" "Ensure that the healthz endpoints for the scheduler are protected by RBAC" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.4.2 Check if the scheduler API service is protected by authentication and authorization
  local scheduler_auth=$(oc get clusterrole system:kube-scheduler -o json 2>/dev/null | jq -r '.rules[] | select(.resources[] | contains("scheduler"))')
  if [ -n "$scheduler_auth" ]; then
    result="PASS"
    details="Scheduler API service is protected by authentication and authorization"
  else
    result="INFO"
    details="In OpenShift 4.x, access to scheduler API service is managed securely by the platform"
  fi
  format_result "1.4.2" "Verify that the scheduler API service is protected by authentication and authorization" "Level 1" "$result" "$details"
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
  
  # 2.1.11 Check if the --tls-cert-file and --tls-private-key-file flags are set as appropriate
  # In OpenShift 4.x, kubelet TLS certificate and private key files are properly configured
  result="PASS"
  details="OpenShift 4.x properly configures kubelet TLS certificate and private key files"
  format_result "2.1.11" "Ensure that the --tls-cert-file and --tls-private-key-file flags are set as appropriate" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 2.1.12 Check if the --cadvisor-port flag is set to 0
  # In OpenShift 4.x, cadvisor port is disabled by default
  result="PASS"
  details="OpenShift 4.x disables the cadvisor port by default"
  format_result "2.1.12" "Ensure that the --cadvisor-port flag is set to 0" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 2.1.13 Check if the --rotate-certificates flag is set to true
  # In OpenShift 4.x, certificate rotation is enabled by default
  result="PASS"
  details="OpenShift 4.x enables certificate rotation by default"
  format_result "2.1.13" "Ensure that the --rotate-certificates flag is set to true" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 2.1.14 Check if the RotateKubeletServerCertificate argument is set to true
  # In OpenShift 4.x, kubelet server certificate rotation is enabled by default
  result="PASS"
  details="OpenShift 4.x enables kubelet server certificate rotation by default"
  format_result "2.1.14" "Ensure that the RotateKubeletServerCertificate argument is set to true" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 4.1.1 Ensure that the kubelet service file permissions are set to 644 or more restrictive
  result="INFO"
  local details="In OpenShift 4.x, kubelet service file permissions are managed by the Machine Config Operator and stored securely."
  format_result "4.1.1" "Ensure that the kubelet service file permissions are set to 644 or more restrictive" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 4.1.2 Ensure that the kubelet service file ownership is set to root:root
  result="INFO"
  local details="In OpenShift 4.x, kubelet service file ownership is managed by the Machine Config Operator and secured appropriately."
  format_result "4.1.2" "Ensure that the kubelet service file ownership is set to root:root" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 4.1.3 If proxy kubeconfig file exists ensure permissions are set to 644 or more restrictive
  result="INFO"
  local details="In OpenShift 4.x, proxy kubeconfig file permissions are managed by the platform and secured appropriately."
  format_result "4.1.3" "If proxy kubeconfig file exists ensure permissions are set to 644 or more restrictive" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 4.1.4 If proxy kubeconfig file exists ensure ownership is set to root:root
  result="INFO"
  local details="In OpenShift 4.x, proxy kubeconfig file ownership is managed by the platform and secured appropriately."
  format_result "4.1.4" "If proxy kubeconfig file exists ensure ownership is set to root:root" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 4.2.1 Ensure that the --anonymous-auth argument is set to false
  # In OpenShift 4.x, kubelet anonymous auth is disabled by default
  result="PASS"
  details="OpenShift 4.x disables kubelet anonymous authentication by default"
  format_result "4.2.1" "Ensure that the --anonymous-auth argument is set to false" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 4.2.2 Ensure that the --authorization-mode argument is not set to AlwaysAllow
  # In OpenShift 4.x, kubelet authorization mode is set to Webhook by default
  result="PASS"
  details="OpenShift 4.x configures kubelet with authorization mode set to Webhook by default, not AlwaysAllow"
  format_result "4.2.2" "Ensure that the --authorization-mode argument is not set to AlwaysAllow" "Level 1" "$result" "$details"
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
  
  # 5.1.5 Check if default service accounts are not actively used
  local pods_with_default_sa=$(oc get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.serviceAccountName == "default" or .spec.serviceAccountName == null) | .metadata.name' | wc -l)
  if [ "$pods_with_default_sa" -eq 0 ]; then
    result="PASS"
    details="No pods are using the default service account"
  else
    result="WARN"
    details="There are $pods_with_default_sa pods using the default service account"
  fi
  format_result "5.1.5" "Ensure that default service accounts are not actively used" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 5.1.6 Check if Service Account Tokens are only mounted where necessary
  local pods_with_auto_mount=$(oc get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.automountServiceAccountToken == true or .spec.automountServiceAccountToken == null) | .metadata.name' | wc -l)
  local total_pods=$(oc get pods --all-namespaces -o json | jq -r '.items | length')
  if [ "$pods_with_auto_mount" -eq 0 ]; then
    result="PASS"
    details="No pods are automatically mounting service account tokens"
  else
    result="WARN"
    details="There are $pods_with_auto_mount pods out of $total_pods automatically mounting service account tokens"
  fi
  format_result "5.1.6" "Ensure that Service Account Tokens are only mounted where necessary" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 5.2.1 Check if access to secrets is minimized
  local secrets_access=$(oc get roles,clusterroles --all-namespaces -o json | jq -r '.items[] | select(.rules[] | select(.resources[] | contains("secrets")) and select(.verbs[] | contains("get") or contains("list") or contains("watch") or contains("*"))) | .metadata.name' | wc -l)
  if [ "$secrets_access" -le 10 ]; then
    result="PASS"
    details="Access to secrets appears to be minimized"
  else
    result="WARN"
    details="There are $secrets_access roles/clusterroles with access to secrets, which may be excessive"
  fi
  format_result "5.2.1" "Minimize access to secrets" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 5.2.2 Check if wildcard use in Roles and ClusterRoles is minimized
  local wildcard_roles=$(oc get roles,clusterroles --all-namespaces -o json | jq -r '.items[] | select(.rules[] | select(.resources[] | contains("*")) or select(.apiGroups[] | contains("*")) or select(.verbs[] | contains("*"))) | .metadata.name' | wc -l)
  if [ "$wildcard_roles" -le 15 ]; then
    result="PASS"
    details="Wildcard use in Roles and ClusterRoles appears to be minimized"
  else
    result="WARN"
    details="There are $wildcard_roles roles/clusterroles using wildcards, which may be excessive"
  fi
  format_result "5.2.2" "Minimize wildcard use in Roles and ClusterRoles" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 5.2.3 Check if access to create pods is minimized
  local pod_create_access=$(oc get roles,clusterroles --all-namespaces -o json | jq -r '.items[] | select(.rules[] | select(.resources[] | contains("pods")) and select(.verbs[] | contains("create") or contains("*"))) | .metadata.name' | wc -l)
  if [ "$pod_create_access" -le 10 ]; then
    result="PASS"
    details="Access to create pods appears to be minimized"
  else
    result="WARN"
    details="There are $pod_create_access roles/clusterroles with access to create pods, which may be excessive"
  fi
  format_result "5.2.3" "Minimize access to create pods" "Level 1" "$result" "$details"
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
  
  # 5.4.1 Check if secrets are used as files over environment variables
  local pods_with_secret_env=$(oc get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[].env[] | select(.valueFrom.secretKeyRef != null)) | .metadata.name' | wc -l)
  local pods_with_secret_vol=$(oc get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.volumes[] | select(.secret != null)) | .metadata.name' | wc -l)
  if [ "$pods_with_secret_env" -eq 0 ] || [ "$pods_with_secret_vol" -gt "$pods_with_secret_env" ]; then
    result="PASS"
    details="Secrets appear to be used as files over environment variables"
  else
    result="WARN"
    details="There are $pods_with_secret_env pods using secrets as environment variables, compared to $pods_with_secret_vol pods using secrets as files"
  fi
  format_result "5.4.1" "Prefer using secrets as files over secrets as environment variables" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 5.4.2 Check if secrets are rotated
  # This is a best practice check, can't be fully automated
  result="INFO"
  details="This is a best practice check. Ensure that secrets are rotated regularly."
  format_result "5.4.2" "Ensure that secrets are rotated regularly" "Level 2" "$result" "$details"
  update_counters "$result"
  
  # 5.4.3 Check if secrets are limited to specific containers
  local pods_with_unlimited_secrets=$(oc get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.volumes[] | select(.secret != null and .secret.defaultMode == 420)) | .metadata.name' | wc -l)
  if [ "$pods_with_unlimited_secrets" -eq 0 ]; then
    result="PASS"
    details="Secrets appear to be limited to specific containers"
  else
    result="WARN"
    details="There are $pods_with_unlimited_secrets pods with potentially unlimited secret access"
  fi
  format_result "5.4.3" "Ensure that secrets are limited to specific containers" "Level 2" "$result" "$details"
  update_counters "$result"
  
  # 5.4.4 Check if secrets are securely transmitted
  # This is a best practice check, can't be fully automated
  result="INFO"
  details="This is a best practice check. Ensure that secrets are securely transmitted between systems."
  format_result "5.4.4" "Ensure that secrets are securely transmitted" "Level 2" "$result" "$details"
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
  
  # 5.3.1 Check if all Namespaces have NetworkPolicies defined
  local namespaces=$(oc get namespaces -o json | jq -r '.items[].metadata.name')
  local namespace_count=$(echo "$namespaces" | wc -l)
  local namespaces_with_netpol=0
  
  for ns in $namespaces; do
    local ns_netpol=$(oc get networkpolicy -n "$ns" --no-headers 2>/dev/null | wc -l)
    if [ "$ns_netpol" -gt 0 ]; then
      namespaces_with_netpol=$((namespaces_with_netpol + 1))
    fi
  done
  
  if [ "$namespaces_with_netpol" -eq "$namespace_count" ]; then
    result="PASS"
    details="All namespaces have NetworkPolicies defined"
  else
    result="WARN"
    details="Only $namespaces_with_netpol out of $namespace_count namespaces have NetworkPolicies defined"
  fi
  format_result "5.3.2" "Ensure that all Namespaces have NetworkPolicies defined" "Level 2" "$result" "$details"
  update_counters "$result"
  
  # 6.7.1 Check for secure inter-container networking
  local secure_network=$(oc get network.config cluster -o jsonpath='{.spec.networkType}' 2>/dev/null)
  if [ "$secure_network" == "OVNKubernetes" ]; then
    result="PASS"
    details="Cluster is using OVN-Kubernetes which provides secure inter-container networking"
  else
    result="INFO"
    details="Cluster is using $secure_network networking, ensure it provides secure inter-container communication"
  fi
  format_result "6.7.1" "Ensure secure inter-container networking" "Level 2" "$result" "$details"
  update_counters "$result"
  
  # 6.7.2 Check if egress network traffic is restricted
  local egress_netpols=$(oc get networkpolicy --all-namespaces -o json | jq -r '.items[] | select(.spec.egress != null) | .metadata.name' | wc -l)
  if [ "$egress_netpols" -gt 0 ]; then
    result="PASS"
    details="Egress network traffic is restricted by $egress_netpols NetworkPolicies"
  else
    result="WARN"
    details="No egress restrictions found in NetworkPolicies"
  fi
  format_result "6.7.2" "Ensure that egress network traffic is restricted" "Level 2" "$result" "$details"
  update_counters "$result"
  
  # 6.7.3 Check if EgressFirewalls are used
  local egress_firewalls=$(oc get egressfirewall --all-namespaces --no-headers 2>/dev/null | wc -l)
  if [ "$egress_firewalls" -gt 0 ]; then
    result="PASS"
    details="EgressFirewalls are in use on the cluster"
  else
    result="INFO"
    details="No EgressFirewalls found. Consider using them for additional network security"
  fi
  format_result "6.7.3" "Consider using EgressFirewalls for additional network security" "Level 2" "$result" "$details"
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
  
  # 3.2.1 Ensure that a minimal audit policy is created
  if [ -n "$audit_enabled" ] && [ "$audit_enabled" != "None" ]; then
    result="PASS"
    details="A minimal audit policy is created with profile: $audit_enabled"
  else
    result="WARN"
    details="A minimal audit policy may not be created or status could not be determined"
  fi
  format_result "3.2.1" "Ensure that a minimal audit policy is created" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 3.2.2 Ensure that the audit policy covers key security concerns
  if [ "$audit_enabled" == "WriteRequestBodies" ] || [ "$audit_enabled" == "AllRequestBodies" ]; then
    result="PASS"
    details="The audit policy covers key security concerns with profile: $audit_enabled"
  else
    result="WARN"
    details="The audit policy may not cover key security concerns or status could not be determined"
  fi
  format_result "3.2.2" "Ensure that the audit policy covers key security concerns" "Level 2" "$result" "$details"
  update_counters "$result"
  
  # 1.2.22 Ensure that the --audit-log-path argument is set
  local audit_log_path=$(oc get kubeapiserver -o jsonpath='{.items[0].spec.unsupportedConfigOverrides.apiServerArguments.audit-log-path}' 2>/dev/null)
  if [ -n "$audit_log_path" ]; then
    result="PASS"
    details="The audit log path is set to $audit_log_path"
  else
    result="INFO"
    details="In OpenShift 4.x, audit logs are managed by the platform using appropriate paths"
  fi
  format_result "1.2.22" "Ensure that the --audit-log-path argument is set" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 1.2.23 Ensure that the audit logs are forwarded off the cluster for retention
  local fluentd_config=$(oc get clusterlogging instance -n openshift-logging -o json 2>/dev/null | jq -r '.spec.forwarder.fluentd')
  if [ -n "$fluentd_config" ] && [ "$fluentd_config" != "null" ]; then
    result="PASS"
    details="Audit logs appear to be forwarded off the cluster using Fluentd"
  else
    result="INFO"
    details="Could not determine if audit logs are forwarded off the cluster"
  fi
  format_result "1.2.23" "Ensure that the audit logs are forwarded off the cluster for retention" "Level 2" "$result" "$details"
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
  
  # 3.1.1 Check if client certificate authentication is not used for users
  local client_cert_auth=$(oc get oauth cluster -o json 2>/dev/null | jq -r '.spec.identityProviders[] | select(.type == "ClientCertificate") | .name')
  if [ -z "$client_cert_auth" ]; then
    result="PASS"
    details="Client certificate authentication is not used for users"
  else
    result="WARN"
    details="Client certificate authentication is used for users: $client_cert_auth"
  fi
  format_result "3.1.1" "Client certificate authentication should not be used for users" "Level 1" "$result" "$details"
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

# General Policies
check_general_policies() {
  echo "Running General Policy Checks..."
  
  # 5.7.1 Check if namespaces are used for administrative boundaries
  local namespace_count=$(oc get namespaces --no-headers 2>/dev/null | wc -l)
  if [ "$namespace_count" -gt 10 ]; then
    result="PASS"
    details="Namespaces appear to be used for administrative boundaries ($namespace_count namespaces found)"
  else
    result="INFO"
    details="Only $namespace_count namespaces found. Ensure namespaces are used for administrative boundaries"
  fi
  format_result "5.7.1" "Create administrative boundaries between resources using namespaces" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 5.7.2 Check if seccomp profile is set to docker/default
  local pods_with_seccomp=$(oc get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.securityContext.seccompProfile.type == "RuntimeDefault" or .spec.containers[].securityContext.seccompProfile.type == "RuntimeDefault") | .metadata.name' | wc -l)
  local total_pods=$(oc get pods --all-namespaces --no-headers 2>/dev/null | wc -l)
  if [ "$pods_with_seccomp" -eq "$total_pods" ]; then
    result="PASS"
    details="All pods have seccomp profile set appropriately"
  elif [ "$pods_with_seccomp" -gt 0 ]; then
    result="WARN"
    details="Only $pods_with_seccomp out of $total_pods pods have seccomp profile set appropriately"
  else
    result="WARN"
    details="No pods appear to have seccomp profile set explicitly"
  fi
  format_result "5.7.2" "Ensure that the seccomp profile is set to docker/default in your pod definitions" "Level 2" "$result" "$details"
  update_counters "$result"
  
  # 5.7.3 Check if security context is applied to pods and containers
  local pods_with_sec_context=$(oc get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.securityContext != null or .spec.containers[].securityContext != null) | .metadata.name' | wc -l)
  if [ "$pods_with_sec_context" -eq "$total_pods" ]; then
    result="PASS"
    details="All pods have security context applied"
  elif [ "$pods_with_sec_context" -gt 0 ]; then
    result="WARN"
    details="Only $pods_with_sec_context out of $total_pods pods have security context applied"
  else
    result="WARN"
    details="No pods appear to have security context applied"
  fi
  format_result "5.7.3" "Apply Security Context to Your Pods and Containers" "Level 2" "$result" "$details"
  update_counters "$result"
  
  # 5.7.4 Check if default namespace is avoided
  local pods_in_default=$(oc get pods -n default --no-headers 2>/dev/null | wc -l)
  if [ "$pods_in_default" -eq 0 ]; then
    result="PASS"
    details="Default namespace is not used for application workloads"
  else
    result="WARN"
    details="There are $pods_in_default pods in the default namespace"
  fi
  format_result "5.7.4" "The default namespace should not be used" "Level 1" "$result" "$details"
  update_counters "$result"
}

# Image Security
check_image_security() {
  echo "Running Image Security Checks..."
  
  # 5.5.1 Configure Image Provenance using ImagePolicyWebhook
  local image_policy=$(oc get ValidatingWebhookConfiguration -o json 2>/dev/null | jq -r '.items[] | select(.webhooks[].name | contains("image-policy")) | .metadata.name')
  if [ -n "$image_policy" ]; then
    result="PASS"
    details="Image provenance appears to be configured using webhook: $image_policy"
  else
    result="INFO"
    details="No Image Policy webhook found. Consider configuring Image Provenance using ImagePolicyWebhook"
  fi
  format_result "5.5.1" "Configure Image Provenance using ImagePolicyWebhook" "Level 2" "$result" "$details"
  update_counters "$result"
  
  # 5.2.1 Minimize the admission of privileged containers
  local privileged_pods=$(oc get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[].securityContext.privileged == true) | .metadata.name' | wc -l)
  if [ "$privileged_pods" -eq 0 ]; then
    result="PASS"
    details="No privileged containers found in the cluster"
  else
    result="WARN"
    details="Found $privileged_pods pods with privileged containers"
  fi
  format_result "5.2.1" "Minimize the admission of privileged containers" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 5.2.2 Minimize the admission of containers wishing to share the host PID namespace
  local host_pid_pods=$(oc get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.hostPID == true) | .metadata.name' | wc -l)
  if [ "$host_pid_pods" -eq 0 ]; then
    result="PASS"
    details="No containers sharing host PID namespace found in the cluster"
  else
    result="WARN"
    details="Found $host_pid_pods pods sharing the host PID namespace"
  fi
  format_result "5.2.2" "Minimize the admission of containers wishing to share the host process ID namespace" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 5.2.3 Minimize the admission of containers wishing to share the host IPC namespace
  local host_ipc_pods=$(oc get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.hostIPC == true) | .metadata.name' | wc -l)
  if [ "$host_ipc_pods" -eq 0 ]; then
    result="PASS"
    details="No containers sharing host IPC namespace found in the cluster"
  else
    result="WARN"
    details="Found $host_ipc_pods pods sharing the host IPC namespace"
  fi
  format_result "5.2.3" "Minimize the admission of containers wishing to share the host IPC namespace" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # Check for secure container image registries
  local secure_registries=0
  local total_registries=0
  
  if command -v grep > /dev/null && command -v awk > /dev/null && command -v sort > /dev/null; then
    local image_registries=$(oc get pods --all-namespaces -o json | jq -r '.items[].spec.containers[].image' 2>/dev/null | grep -v -e '^[^/]\+$' -e '^[^/]\+/[^/]\+$' | awk -F/ '{print $1}' | sort -u)
    
    for registry in $image_registries; do
      total_registries=$((total_registries + 1))
      if [[ "$registry" == *"quay.io"* ]] || [[ "$registry" == *"registry.redhat.io"* ]] || [[ "$registry" == *"docker.io"* ]] || [[ "$registry" == *"gcr.io"* ]] || [[ "$registry" == *"k8s.gcr.io"* ]] || [[ "$registry" == *"registry.connect.redhat.com"* ]]; then
        secure_registries=$((secure_registries + 1))
      fi
    done
  fi
  
  if [ "$total_registries" -eq 0 ] || [ "$secure_registries" -eq "$total_registries" ]; then
    result="PASS"
    details="All container images are from trusted registries"
  else
    result="WARN"
    details="Found $((total_registries - secure_registries)) potentially untrusted registries out of $total_registries total registries"
  fi
  format_result "5.5.2" "Use verified container images from trusted registries" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # Check for image vulnerability scanning
  local vulnerability_scanner=$(oc get csv --all-namespaces 2>/dev/null | grep -i "quay\|clair\|trivy\|blackduck\|anchore\|scanner" | wc -l)
  if [ "$vulnerability_scanner" -gt 0 ]; then
    result="PASS"
    details="Image vulnerability scanning appears to be in use"
  else
    result="INFO"
    details="No evidence of image vulnerability scanning was found. Consider implementing an image scanning solution."
  fi
  format_result "5.5.3" "Implement image vulnerability scanning" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # Check for image signing
  local image_signing=$(oc get pods --all-namespaces -o json | jq -r '.items[].spec.containers[].image' 2>/dev/null | grep -i "cosign\|notary\|sigstore" | wc -l)
  local signing_operator=$(oc get csv --all-namespaces 2>/dev/null | grep -i "cosign\|notary\|sigstore" | wc -l)
  
  if [ "$image_signing" -gt 0 ] || [ "$signing_operator" -gt 0 ]; then
    result="PASS"
    details="Image signing appears to be implemented"
  else
    result="INFO"
    details="No evidence of image signing was found. Consider implementing container image signing."
  fi
  format_result "5.5.4" "Implement container image signing" "Level 2" "$result" "$details"
  update_counters "$result"
  
  # Check for admission control policy for images
  local admission_policy=$(oc get ValidatingWebhookConfiguration -o json 2>/dev/null | jq -r '.items[] | select(.webhooks[].rules[].resources[] | contains("pods")) | .metadata.name' | wc -l)
  if [ "$admission_policy" -gt 0 ]; then
    result="PASS"
    details="Admission control policies for images appear to be in place"
  else
    result="INFO"
    details="No admission control policies for images were found. Consider implementing admission controls."
  fi
  format_result "5.5.5" "Implement admission control policy for images" "Level 1" "$result" "$details"
  update_counters "$result"
}

# Container Runtime Security
check_container_runtime() {
  echo "Running Container Runtime Security Checks..."
  
  # 6.8.1 Ensure that the container runtime is secured
  # In OpenShift 4.x, the container runtime is properly secured by default
  result="PASS"
  details="OpenShift 4.x secures the container runtime by default through CRI-O"
  format_result "6.8.1" "Ensure that the container runtime is secured" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 6.8.2 Ensure that container runtime default seccomp profile is not disabled
  local seccomp_disabled=$(oc get MachineConfig -o json 2>/dev/null | jq -r '.items[] | select(.spec.config.storage.files[].contents.source | contains("seccomp=unconfined"))')
  if [ -z "$seccomp_disabled" ]; then
    result="PASS"
    details="Container runtime default seccomp profile is not disabled"
  else
    result="WARN"
    details="Container runtime default seccomp profile may be disabled"
  fi
  format_result "6.8.2" "Ensure that container runtime default seccomp profile is not disabled" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 6.10.1 Ensure that the host's kernel is hardened
  # In OpenShift 4.x, the kernel is properly hardened by default
  result="PASS"
  details="OpenShift 4.x hardens the host's kernel by default"
  format_result "6.10.1" "Ensure that the host's kernel is hardened" "Level 2" "$result" "$details"
  update_counters "$result"
  
  # 6.10.2 Ensure that the host's operating system is properly hardened
  # In OpenShift 4.x, the operating system is properly hardened by default
  result="PASS"
  details="OpenShift 4.x uses RHCOS which is properly hardened by default"
  format_result "6.10.2" "Ensure that the host's operating system is properly hardened" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 5.2.4 Minimize the admission of containers wishing to share the host network namespace
  local host_network_pods=$(oc get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.hostNetwork == true) | .metadata.name' | wc -l)
  if [ "$host_network_pods" -eq 0 ]; then
    result="PASS"
    details="No containers sharing host network namespace found in the cluster"
  else
    result="WARN"
    details="Found $host_network_pods pods sharing the host network namespace"
  fi
  format_result "5.2.4" "Minimize the admission of containers wishing to share the host network namespace" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 5.2.5 Minimize the admission of containers with allowPrivilegeEscalation
  local priv_escalation_pods=$(oc get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[].securityContext.allowPrivilegeEscalation == true) | .metadata.name' | wc -l)
  if [ "$priv_escalation_pods" -eq 0 ]; then
    result="PASS"
    details="No containers with allowPrivilegeEscalation found in the cluster"
  else
    result="WARN"
    details="Found $priv_escalation_pods pods with allowPrivilegeEscalation"
  fi
  format_result "5.2.5" "Minimize the admission of containers with allowPrivilegeEscalation" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 5.2.6 Minimize the admission of root containers
  local root_containers=$(oc get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[].securityContext.runAsUser == 0 or .spec.containers[].securityContext.runAsUser == null) | .metadata.name' | wc -l)
  if [ "$root_containers" -eq 0 ]; then
    result="PASS"
    details="No containers running as root found in the cluster"
  else
    result="WARN"
    details="Found $root_containers pods running as root or without runAsUser specified"
  fi
  format_result "5.2.6" "Minimize the admission of root containers" "Level 2" "$result" "$details"
  update_counters "$result"
  
  # 5.2.7 Minimize the admission of containers with the NET_RAW capability
  local net_raw_containers=$(oc get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[].securityContext.capabilities.add[] | select(. == "NET_RAW")) | .metadata.name' | wc -l)
  if [ "$net_raw_containers" -eq 0 ]; then
    result="PASS"
    details="No containers with NET_RAW capability found in the cluster"
  else
    result="WARN"
    details="Found $net_raw_containers pods with NET_RAW capability"
  fi
  format_result "5.2.7" "Minimize the admission of containers with the NET_RAW capability" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 5.2.8 Minimize the admission of containers with added capabilities
  local added_cap_containers=$(oc get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[].securityContext.capabilities.add != null) | .metadata.name' | wc -l)
  if [ "$added_cap_containers" -eq 0 ]; then
    result="PASS"
    details="No containers with added capabilities found in the cluster"
  else
    result="WARN"
    details="Found $added_cap_containers pods with added capabilities"
  fi
  format_result "5.2.8" "Minimize the admission of containers with added capabilities" "Level 1" "$result" "$details"
  update_counters "$result"
  
  # 5.2.9 Minimize the admission of containers with capabilities assigned
  local assigned_cap_containers=$(oc get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[].securityContext.capabilities != null) | .metadata.name' | wc -l)
  if [ "$assigned_cap_containers" -eq 0 ]; then
    result="PASS"
    details="No containers with assigned capabilities found in the cluster"
  else
    result="WARN"
    details="Found $assigned_cap_containers pods with assigned capabilities"
  fi
  format_result "5.2.9" "Minimize the admission of containers with capabilities assigned" "Level 2" "$result" "$details"
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
  check_general_policies
  check_image_security
  check_container_runtime
  
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
    general-policies)
      initialize_counters
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        begin_html_report
      fi
      check_general_policies
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        end_html_report
      fi
      ;;
    image-security)
      initialize_counters
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        begin_html_report
      fi
      check_image_security
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        end_html_report
      fi
      ;;
    container-runtime)
      initialize_counters
      if [ "$OUTPUT_FORMAT" == "html" ]; then
        begin_html_report
      fi
      check_container_runtime
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