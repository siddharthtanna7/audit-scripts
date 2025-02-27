#!/bin/bash

# ocp-netpol-audit.sh - OpenShift NetworkPolicy Auditing Tool
# A tool for security engineers to audit and visualize network policies in OpenShift clusters

set -e

VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")

# No colors - simple output

# Function to display usage information
show_usage() {
  cat << EOF
OpenShift NetworkPolicy Audit Tool v${VERSION}
A tool for security engineers to audit and visualize network policies in OpenShift clusters

Usage:
  ${SCRIPT_NAME} [command] [options]

Commands:
  list                          List all NetworkPolicies across all namespaces
  audit                         Perform a comprehensive audit of NetworkPolicies
  visualize                     Generate a visualization of NetworkPolicy relationships
  coverage                      Show namespace coverage of NetworkPolicies
  check [namespace]             Check NetworkPolicies in a specific namespace
  analyze [policy_name]         Analyze a specific NetworkPolicy
  gaps                          Identify namespaces without NetworkPolicies
  default-deny                  Check for default-deny policies across namespaces
  flows [namespace]             Show allowed traffic flows for a namespace
  pods [namespace]              Show pod-to-pod communication matrix
  recommendations [namespace]   Generate NetworkPolicy recommendations
  simulate [options]            Simulate traffic between pods to test policies
  help                          Show this help message

Options:
  -o, --output [format]         Output format: table (default), json, yaml, dot
  -n, --namespace [namespace]   Filter by namespace
  -l, --label [label]           Filter by label selector
  -p, --pod [pod]               Filter by pod name pattern
  -d, --detail                  Show detailed information
  -c, --cross-namespace         Include cross-namespace policies in analysis
  -a, --all-namespaces          Show information from all namespaces
  -h, --help                    Show this help message
  -v, --version                 Show version information

Examples:
  ${SCRIPT_NAME} list --all-namespaces
  ${SCRIPT_NAME} audit
  ${SCRIPT_NAME} visualize --output dot > network-policies.dot
  ${SCRIPT_NAME} coverage
  ${SCRIPT_NAME} check app-namespace
  ${SCRIPT_NAME} default-deny --all-namespaces
  ${SCRIPT_NAME} gaps
  ${SCRIPT_NAME} flows frontend-namespace
  ${SCRIPT_NAME} pods app-namespace --detail
  ${SCRIPT_NAME} recommendations app-namespace
  ${SCRIPT_NAME} simulate --from-namespace=ns1 --to-namespace=ns2 --to-port=8080

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
  
  # Check if jq is installed
  if ! command -v jq &> /dev/null; then
    echo "Warning: 'jq' command not found. Some features may not work properly."
    echo "Please install jq for better parsing of JSON output."
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
    dot)
      # Return as-is, as dot format is only generated for visualization
      echo "$data"
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

# Function to get all namespaces
get_all_namespaces() {
  if [ -n "$NAMESPACE" ]; then
    echo "$NAMESPACE"
  else
    oc get namespaces -o jsonpath='{.items[*].metadata.name}'
  fi
}

# Function to list all NetworkPolicies
list_networkpolicies() {
  echo "Listing NetworkPolicies..."
  
  if [ "$ALL_NAMESPACES" == "true" ]; then
    echo "NAMESPACE\tNAME\tPOD SELECTOR\tPOLICY TYPES"
    
    if [ "$OUTPUT_FORMAT" == "json" ]; then
      oc get networkpolicy --all-namespaces -o json
    elif [ "$OUTPUT_FORMAT" == "yaml" ]; then
      oc get networkpolicy --all-namespaces -o yaml
    else
      oc get networkpolicy --all-namespaces -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,POD_SELECTOR:.spec.podSelector.matchLabels,POLICY_TYPES:.spec.policyTypes | tail -n +2 | sed 's/map\[\(.*\)\]/\1/g' | sed 's/ /\t/g'
    fi
  else
    namespace=${NAMESPACE:-default}
    echo "Namespace: $namespace"
    echo "NAME\tPOD SELECTOR\tPOLICY TYPES"
    
    if [ "$OUTPUT_FORMAT" == "json" ]; then
      oc get networkpolicy -n "$namespace" -o json
    elif [ "$OUTPUT_FORMAT" == "yaml" ]; then
      oc get networkpolicy -n "$namespace" -o yaml
    else
      oc get networkpolicy -n "$namespace" -o custom-columns=NAME:.metadata.name,POD_SELECTOR:.spec.podSelector.matchLabels,POLICY_TYPES:.spec.policyTypes | tail -n +2 | sed 's/map\[\(.*\)\]/\1/g' | sed 's/ /\t/g'
    fi
  fi
}

# Function to analyze policy coverage across namespaces
check_policy_coverage() {
  echo "Analyzing NetworkPolicy coverage across namespaces..."
  
  echo "NAMESPACE\tPOLICIES\tDEFAULT-DENY\tPOD COVERAGE\tRISK LEVEL"
  
  for ns in $(get_all_namespaces); do
    # Count policies
    local policy_count=$(oc get networkpolicy -n "$ns" --no-headers 2>/dev/null | wc -l)
    
    # Check if there's a default deny policy
    local default_deny=0
    if oc get networkpolicy -n "$ns" -o json 2>/dev/null | jq -r '.items[] | select(.spec.podSelector.matchLabels == null)' | grep -q "Ingress"; then
      default_deny=1
    fi
    
    # Get pod count
    local pod_count=$(oc get pods -n "$ns" --no-headers 2>/dev/null | wc -l)
    
    # Calculate pod coverage
    local coverage="0%"
    local risk="HIGH"
    
    if [ "$pod_count" -gt 0 ]; then
      if [ "$policy_count" -gt 0 ]; then
        # Get pods targeted by policies
        local targeted_labels=$(oc get networkpolicy -n "$ns" -o json 2>/dev/null | jq -r '.items[].spec.podSelector.matchLabels | keys[]' 2>/dev/null | sort | uniq)
        local total_targeted=0
        
        # Count pods targeted by any policy
        for label in $targeted_labels; do
          local label_value=$(oc get networkpolicy -n "$ns" -o json 2>/dev/null | jq -r '.items[].spec.podSelector.matchLabels."'"$label"'"' | head -1)
          if [ -n "$label_value" ]; then
            local pods_with_label=$(oc get pods -n "$ns" -l "$label=$label_value" --no-headers 2>/dev/null | wc -l)
            total_targeted=$((total_targeted + pods_with_label))
          fi
        done
        
        # Check for default deny that would cover all pods
        if [ "$default_deny" -eq 1 ]; then
          total_targeted=$pod_count
        fi
        
        # Calculate coverage percentage
        local percentage=$((total_targeted * 100 / pod_count))
        coverage="${percentage}%"
        
        # Determine risk level
        if [ "$percentage" -eq 100 ]; then
          if [ "$default_deny" -eq 1 ]; then
            risk="LOW"
          else
            risk="MEDIUM"
          fi
        elif [ "$percentage" -gt 50 ]; then
          risk="MEDIUM"
        else
          risk="HIGH"
        fi
      fi
    elif [ "$pod_count" -eq 0 ]; then
      coverage="N/A"
      risk="N/A"
    fi
    
    # Display default deny as Yes/No
    local default_deny_text="No"
    if [ "$default_deny" -eq 1 ]; then
      default_deny_text="Yes"
    fi
    
    echo "$ns\t$policy_count\t$default_deny_text\t$coverage\t$risk"
  done
}

# Function to identify namespaces without NetworkPolicies
identify_gaps() {
  echo "Identifying namespaces without NetworkPolicies..."
  
  echo "NAMESPACE\tPOD COUNT\tRISK LEVEL"
  
  for ns in $(oc get namespaces -o jsonpath='{.items[*].metadata.name}'); do
    # Count policies
    local policy_count=$(oc get networkpolicy -n "$ns" --no-headers 2>/dev/null | wc -l)
    
    # If no policies, check pod count to assess risk
    if [ "$policy_count" -eq 0 ]; then
      local pod_count=$(oc get pods -n "$ns" --no-headers 2>/dev/null | wc -l)
      local risk="LOW"
      
      # Determine risk based on namespace and pod count
      if [[ "$ns" == "default" || "$ns" == "kube-"* || "$ns" == "openshift"* ]]; then
        if [ "$pod_count" -gt 0 ]; then
          risk="HIGH"
        fi
      elif [ "$pod_count" -gt 5 ]; then
        risk="HIGH"
      elif [ "$pod_count" -gt 0 ]; then
        risk="MEDIUM"
      fi
      
      echo "$ns\t$pod_count\t$risk"
    fi
  done
}

# Function to check for default-deny policies
check_default_deny() {
  echo "Checking for default-deny NetworkPolicies..."
  
  echo "NAMESPACE\tDEFAULT-DENY-INGRESS\tDEFAULT-DENY-EGRESS"
  
  if [ "$ALL_NAMESPACES" == "true" ]; then
    namespaces=$(oc get namespaces -o jsonpath='{.items[*].metadata.name}')
  else
    namespaces=${NAMESPACE:-default}
  fi
  
  for ns in $namespaces; do
    local default_deny_ingress="No"
    local default_deny_egress="No"
    
    # Check for default deny ingress
    if oc get networkpolicy -n "$ns" -o json 2>/dev/null | jq -r '.items[] | select(.spec.podSelector.matchLabels | length == 0)' | grep -q "Ingress"; then
      default_deny_ingress="Yes"
    fi
    
    # Check for default deny egress
    if oc get networkpolicy -n "$ns" -o json 2>/dev/null | jq -r '.items[] | select(.spec.podSelector.matchLabels | length == 0)' | grep -q "Egress"; then
      default_deny_egress="Yes"
    fi
    
    echo "$ns\t$default_deny_ingress\t$default_deny_egress"
  done
}

# Function to analyze a specific NetworkPolicy
analyze_policy() {
  local policy_name="$1"
  
  if [ -z "$policy_name" ]; then
    echo "Error: NetworkPolicy name is required."
    echo "Usage: ${SCRIPT_NAME} analyze [policy_name] -n [namespace]"
    exit 1
  fi
  
  namespace=${NAMESPACE:-default}
  echo "Analyzing NetworkPolicy: $policy_name in namespace: $namespace"
  
  # Check if policy exists
  if ! oc get networkpolicy "$policy_name" -n "$namespace" &> /dev/null; then
    echo "Error: NetworkPolicy '$policy_name' not found in namespace '$namespace'."
    exit 1
  fi
  
  # Get policy details
  local policy=$(oc get networkpolicy "$policy_name" -n "$namespace" -o json)
  
  # Extract pod selector
  local pod_selector=$(echo "$policy" | jq -r '.spec.podSelector.matchLabels')
  
  # Extract policy types
  local policy_types=$(echo "$policy" | jq -r '.spec.policyTypes[]')
  
  # Get impacted pods
  local impacted_pods=""
  if [ "$pod_selector" != "null" ] && [ "$pod_selector" != "{}" ]; then
    local selector=""
    for key in $(echo "$pod_selector" | jq -r 'keys[]'); do
      local value=$(echo "$pod_selector" | jq -r ".[\"$key\"]")
      selector="${selector}${key}=${value},"
    done
    selector=${selector%,}
    impacted_pods=$(oc get pods -n "$namespace" -l "$selector" -o name 2>/dev/null | sed 's|pod/||g')
  else
    impacted_pods="ALL PODS IN NAMESPACE"
  fi
  
  # Print analysis
  echo "Policy Type(s): $policy_types"
  echo "Pod Selector: $pod_selector"
  echo ""
  echo "Impacted Pods:"
  if [ -n "$impacted_pods" ]; then
    echo "$impacted_pods" | tr ' ' '\n' | sed 's/^/  - /'
  else
    echo "  None"
  fi
  echo ""
  
  # Analyze ingress rules
  if echo "$policy_types" | grep -q "Ingress"; then
    echo "Ingress Rules Analysis:"
    local ingress_rules=$(echo "$policy" | jq -r '.spec.ingress')
    if [ "$ingress_rules" == "null" ] || [ "$ingress_rules" == "[]" ]; then
      echo "  - Policy blocks all ingress traffic"
    else
      # Iterate through each ingress rule
      local rule_count=$(echo "$ingress_rules" | jq -r 'length')
      for ((i=0; i<rule_count; i++)); do
        echo "  Rule #$((i+1)):"
        
        # Extract from selectors
        local from_selectors=$(echo "$ingress_rules" | jq -r ".[$i].from")
        if [ "$from_selectors" == "null" ] || [ "$from_selectors" == "[]" ]; then
          echo "    - Allows traffic from all sources"
        else
          echo "    From:"
          local from_count=$(echo "$from_selectors" | jq -r 'length')
          for ((j=0; j<from_count; j++)); do
            local pod_selector=$(echo "$from_selectors" | jq -r ".[$j].podSelector")
            local namespace_selector=$(echo "$from_selectors" | jq -r ".[$j].namespaceSelector")
            local ip_block=$(echo "$from_selectors" | jq -r ".[$j].ipBlock")
            
            if [ "$pod_selector" != "null" ]; then
              echo "      - Pod selector: $(echo "$pod_selector" | jq -r '.matchLabels')"
            fi
            if [ "$namespace_selector" != "null" ]; then
              echo "      - Namespace selector: $(echo "$namespace_selector" | jq -r '.matchLabels')"
            fi
            if [ "$ip_block" != "null" ]; then
              echo "      - IP block: $(echo "$ip_block" | jq -r '.cidr') (except: $(echo "$ip_block" | jq -r '.except[]'))"
            fi
          done
        fi
        
        # Extract ports
        local ports=$(echo "$ingress_rules" | jq -r ".[$i].ports")
        if [ "$ports" == "null" ] || [ "$ports" == "[]" ]; then
          echo "    Ports: All ports"
        else
          echo "    Ports:"
          local ports_count=$(echo "$ports" | jq -r 'length')
          for ((k=0; k<ports_count; k++)); do
            local port=$(echo "$ports" | jq -r ".[$k].port")
            local protocol=$(echo "$ports" | jq -r ".[$k].protocol")
            echo "      - $protocol/$port"
          done
        fi
      done
    fi
  fi
  
  # Analyze egress rules
  if echo "$policy_types" | grep -q "Egress"; then
    echo ""
    echo "Egress Rules Analysis:"
    local egress_rules=$(echo "$policy" | jq -r '.spec.egress')
    if [ "$egress_rules" == "null" ] || [ "$egress_rules" == "[]" ]; then
      echo "  - Policy blocks all egress traffic"
    else
      # Iterate through each egress rule
      local rule_count=$(echo "$egress_rules" | jq -r 'length')
      for ((i=0; i<rule_count; i++)); do
        echo "  Rule #$((i+1)):"
        
        # Extract to selectors
        local to_selectors=$(echo "$egress_rules" | jq -r ".[$i].to")
        if [ "$to_selectors" == "null" ] || [ "$to_selectors" == "[]" ]; then
          echo "    - Allows traffic to all destinations"
        else
          echo "    To:"
          local to_count=$(echo "$to_selectors" | jq -r 'length')
          for ((j=0; j<to_count; j++)); do
            local pod_selector=$(echo "$to_selectors" | jq -r ".[$j].podSelector")
            local namespace_selector=$(echo "$to_selectors" | jq -r ".[$j].namespaceSelector")
            local ip_block=$(echo "$to_selectors" | jq -r ".[$j].ipBlock")
            
            if [ "$pod_selector" != "null" ]; then
              echo "      - Pod selector: $(echo "$pod_selector" | jq -r '.matchLabels')"
            fi
            if [ "$namespace_selector" != "null" ]; then
              echo "      - Namespace selector: $(echo "$namespace_selector" | jq -r '.matchLabels')"
            fi
            if [ "$ip_block" != "null" ]; then
              local cidr=$(echo "$ip_block" | jq -r '.cidr')
              local except=$(echo "$ip_block" | jq -r '.except[]')
              if [ "$except" == "null" ]; then
                echo "      - IP block: $cidr"
              else
                echo "      - IP block: $cidr (except: $except)"
              fi
            fi
          done
        fi
        
        # Extract ports
        local ports=$(echo "$egress_rules" | jq -r ".[$i].ports")
        if [ "$ports" == "null" ] || [ "$ports" == "[]" ]; then
          echo "    Ports: All ports"
        else
          echo "    Ports:"
          local ports_count=$(echo "$ports" | jq -r 'length')
          for ((k=0; k<ports_count; k++)); do
            local port=$(echo "$ports" | jq -r ".[$k].port")
            local protocol=$(echo "$ports" | jq -r ".[$k].protocol")
            echo "      - $protocol/$port"
          done
        fi
      done
    fi
  fi
  
  # Security assessment
  echo ""
  echo "Security Assessment:"
  
  # Check if policy is overly permissive
  local is_permissive=0
  if echo "$policy" | jq -r '.spec.ingress[].from' | grep -q "null"; then
    echo "  WARNING: Policy allows ingress from all sources"
    is_permissive=1
  fi
  if echo "$policy" | jq -r '.spec.egress[].to' | grep -q "null"; then
    echo "  WARNING: Policy allows egress to all destinations"
    is_permissive=1
  fi
  
  # Check if policy has empty pod selector (applies to all pods)
  if [ "$pod_selector" == "{}" ] || [ "$pod_selector" == "null" ]; then
    echo "  INFO: Policy applies to all pods in the namespace"
  fi
  
  # Overall assessment
  if [ "$is_permissive" -eq 1 ]; then
    echo "  OVERALL: Policy may be too permissive and should be reviewed"
  else
    echo "  OVERALL: Policy appears to be properly restrictive"
  fi
}

# Function to check NetworkPolicies in a specific namespace
check_namespace() {
  local namespace="$1"
  
  if [ -z "$namespace" ]; then
    echo "Error: Namespace is required."
    echo "Usage: ${SCRIPT_NAME} check [namespace]"
    exit 1
  fi
  
  echo "Checking NetworkPolicies in namespace: $namespace"
  
  # Check if namespace exists
  if ! oc get namespace "$namespace" &> /dev/null; then
    echo "Error: Namespace '$namespace' does not exist."
    exit 1
  fi
  
  # Get all NetworkPolicies in the namespace
  local policies=$(oc get networkpolicy -n "$namespace" -o name)
  if [ -z "$policies" ]; then
    echo "No NetworkPolicies found in namespace '$namespace'."
    echo ""
    echo "Security Assessment:"
    echo "  WARNING: Namespace has no NetworkPolicies defined."
    echo "  RECOMMENDATION: Consider implementing at least a default-deny policy."
    return
  fi
  
  echo "Found $(echo "$policies" | wc -w) NetworkPolicies:"
  echo "$policies" | sed 's|networkpolicy.networking.k8s.io/||g' | sed 's/^/  - /'
  echo ""
  
  # Check if there's a default-deny policy
  local default_deny_ingress=0
  local default_deny_egress=0
  for policy in $(echo "$policies" | sed 's|networkpolicy.networking.k8s.io/||g'); do
    local policy_json=$(oc get networkpolicy "$policy" -n "$namespace" -o json)
    local pod_selector=$(echo "$policy_json" | jq -r '.spec.podSelector.matchLabels')
    local policy_types=$(echo "$policy_json" | jq -r '.spec.policyTypes[]')
    
    if [ "$pod_selector" == "{}" ] || [ "$pod_selector" == "null" ]; then
      if echo "$policy_types" | grep -q "Ingress"; then
        default_deny_ingress=1
      fi
      if echo "$policy_types" | grep -q "Egress"; then
        default_deny_egress=1
      fi
    fi
  done
  
  echo "Default Deny Policies:"
  echo "  Ingress: $([ "$default_deny_ingress" -eq 1 ] && echo "Yes" || echo "No")"
  echo "  Egress: $([ "$default_deny_egress" -eq 1 ] && echo "Yes" || echo "No")"
  echo ""
  
  # Get pods in the namespace
  local pods=$(oc get pods -n "$namespace" -o name)
  local pod_count=$(echo "$pods" | wc -w)
  
  echo "Pods in Namespace: $pod_count"
  if [ "$DETAIL" == "true" ] && [ "$pod_count" -gt 0 ]; then
    echo "$pods" | sed 's|pod/||g' | sed 's/^/  - /'
    echo ""
  fi
  
  # Check policy coverage for each pod
  if [ "$pod_count" -gt 0 ]; then
    echo "Pod Policy Coverage:"
    local covered_pods=0
    
    for pod in $(echo "$pods" | sed 's|pod/||g'); do
      local pod_labels=$(oc get pod "$pod" -n "$namespace" -o json | jq -r '.metadata.labels')
      local covered=0
      local covering_policies=""
      
      for policy in $(echo "$policies" | sed 's|networkpolicy.networking.k8s.io/||g'); do
        local policy_json=$(oc get networkpolicy "$policy" -n "$namespace" -o json)
        local pod_selector=$(echo "$policy_json" | jq -r '.spec.podSelector.matchLabels')
        
        if [ "$pod_selector" == "{}" ] || [ "$pod_selector" == "null" ]; then
          covered=1
          covering_policies="$covering_policies$policy (all pods), "
        else
          # Check if pod labels match policy selector
          local matches=1
          for key in $(echo "$pod_selector" | jq -r 'keys[]'); do
            local value=$(echo "$pod_selector" | jq -r ".[\"$key\"]")
            local pod_value=$(echo "$pod_labels" | jq -r ".[\"$key\"]")
            
            if [ "$pod_value" != "$value" ]; then
              matches=0
              break
            fi
          done
          
          if [ "$matches" -eq 1 ]; then
            covered=1
            covering_policies="$covering_policies$policy, "
          fi
        fi
      done
      
      if [ "$covered" -eq 1 ]; then
        covered_pods=$((covered_pods + 1))
        if [ "$DETAIL" == "true" ]; then
          echo "  - $pod: Covered by [${covering_policies%, }]"
        fi
      else
        if [ "$DETAIL" == "true" ]; then
          echo "  - $pod: NOT covered by any policy"
        fi
      fi
    done
    
    local coverage_percentage=$((covered_pods * 100 / pod_count))
    echo "  Coverage: $coverage_percentage% ($covered_pods/$pod_count pods)"
  fi
  
  echo ""
  echo "Security Assessment:"
  if [ "$default_deny_ingress" -eq 0 ]; then
    echo "  WARNING: No default-deny ingress policy found."
    echo "  RECOMMENDATION: Implement a default-deny ingress policy to block unspecified traffic."
  fi
  
  if [ "$default_deny_egress" -eq 0 ]; then
    echo "  WARNING: No default-deny egress policy found."
    echo "  RECOMMENDATION: Consider implementing a default-deny egress policy and explicitly allow required outbound traffic."
  fi
  
  if [ "$pod_count" -gt 0 ] && [ "$covered_pods" -lt "$pod_count" ]; then
    echo "  WARNING: Some pods are not covered by any NetworkPolicy."
    echo "  RECOMMENDATION: Ensure all pods have appropriate NetworkPolicies applied."
  fi
}

# Function to generate traffic flow visualizations
visualize_flows() {
  local namespace="${1:-all}"
  local format="${OUTPUT_FORMAT:-dot}"
  
  echo "Generating network policy visualization..."
  
  # If DOT format, create a DOT file for use with Graphviz
  if [ "$format" == "dot" ]; then
    echo "digraph NetworkPolicies {"
    echo "  rankdir=LR;"
    echo "  node [shape=box, style=filled, fillcolor=lightblue];"
    echo "  edge [color=gray];"
    echo ""
    
    # Add nodes for namespaces
    if [ "$namespace" == "all" ]; then
      for ns in $(oc get namespaces -o jsonpath='{.items[*].metadata.name}'); do
        echo "  \"$ns\" [shape=ellipse, fillcolor=lightgreen];"
      done
    else
      echo "  \"$namespace\" [shape=ellipse, fillcolor=lightgreen];"
    fi
    
    echo ""
    
    # Process network policies
    if [ "$namespace" == "all" ]; then
      netpols=$(oc get networkpolicy --all-namespaces -o json)
    else
      netpols=$(oc get networkpolicy -n "$namespace" -o json)
    fi
    
    # Extract policy connections
    echo "$netpols" | jq -r '.items[] | 
      "  \"" + .metadata.namespace + "/" + .metadata.name + "\" [shape=box, fillcolor=lightblue, label=\"" + .metadata.name + "\"];" +
      "\n  \"" + .metadata.namespace + "\" -> \"" + .metadata.namespace + "/" + .metadata.name + "\" [style=dashed];'
    
    echo ""
    
    # Extract ingress rules
    echo "$netpols" | jq -r '.items[] | select(.spec.ingress != null) | 
      .metadata.namespace as $ns | 
      .metadata.name as $name | 
      .spec.ingress[] | 
      select(.from != null) | 
      .from[] | 
      if .namespaceSelector != null then
        if .namespaceSelector.matchLabels != null then
          "  \"NAMESPACE[" + (.namespaceSelector.matchLabels | to_entries | map(.key + "=" + .value) | join(",")) + "]\" -> \"" + $ns + "/" + $name + "\";"
        else
          "  \"ALL_NAMESPACES\" -> \"" + $ns + "/" + $name + "\";"
        end
      elif .podSelector != null then
        if .podSelector.matchLabels != null then
          "  \"POD[" + (.podSelector.matchLabels | to_entries | map(.key + "=" + .value) | join(",")) + "]\" -> \"" + $ns + "/" + $name + "\";"
        else
          "  \"ALL_PODS\" -> \"" + $ns + "/" + $name + "\";"
        end
      elif .ipBlock != null then
        "  \"IP[" + .ipBlock.cidr + "]\" -> \"" + $ns + "/" + $name + "\";"
      else
        ""
      end'
    
    echo ""
    
    # Extract egress rules
    echo "$netpols" | jq -r '.items[] | select(.spec.egress != null) | 
      .metadata.namespace as $ns | 
      .metadata.name as $name | 
      .spec.egress[] | 
      select(.to != null) | 
      .to[] | 
      if .namespaceSelector != null then
        if .namespaceSelector.matchLabels != null then
          "  \"" + $ns + "/" + $name + "\" -> \"NAMESPACE[" + (.namespaceSelector.matchLabels | to_entries | map(.key + "=" + .value) | join(",")) + "]\";"
        else
          "  \"" + $ns + "/" + $name + "\" -> \"ALL_NAMESPACES\";"
        end
      elif .podSelector != null then
        if .podSelector.matchLabels != null then
          "  \"" + $ns + "/" + $name + "\" -> \"POD[" + (.podSelector.matchLabels | to_entries | map(.key + "=" + .value) | join(",")) + "]\";"
        else
          "  \"" + $ns + "/" + $name + "\" -> \"ALL_PODS\";"
        end
      elif .ipBlock != null then
        "  \"" + $ns + "/" + $name + "\" -> \"IP[" + .ipBlock.cidr + "]\";"
      else
        ""
      end'
    
    echo "}"
    
    echo "Visualization generated in DOT format."
    echo "To render the visualization, pipe the output to a file and use Graphviz:"
    echo "Example: ${SCRIPT_NAME} visualize -o dot > network-policies.dot && dot -Tpng network-policies.dot -o network-policies.png"
  else
    echo "Visualization is only supported in DOT format. Please use '--output dot'."
  fi
}

# Function to generate flow matrix
generate_flow_matrix() {
  local namespace="$1"
  
  if [ -z "$namespace" ]; then
    echo "Error: Namespace is required."
    echo "Usage: ${SCRIPT_NAME} flows [namespace]"
    exit 1
  fi
  
  echo "Generating traffic flow matrix for namespace: $namespace"
  
  # Check if namespace exists
  if ! oc get namespace "$namespace" &> /dev/null; then
    echo "Error: Namespace '$namespace' does not exist."
    exit 1
  fi
  
  # Get all pods in the namespace
  local pods=$(oc get pods -n "$namespace" -o jsonpath='{.items[*].metadata.name}')
  if [ -z "$pods" ]; then
    echo "No pods found in namespace '$namespace'."
    return
  fi
  
  # Get all NetworkPolicies in the namespace
  local policies=$(oc get networkpolicy -n "$namespace" -o json)
  
  # Check if there's a default-deny policy
  local default_deny_ingress=0
  local default_deny_egress=0
  
  echo "$policies" | jq -r '.items[] | select(.spec.podSelector.matchLabels | length == 0)' | while read -r policy; do
    if echo "$policy" | jq -r '.spec.policyTypes[]' | grep -q "Ingress"; then
      default_deny_ingress=1
    fi
    if echo "$policy" | jq -r '.spec.policyTypes[]' | grep -q "Egress"; then
      default_deny_egress=1
    fi
  done
  
  echo "Default Policies:"
  echo "  Default Deny Ingress: $([ "$default_deny_ingress" -eq 1 ] && echo "Yes" || echo "No")"
  echo "  Default Deny Egress: $([ "$default_deny_egress" -eq 1 ] && echo "Yes" || echo "No")"
  echo ""
  
  # Print matrix header
  echo "Pod-to-Pod Communication Matrix (Ingress/Egress):"
  echo ""
  printf "%-25s" "FROM \\ TO"
  for target_pod in $pods; do
    printf "%-15s" "$target_pod"
  done
  echo ""
  
  # Print matrix separator
  printf "%-25s" "------------------------"
  for target_pod in $pods; do
    printf "%-15s" "---------------"
  done
  echo ""
  
  # Generate matrix
  for source_pod in $pods; do
    printf "%-25s" "$source_pod"
    
    for target_pod in $pods; do
      local source_allowed_to_target="N/N"
      
      # Get pod labels
      local source_labels=$(oc get pod "$source_pod" -n "$namespace" -o json | jq -r '.metadata.labels')
      local target_labels=$(oc get pod "$target_pod" -n "$namespace" -o json | jq -r '.metadata.labels')
      
      # Check ingress (target ← source)
      local ingress_allowed=0
      if [ "$default_deny_ingress" -eq 0 ]; then
        ingress_allowed=1
      fi
      
      echo "$policies" | jq -r '.items[] | select(.spec.policyTypes[] | contains("Ingress"))' | while read -r policy; do
        local pod_selector=$(echo "$policy" | jq -r '.spec.podSelector.matchLabels')
        
        # Check if target pod is selected by policy
        local target_matches=1
        if [ "$pod_selector" != "{}" ] && [ "$pod_selector" != "null" ]; then
          for key in $(echo "$pod_selector" | jq -r 'keys[]'); do
            local value=$(echo "$pod_selector" | jq -r ".[\"$key\"]")
            local pod_value=$(echo "$target_labels" | jq -r ".[\"$key\"]")
            
            if [ "$pod_value" != "$value" ]; then
              target_matches=0
              break
            fi
          done
        fi
        
        if [ "$target_matches" -eq 1 ]; then
          # Check if policy allows ingress from source pod
          local ingress_rules=$(echo "$policy" | jq -r '.spec.ingress')
          if [ "$ingress_rules" == "[]" ]; then
            ingress_allowed=0
          else
            local allowed=0
            echo "$ingress_rules" | jq -r '.[] | select(.from != null) | .from[]' | while read -r from; do
              local pod_selector=$(echo "$from" | jq -r '.podSelector')
              if [ "$pod_selector" != "null" ]; then
                # Check if source pod matches podSelector
                local matches=1
                for key in $(echo "$pod_selector" | jq -r '.matchLabels | keys[]'); do
                  local value=$(echo "$pod_selector" | jq -r ".matchLabels[\"$key\"]")
                  local pod_value=$(echo "$source_labels" | jq -r ".[\"$key\"]")
                  
                  if [ "$pod_value" != "$value" ]; then
                    matches=0
                    break
                  fi
                done
                
                if [ "$matches" -eq 1 ]; then
                  allowed=1
                fi
              else
                # No podSelector means all pods
                allowed=1
              fi
            done
            
            if [ "$allowed" -eq 1 ]; then
              ingress_allowed=1
            fi
          fi
        fi
      done
      
      # Check egress (source → target)
      local egress_allowed=0
      if [ "$default_deny_egress" -eq 0 ]; then
        egress_allowed=1
      fi
      
      echo "$policies" | jq -r '.items[] | select(.spec.policyTypes[] | contains("Egress"))' | while read -r policy; do
        local pod_selector=$(echo "$policy" | jq -r '.spec.podSelector.matchLabels')
        
        # Check if source pod is selected by policy
        local source_matches=1
        if [ "$pod_selector" != "{}" ] && [ "$pod_selector" != "null" ]; then
          for key in $(echo "$pod_selector" | jq -r 'keys[]'); do
            local value=$(echo "$pod_selector" | jq -r ".[\"$key\"]")
            local pod_value=$(echo "$source_labels" | jq -r ".[\"$key\"]")
            
            if [ "$pod_value" != "$value" ]; then
              source_matches=0
              break
            fi
          done
        fi
        
        if [ "$source_matches" -eq 1 ]; then
          # Check if policy allows egress to target pod
          local egress_rules=$(echo "$policy" | jq -r '.spec.egress')
          if [ "$egress_rules" == "[]" ]; then
            egress_allowed=0
          else
            local allowed=0
            echo "$egress_rules" | jq -r '.[] | select(.to != null) | .to[]' | while read -r to; do
              local pod_selector=$(echo "$to" | jq -r '.podSelector')
              if [ "$pod_selector" != "null" ]; then
                # Check if target pod matches podSelector
                local matches=1
                for key in $(echo "$pod_selector" | jq -r '.matchLabels | keys[]'); do
                  local value=$(echo "$pod_selector" | jq -r ".matchLabels[\"$key\"]")
                  local pod_value=$(echo "$target_labels" | jq -r ".[\"$key\"]")
                  
                  if [ "$pod_value" != "$value" ]; then
                    matches=0
                    break
                  fi
                done
                
                if [ "$matches" -eq 1 ]; then
                  allowed=1
                fi
              else
                # No podSelector means all pods
                allowed=1
              fi
            done
            
            if [ "$allowed" -eq 1 ]; then
              egress_allowed=1
            fi
          fi
        fi
      done
      
      source_allowed_to_target="${ingress_allowed}/${egress_allowed}"
      if [ "$source_allowed_to_target" == "1/1" ]; then
        source_allowed_to_target="Y/Y"
      elif [ "$source_allowed_to_target" == "1/0" ]; then
        source_allowed_to_target="Y/N"
      elif [ "$source_allowed_to_target" == "0/1" ]; then
        source_allowed_to_target="N/Y"
      fi
      
      printf "%-15s" "$source_allowed_to_target"
    done
    echo ""
  done
  
  echo ""
  echo "Legend: Ingress/Egress"
  echo "Y/Y: Traffic allowed in both directions"
  echo "Y/N: Ingress allowed, Egress denied"
  echo "N/Y: Ingress denied, Egress allowed"
  echo "N/N: Traffic denied in both directions"
}

# Function to generate NetworkPolicy recommendations
generate_recommendations() {
  local namespace="$1"
  
  if [ -z "$namespace" ]; then
    echo "Error: Namespace is required."
    echo "Usage: ${SCRIPT_NAME} recommendations [namespace]"
    exit 1
  fi
  
  echo "Generating NetworkPolicy recommendations for namespace: $namespace"
  
  # Check if namespace exists
  if ! oc get namespace "$namespace" &> /dev/null; then
    echo "Error: Namespace '$namespace' does not exist."
    exit 1
  fi
  
  # Get existing NetworkPolicies
  local existing_policies=$(oc get networkpolicy -n "$namespace" -o name 2>/dev/null)
  
  if [ -n "$existing_policies" ]; then
    echo "Existing NetworkPolicies:"
    echo "$existing_policies" | sed 's|networkpolicy.networking.k8s.io/||g' | sed 's/^/  - /'
    echo ""
  else
    echo "No existing NetworkPolicies found in namespace '$namespace'."
    echo ""
  fi
  
  # Check if there's a default-deny policy
  local has_default_deny_ingress=0
  local has_default_deny_egress=0
  
  if [ -n "$existing_policies" ]; then
    for policy in $(echo "$existing_policies" | sed 's|networkpolicy.networking.k8s.io/||g'); do
      local policy_json=$(oc get networkpolicy "$policy" -n "$namespace" -o json)
      
      # Check for default deny ingress
      if echo "$policy_json" | jq -r '.spec.podSelector.matchLabels' | grep -q "{}"; then
        if echo "$policy_json" | jq -r '.spec.policyTypes[]' | grep -q "Ingress"; then
          if [ "$(echo "$policy_json" | jq -r '.spec.ingress | length')" -eq 0 ]; then
            has_default_deny_ingress=1
          fi
        fi
      fi
      
      # Check for default deny egress
      if echo "$policy_json" | jq -r '.spec.podSelector.matchLabels' | grep -q "{}"; then
        if echo "$policy_json" | jq -r '.spec.policyTypes[]' | grep -q "Egress"; then
          if [ "$(echo "$policy_json" | jq -r '.spec.egress | length')" -eq 0 ]; then
            has_default_deny_egress=1
          fi
        fi
      fi
    done
  fi
  
  # Get deployments and services
  local deployments=$(oc get deployment -n "$namespace" -o json 2>/dev/null)
  local services=$(oc get service -n "$namespace" -o json 2>/dev/null)
  
  # Recommendations
  echo "NetworkPolicy Recommendations:"
  
  # 1. Default deny policies
  if [ "$has_default_deny_ingress" -eq 0 ]; then
    echo "1. Create a default-deny ingress policy:"
    cat << EOF
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: $namespace
spec:
  podSelector: {}
  policyTypes:
  - Ingress
EOF
    echo ""
  fi
  
  if [ "$has_default_deny_egress" -eq 0 ]; then
    echo "2. Create a default-deny egress policy:"
    cat << EOF
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: $namespace
spec:
  podSelector: {}
  policyTypes:
  - Egress
EOF
    echo ""
  fi
  
  # 3. Recommendations based on services
  if [ -n "$services" ] && [ "$(echo "$services" | jq -r '.items | length')" -gt 0 ]; then
    echo "3. Allow traffic to services:"
    
    local service_count=0
    echo "$services" | jq -r '.items[] | select(.spec.type != "ExternalName")' | while read -r service; do
      service_count=$((service_count + 1))
      local service_name=$(echo "$service" | jq -r '.metadata.name')
      local selector=$(echo "$service" | jq -r '.spec.selector')
      local ports=$(echo "$service" | jq -r '.spec.ports')
      
      if [ "$selector" != "null" ] && [ "$selector" != "{}" ]; then
        echo "Allow traffic to service: $service_name"
        
        # Generate policy for this service
        cat << EOF
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-to-$service_name
  namespace: $namespace
spec:
  podSelector:
    matchLabels:
$(echo "$selector" | jq -r 'to_entries[] | "      \(.key): \(.value)"')
  policyTypes:
  - Ingress
  ingress:
  - ports:
$(echo "$ports" | jq -r '.[] | "    - port: \(.port)\n      protocol: \(.protocol // "TCP")"')
EOF
        echo ""
      fi
    done
    
    if [ "$service_count" -eq 0 ]; then
      echo "  No services with selectors found in namespace '$namespace'."
      echo ""
    fi
  fi
  
  # 4. DNS egress policy
  if [ "$has_default_deny_egress" -eq 1 ]; then
    echo "4. Allow DNS egress traffic:"
    cat << EOF
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: $namespace
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
EOF
    echo ""
  fi
  
  # 5. Allow monitoring (Prometheus)
  echo "5. Allow monitoring (Prometheus) ingress:"
  cat << EOF
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-prometheus
  namespace: $namespace
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: openshift-monitoring
EOF
  echo ""
  
  # 6. Recommendations for cross-namespace communication
  if [ "$CROSS_NAMESPACE" == "true" ]; then
    echo "6. Example of cross-namespace communication policy:"
    cat << EOF
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-other-namespace
  namespace: $namespace
spec:
  podSelector:
    matchLabels:
      # Replace with appropriate pod selector
      app: example
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          # Replace with appropriate namespace label
          name: other-namespace
      podSelector:
        matchLabels:
          # Replace with appropriate pod selector
          app: calling-app
    ports:
    - protocol: TCP
      port: 8080
EOF
    echo ""
  fi
  
  # 7. Known external endpoints
  if [ "$has_default_deny_egress" -eq 1 ]; then
    echo "7. Allow egress to known external endpoints:"
    cat << EOF
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-external-egress
  namespace: $namespace
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
        - 169.254.0.0/16
EOF
    echo ""
  fi
  
  echo "These are recommended NetworkPolicies based on the current state of your namespace."
  echo "Review and modify them according to your specific requirements before applying."
}

# Function to simulate traffic between pods
simulate_traffic() {
  local from_namespace="${FROM_NAMESPACE:-default}"
  local to_namespace="${TO_NAMESPACE:-default}"
  local to_port="${TO_PORT:-80}"
  local from_pod=""
  local to_pod=""
  
  echo "Simulating traffic from namespace '$from_namespace' to namespace '$to_namespace' on port '$to_port'..."
  
  # Get a pod from the source namespace
  from_pod=$(oc get pods -n "$from_namespace" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  if [ -z "$from_pod" ]; then
    echo "Error: No running pods found in source namespace '$from_namespace'."
    exit 1
  fi
  
  # Get a pod from the target namespace
  to_pod=$(oc get pods -n "$to_namespace" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  if [ -z "$to_pod" ]; then
    echo "Error: No running pods found in target namespace '$to_namespace'."
    exit 1
  fi
  
  # Get the IP of the target pod
  to_pod_ip=$(oc get pod "$to_pod" -n "$to_namespace" -o jsonpath='{.status.podIP}')
  if [ -z "$to_pod_ip" ]; then
    echo "Error: Could not get IP address of target pod '$to_pod'."
    exit 1
  fi
  
  echo "Source Pod: $from_pod (namespace: $from_namespace)"
  echo "Target Pod: $to_pod (namespace: $to_namespace, IP: $to_pod_ip)"
  echo ""
  
  # Simulate traffic using wget or curl
  echo "Testing connectivity from source to target..."
  local result
  
  # Try to execute a curl or wget command in the source pod
  if oc exec "$from_pod" -n "$from_namespace" -- curl -s --connect-timeout 5 "$to_pod_ip:$to_port" &> /dev/null; then
    result="Success (curl)"
  elif oc exec "$from_pod" -n "$from_namespace" -- wget -q -O - --timeout=5 "$to_pod_ip:$to_port" &> /dev/null; then
    result="Success (wget)"
  else
    result="Failed"
  fi
  
  echo "Connectivity test result: $result"
  
  if [ "$result" == "Failed" ]; then
    echo ""
    echo "Analyzing potential NetworkPolicy restrictions..."
    
    # Check for egress restrictions in source namespace
    local egress_policies=$(oc get networkpolicy -n "$from_namespace" -o json | jq -r '.items[] | select(.spec.policyTypes[] | contains("Egress"))')
    if [ -n "$egress_policies" ]; then
      echo "Found egress policies in source namespace that might be blocking traffic:"
      echo "$egress_policies" | jq -r '.metadata.name' | sed 's/^/  - /'
    else
      echo "No egress policies found in source namespace."
    fi
    
    # Check for ingress restrictions in target namespace
    local ingress_policies=$(oc get networkpolicy -n "$to_namespace" -o json | jq -r '.items[] | select(.spec.policyTypes[] | contains("Ingress"))')
    if [ -n "$ingress_policies" ]; then
      echo "Found ingress policies in target namespace that might be blocking traffic:"
      echo "$ingress_policies" | jq -r '.metadata.name' | sed 's/^/  - /'
    else
      echo "No ingress policies found in target namespace."
    fi
    
    # Check if the target port is open
    echo ""
    echo "Checking if the target port $to_port is open on the target pod..."
    local port_check
    if oc exec "$to_pod" -n "$to_namespace" -- netstat -tulpn 2>/dev/null | grep -q ":$to_port "; then
      port_check="Port is open"
    else
      port_check="Port does not appear to be open (this might be a cause of failure)"
    fi
    echo "Port check result: $port_check"
  fi
}

# Function to perform a comprehensive audit
audit_networkpolicies() {
  echo "Performing comprehensive NetworkPolicy audit..."
  
  # 1. Check policy coverage
  echo "1. NetworkPolicy Coverage:"
  check_policy_coverage
  echo ""
  
  # 2. Identify namespaces without policies
  echo "2. Namespaces Without NetworkPolicies:"
  identify_gaps
  echo ""
  
  # 3. Check for default-deny policies
  echo "3. Default-Deny Policy Deployment:"
  check_default_deny
  echo ""
  
  # 4. Check for overly permissive policies
  echo "4. Overly Permissive Policies:"
  echo "NAMESPACE\tPOLICY\tISSUE"
  
  for ns in $(oc get namespaces -o jsonpath='{.items[*].metadata.name}'); do
    for policy in $(oc get networkpolicy -n "$ns" --no-headers 2>/dev/null | awk '{print $1}'); do
      # Get policy details
      local policy_json=$(oc get networkpolicy "$policy" -n "$ns" -o json)
      
      # Check for empty podSelector
      local pod_selector=$(echo "$policy_json" | jq -r '.spec.podSelector.matchLabels')
      local empty_selector=0
      if [ "$pod_selector" == "{}" ] || [ "$pod_selector" == "null" ]; then
        empty_selector=1
      fi
      
      # Check for ingress from any source
      if echo "$policy_json" | jq -r '.spec.ingress[]?.from' | grep -q "null"; then
        echo "$ns\t$policy\tAllows ingress from all sources"
      fi
      
      # Check for egress to any destination
      if echo "$policy_json" | jq -r '.spec.egress[]?.to' | grep -q "null"; then
        echo "$ns\t$policy\tAllows egress to all destinations"
      fi
      
      # Non-default-deny policy with empty selector
      if [ "$empty_selector" -eq 1 ]; then
        local has_ingress=$(echo "$policy_json" | jq -r '.spec.ingress | length')
        local has_egress=$(echo "$policy_json" | jq -r '.spec.egress | length')
        
        if [ "$has_ingress" -gt 0 ] || [ "$has_egress" -gt 0 ]; then
          echo "$ns\t$policy\tEmpty pod selector with permissive rules"
        fi
      fi
    done
  done
  echo ""
  
  # 5. Summary and recommendations
  echo "5. Summary and Recommendations:"
  
  # Count total namespaces and namespaces with policies
  local total_ns=$(oc get namespaces --no-headers | wc -l)
  local ns_with_policies=$(oc get networkpolicy --all-namespaces --no-headers 2>/dev/null | awk '{print $1}' | sort | uniq | wc -l)
  local coverage_percentage=$((ns_with_policies * 100 / total_ns))
  
  echo "Total Namespaces: $total_ns"
  echo "Namespaces with NetworkPolicies: $ns_with_policies"
  echo "Coverage: $coverage_percentage%"
  echo ""
  
  # Recommend default-deny if coverage is low
  if [ "$coverage_percentage" -lt 70 ]; then
    echo "RECOMMENDATION: Implement default-deny NetworkPolicies in all production namespaces."
    echo "                This establishes a baseline security posture by blocking unwanted traffic."
  fi
  
  # Check for ingress controller protection
  local ingress_protected=0
  if oc get networkpolicy -n openshift-ingress --no-headers 2>/dev/null | wc -l | grep -q "[1-9]"; then
    ingress_protected=1
  fi
  
  if [ "$ingress_protected" -eq 0 ]; then
    echo "RECOMMENDATION: Implement NetworkPolicies for the ingress controller namespace."
    echo "                This helps protect your ingress controllers from unauthorized access."
  fi
  
  # Check for Prometheus access
  local prom_policies=$(oc get networkpolicy --all-namespaces -o json | jq -r '.items[] | select(.spec.ingress[]?.from[]?.namespaceSelector.matchLabels."kubernetes.io/metadata.name" == "openshift-monitoring") | .metadata.namespace' | sort | uniq | wc -l)
  
  if [ "$prom_policies" -lt "$ns_with_policies" ]; then
    echo "RECOMMENDATION: Ensure Prometheus has access to all namespaces for monitoring."
    echo "                Add ingress rules for the openshift-monitoring namespace in your NetworkPolicies."
  fi
  
  echo ""
  echo "Audit completed successfully."
}

# Function to create pod-to-pod communication matrix
pod_communication_matrix() {
  local namespace="$1"
  
  if [ -z "$namespace" ]; then
    echo "Error: Namespace is required."
    echo "Usage: ${SCRIPT_NAME} pods [namespace]"
    exit 1
  fi
  
  echo "Generating pod communication matrix for namespace: $namespace"
  
  # Check if namespace exists
  if ! oc get namespace "$namespace" &> /dev/null; then
    echo "Error: Namespace '$namespace' does not exist."
    exit 1
  fi
  
  # Get all pods in namespace
  local pods=$(oc get pods -n "$namespace" --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}')
  if [ -z "$pods" ]; then
    echo "No running pods found in namespace '$namespace'."
    return
  fi
  
  # Group pods by application/component
  echo "Pod Grouping by Labels:"
  echo "LABEL\tPODS"
  
  # Get all label keys
  local label_keys=$(oc get pods -n "$namespace" -o json | jq -r '.items[].metadata.labels | keys[]' | sort | uniq)
  
  for key in $label_keys; do
    # Skip internal kubernetes labels
    if [[ "$key" == "pod-template-hash" || "$key" == "controller-revision-hash" || "$key" == "statefulset.kubernetes.io/pod-name" ]]; then
      continue
    fi
    
    # Get values for this key
    local values=$(oc get pods -n "$namespace" -o json | jq -r --arg key "$key" '.items[] | select(.metadata.labels[$key] != null) | .metadata.labels[$key]' | sort | uniq)
    
    for value in $values; do
      local pods_with_label=$(oc get pods -n "$namespace" -l "$key=$value" -o jsonpath='{.items[*].metadata.name}')
      local pod_count=$(echo "$pods_with_label" | wc -w)
      
      if [ "$pod_count" -gt 0 ]; then
        echo "$key=$value\t$pod_count pods"
        
        if [ "$DETAIL" == "true" ]; then
          echo "$pods_with_label" | tr ' ' '\n' | sed 's/^/  - /'
        fi
      fi
    done
  done
  echo ""
  
  # Get NetworkPolicies in namespace
  local policies=$(oc get networkpolicy -n "$namespace" -o name)
  if [ -z "$policies" ]; then
    echo "No NetworkPolicies found in namespace '$namespace'."
    echo "All pods can communicate freely with each other (no restrictions)."
    return
  fi
  
  # Check if there's a default-deny policy
  local default_deny_ingress=0
  local default_deny_egress=0
  
  for policy in $(echo "$policies" | sed 's|networkpolicy.networking.k8s.io/||g'); do
    local policy_json=$(oc get networkpolicy "$policy" -n "$namespace" -o json)
    local pod_selector=$(echo "$policy_json" | jq -r '.spec.podSelector.matchLabels')
    local policy_types=$(echo "$policy_json" | jq -r '.spec.policyTypes[]')
    
    if [ "$pod_selector" == "{}" ] || [ "$pod_selector" == "null" ]; then
      if echo "$policy_types" | grep -q "Ingress"; then
        if [ "$(echo "$policy_json" | jq -r '.spec.ingress | length')" -eq 0 ]; then
          default_deny_ingress=1
        fi
      fi
      
      if echo "$policy_types" | grep -q "Egress"; then
        if [ "$(echo "$policy_json" | jq -r '.spec.egress | length')" -eq 0 ]; then
          default_deny_egress=1
        fi
      fi
    fi
  done
  
  echo "Network Restriction Summary:"
  echo "Default Deny Ingress: $([ "$default_deny_ingress" -eq 1 ] && echo "Yes" || echo "No")"
  echo "Default Deny Egress: $([ "$default_deny_egress" -eq 1 ] && echo "Yes" || echo "No")"
  echo ""
  
  if [ "$default_deny_ingress" -eq 0 ] && [ "$default_deny_egress" -eq 0 ]; then
    echo "No default deny policies found. Communication is allowed by default unless explicitly denied."
  elif [ "$default_deny_ingress" -eq 1 ] && [ "$default_deny_egress" -eq 0 ]; then
    echo "Default deny ingress policy found. Incoming traffic is denied by default unless explicitly allowed."
  elif [ "$default_deny_ingress" -eq 0 ] && [ "$default_deny_egress" -eq 1 ]; then
    echo "Default deny egress policy found. Outgoing traffic is denied by default unless explicitly allowed."
  else
    echo "Both default deny ingress and egress policies found. All traffic is denied by default unless explicitly allowed."
  fi
  
  echo ""
  echo "Network Policy Summary:"
  for policy in $(echo "$policies" | sed 's|networkpolicy.networking.k8s.io/||g'); do
    local policy_json=$(oc get networkpolicy "$policy" -n "$namespace" -o json)
    local pod_selector=$(echo "$policy_json" | jq -r '.spec.podSelector.matchLabels')
    local policy_types=$(echo "$policy_json" | jq -r '.spec.policyTypes[]')
    
    echo "Policy: $policy"
    echo "  Types: $policy_types"
    echo "  Pod Selector: $pod_selector"
    
    # Get pods affected by this policy
    local affected_pods=""
    if [ "$pod_selector" == "{}" ] || [ "$pod_selector" == "null" ]; then
      affected_pods="All pods in namespace"
    else
      local selector=""
      for key in $(echo "$pod_selector" | jq -r 'keys[]'); do
        local value=$(echo "$pod_selector" | jq -r ".[\"$key\"]")
        selector="${selector}${key}=${value},"
      done
      selector=${selector%,}
      affected_pods=$(oc get pods -n "$namespace" -l "$selector" -o name 2>/dev/null | sed 's|pod/||g')
    fi
    
    echo "  Affected Pods: $([ "$affected_pods" == "All pods in namespace" ] && echo "$affected_pods" || echo "$(echo "$affected_pods" | wc -w) pods")"
    
    if [ "$DETAIL" == "true" ] && [ "$affected_pods" != "All pods in namespace" ]; then
      echo "$affected_pods" | tr ' ' '\n' | sed 's/^/    - /'
    fi
    
    # Summarize ingress rules
    if echo "$policy_types" | grep -q "Ingress"; then
      local ingress_rules=$(echo "$policy_json" | jq -r '.spec.ingress')
      if [ "$ingress_rules" == "null" ] || [ "$ingress_rules" == "[]" ]; then
        echo "  Ingress: Deny all"
      else
        echo "  Ingress Rules:"
        local rule_count=$(echo "$ingress_rules" | jq -r 'length')
        for ((i=0; i<rule_count; i++)); do
          local from_selectors=$(echo "$ingress_rules" | jq -r ".[$i].from")
          if [ "$from_selectors" == "null" ] || [ "$from_selectors" == "[]" ]; then
            echo "    - Allow from all sources"
          else
            echo "    - Allow from:"
            local from_count=$(echo "$from_selectors" | jq -r 'length')
            for ((j=0; j<from_count; j++)); do
              local pod_selector=$(echo "$from_selectors" | jq -r ".[$j].podSelector")
              local namespace_selector=$(echo "$from_selectors" | jq -r ".[$j].namespaceSelector")
              local ip_block=$(echo "$from_selectors" | jq -r ".[$j].ipBlock")
              
              if [ "$pod_selector" != "null" ]; then
                echo "      - Pod selector: $(echo "$pod_selector" | jq -r '.matchLabels')"
              fi
              if [ "$namespace_selector" != "null" ]; then
                echo "      - Namespace selector: $(echo "$namespace_selector" | jq -r '.matchLabels')"
              fi
              if [ "$ip_block" != "null" ]; then
                echo "      - IP block: $(echo "$ip_block" | jq -r '.cidr')"
              fi
            done
          fi
        done
      fi
    fi
    
    # Summarize egress rules
    if echo "$policy_types" | grep -q "Egress"; then
      local egress_rules=$(echo "$policy_json" | jq -r '.spec.egress')
      if [ "$egress_rules" == "null" ] || [ "$egress_rules" == "[]" ]; then
        echo "  Egress: Deny all"
      else
        echo "  Egress Rules:"
        local rule_count=$(echo "$egress_rules" | jq -r 'length')
        for ((i=0; i<rule_count; i++)); do
          local to_selectors=$(echo "$egress_rules" | jq -r ".[$i].to")
          if [ "$to_selectors" == "null" ] || [ "$to_selectors" == "[]" ]; then
            echo "    - Allow to all destinations"
          else
            echo "    - Allow to:"
            local to_count=$(echo "$to_selectors" | jq -r 'length')
            for ((j=0; j<to_count; j++)); do
              local pod_selector=$(echo "$to_selectors" | jq -r ".[$j].podSelector")
              local namespace_selector=$(echo "$to_selectors" | jq -r ".[$j].namespaceSelector")
              local ip_block=$(echo "$to_selectors" | jq -r ".[$j].ipBlock")
              
              if [ "$pod_selector" != "null" ]; then
                echo "      - Pod selector: $(echo "$pod_selector" | jq -r '.matchLabels')"
              fi
              if [ "$namespace_selector" != "null" ]; then
                echo "      - Namespace selector: $(echo "$namespace_selector" | jq -r '.matchLabels')"
              fi
              if [ "$ip_block" != "null" ]; then
                echo "      - IP block: $(echo "$ip_block" | jq -r '.cidr')"
              fi
            done
          fi
        done
      fi
    fi
    
    echo ""
  done
}

# Parse command line arguments
parse_args() {
  COMMAND=""
  NAMESPACE=""
  OUTPUT_FORMAT="table"
  ALL_NAMESPACES=false
  DETAIL=false
  CROSS_NAMESPACE=false
  POD=""
  LABEL=""
  FROM_NAMESPACE=""
  TO_NAMESPACE=""
  TO_PORT=""
  
  while [[ $# -gt 0 ]]; do
    case "$1" in
      list|audit|visualize|coverage|check|analyze|gaps|default-deny|flows|pods|recommendations|simulate|help)
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
      -l|--label)
        if [[ $# -lt 2 ]] || [[ "$2" == -* ]]; then
          echo "Error: Missing argument for $1"
          exit 1
        fi
        LABEL="$2"
        shift 2
        ;;
      -p|--pod)
        if [[ $# -lt 2 ]] || [[ "$2" == -* ]]; then
          echo "Error: Missing argument for $1"
          exit 1
        fi
        POD="$2"
        shift 2
        ;;
      -a|--all-namespaces)
        ALL_NAMESPACES=true
        shift
        ;;
      -d|--detail)
        DETAIL=true
        shift
        ;;
      -c|--cross-namespace)
        CROSS_NAMESPACE=true
        shift
        ;;
      --from-namespace)
        if [[ $# -lt 2 ]] || [[ "$2" == -* ]]; then
          echo "Error: Missing argument for $1"
          exit 1
        fi
        FROM_NAMESPACE="$2"
        shift 2
        ;;
      --to-namespace)
        if [[ $# -lt 2 ]] || [[ "$2" == -* ]]; then
          echo "Error: Missing argument for $1"
          exit 1
        fi
        TO_NAMESPACE="$2"
        shift 2
        ;;
      --to-port)
        if [[ $# -lt 2 ]] || [[ "$2" == -* ]]; then
          echo "Error: Missing argument for $1"
          exit 1
        fi
        TO_PORT="$2"
        shift 2
        ;;
      -h|--help)
        show_usage
        exit 0
        ;;
      -v|--version)
        echo "OpenShift NetworkPolicy Audit Tool v${VERSION}"
        exit 0
        ;;
      *)
        # For commands that take a positional argument
        if [ "$COMMAND" == "check" ] || [ "$COMMAND" == "flows" ] || [ "$COMMAND" == "pods" ] || [ "$COMMAND" == "recommendations" ]; then
          if [ -z "$NAMESPACE" ]; then
            NAMESPACE="$1"
          else
            echo "Error: Unknown argument: $1"
            show_usage
            exit 1
          fi
        elif [ "$COMMAND" == "analyze" ]; then
          if [ -z "$2" ]; then
            SCC_NAME="$1"
          else
            echo "Error: Unknown argument: $1"
            show_usage
            exit 1
          fi
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

# Main function
main() {
  parse_args "$@"
  check_prereqs
  
  case "$COMMAND" in
    list)
      list_networkpolicies
      ;;
    audit)
      audit_networkpolicies
      ;;
    visualize)
      visualize_flows
      ;;
    coverage)
      check_policy_coverage
      ;;
    check)
      check_namespace "$NAMESPACE"
      ;;
    analyze)
      analyze_policy "$SCC_NAME"
      ;;
    gaps)
      identify_gaps
      ;;
    default-deny)
      check_default_deny
      ;;
    flows)
      generate_flow_matrix "$NAMESPACE"
      ;;
    pods)
      pod_communication_matrix "$NAMESPACE"
      ;;
    recommendations)
      generate_recommendations "$NAMESPACE"
      ;;
    simulate)
      simulate_traffic
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