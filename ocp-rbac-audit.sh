#!/bin/bash

# ocp-rbac-audit.sh - OpenShift RBAC Auditing Tool
# A tool for security engineers to audit roles and role bindings for prohibited permissions

set -e
set -u

VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")

# Function to display usage information
show_usage() {
  cat << EOF
OpenShift RBAC Audit Tool v${VERSION}
A tool for security engineers to audit roles and permissions in OpenShift clusters

Usage:
  ${SCRIPT_NAME} [command] [options]

Commands:
  audit                          Audit prohibited permissions against all subjects
  define-prohibited              Define or update prohibited permissions
  list-prohibited                List currently defined prohibited permissions
  check-subject [subject]        Check if a specific subject has prohibited permissions
  check-role [role]              Check if a specific role has prohibited permissions
  check-ns [namespace]           Check all subjects in a namespace for prohibited permissions
  list-high-risk                 List subjects with high-risk permissions
  list-roles                     List all roles and clusterroles
  list-bindings                  List all rolebindings and clusterrolebindings
  help                           Show this help message

Options:
  -c, --config [file]            Path to the configuration file (default: .ocp-rbac-audit.conf)
  -n, --namespace [namespace]    Filter by namespace
  -s, --subject-type [type]      Filter by subject type (User, Group, or ServiceAccount)
  -v, --verbose                  Show detailed information
  -o, --output [format]          Output format: table (default), json, yaml
  -a, --all-namespaces           Include all namespaces
  -h, --help                     Show this help message
  --version                      Show version information

Examples:
  ${SCRIPT_NAME} define-prohibited
  ${SCRIPT_NAME} audit
  ${SCRIPT_NAME} check-subject User:system:admin
  ${SCRIPT_NAME} check-subject ServiceAccount:default -n kube-system
  ${SCRIPT_NAME} check-role cluster-admin
  ${SCRIPT_NAME} check-ns kube-system
  ${SCRIPT_NAME} list-high-risk

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
  
  if ! command -v jq &> /dev/null; then
    echo "Error: 'jq' command not found."
    echo "Please install jq for JSON processing."
    exit 1
  fi
}

# Function to create a default config file if it doesn't exist
create_default_config() {
  if [ ! -f "$CONFIG_FILE" ]; then
    echo "Creating default configuration file: $CONFIG_FILE"
    
    cat > "$CONFIG_FILE" << EOF
# OpenShift RBAC Audit Tool Configuration
# Format: <resource>:<verb>[,<verb>,...] 
# You can use wildcards '*' for resources or verbs
# Lines starting with '#' are comments

# High-risk API permissions
secrets:*
configmaps:*
pods:*
services:*
deployments:*
daemonsets:*
statefulsets:*
jobs:*
cronjobs:*
persistentvolumes:*
persistentvolumeclaims:*
storageclasses:*
nodes:*

# Security-critical permissions
security.openshift.io/*:*
securitycontextconstraints:*
oauth:*
users:*
groups:*
serviceaccounts:*
roles:*
rolebindings:*
clusterroles:*
clusterrolebindings:*

# Administrative permissions
*:escalate
*:impersonate
*:bind
*:deletecollection
namespaces:delete
projects:delete
EOF
    
    echo "Default prohibited permissions config created at $CONFIG_FILE"
    echo "Please review and edit this file to match your organization's security policy."
  fi
}

# Function to parse the config file
parse_config() {
  if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file not found: $CONFIG_FILE"
    create_default_config
  fi
  
  # Read prohibited permissions from config file
  PROHIBITED_PERMISSIONS=()
  
  while IFS= read -r line; do
    # Skip comments and empty lines
    if [[ ! "$line" =~ ^[[:space:]]*# && -n "$line" ]]; then
      PROHIBITED_PERMISSIONS+=("$line")
    fi
  done < "$CONFIG_FILE"
  
  if [ ${#PROHIBITED_PERMISSIONS[@]} -eq 0 ]; then
    echo "Warning: No prohibited permissions defined in $CONFIG_FILE"
    echo "Please run '${SCRIPT_NAME} define-prohibited' to define prohibited permissions."
  fi
}

# Function to check if a specific permission is prohibited
is_prohibited() {
  local resource="$1"
  local verb="$2"
  
  for permission in "${PROHIBITED_PERMISSIONS[@]}"; do
    local prohibited_resource=$(echo "$permission" | cut -d':' -f1)
    local prohibited_verbs=$(echo "$permission" | cut -d':' -f2)
    
    # Check if resource matches (direct or wildcard)
    if [[ "$prohibited_resource" == "*" || "$prohibited_resource" == "$resource" || 
          "$prohibited_resource" == "*/*" && "${prohibited_resource%/*}" == "${resource%/*}" && "${prohibited_resource#*/}" == "*" ]]; then
      
      # Check if verb matches (direct or in comma-separated list or wildcard)
      if [[ "$prohibited_verbs" == "*" ]]; then
        return 0  # Prohibited
      else
        IFS=',' read -ra VERB_ARRAY <<< "$prohibited_verbs"
        for prohibited_verb in "${VERB_ARRAY[@]}"; do
          if [[ "$prohibited_verb" == "$verb" ]]; then
            return 0  # Prohibited
          fi
        done
      fi
    fi
  done
  
  return 1  # Not prohibited
}

# Function to let user interactively define prohibited permissions
define_prohibited_permissions() {
  local temp_file=$(mktemp)
  
  if [ -f "$CONFIG_FILE" ]; then
    cp "$CONFIG_FILE" "$temp_file"
  else
    create_default_config
    cp "$CONFIG_FILE" "$temp_file"
  fi
  
  echo "Opening editor to define prohibited permissions..."
  ${VISUAL:-${EDITOR:-vi}} "$temp_file"
  
  echo "Validating configuration format..."
  local invalid_lines=0
  while IFS= read -r line; do
    # Skip comments and empty lines
    if [[ ! "$line" =~ ^[[:space:]]*# && -n "$line" ]]; then
      # Check format: resource:verb[,verb,...]
      if ! [[ "$line" =~ ^[a-zA-Z0-9./*-]+:[a-zA-Z*,]+$ ]]; then
        echo "Invalid format: $line"
        echo "Format should be: <resource>:<verb>[,<verb>,...]"
        invalid_lines=$((invalid_lines + 1))
      fi
    fi
  done < "$temp_file"
  
  if [ $invalid_lines -gt 0 ]; then
    echo "Error: Found $invalid_lines invalid lines in configuration."
    echo "Configuration not updated. Please fix and try again."
    rm "$temp_file"
    exit 1
  fi
  
  mv "$temp_file" "$CONFIG_FILE"
  echo "Updated prohibited permissions configuration saved to $CONFIG_FILE"
}

# Function to list prohibited permissions
list_prohibited_permissions() {
  parse_config
  
  echo "Prohibited Permissions:"
  
  if [ ${#PROHIBITED_PERMISSIONS[@]} -eq 0 ]; then
    echo "No prohibited permissions defined."
    return
  fi
  
  echo "RESOURCE\tVERBS"
  for permission in "${PROHIBITED_PERMISSIONS[@]}"; do
    local resource=$(echo "$permission" | cut -d':' -f1)
    local verbs=$(echo "$permission" | cut -d':' -f2)
    
    echo "$resource\t$verbs"
  done
}

# Function to get all subjects with their roles
get_all_subjects() {
  local namespace="$1"
  local ns_option=""
  
  if [ -n "$namespace" ] && [ "$namespace" != "all" ]; then
    ns_option="-n \"$namespace\""
  else
    ns_option="--all-namespaces"
  fi
  
  # Get all role bindings
  local bindings
  if [ "$namespace" == "all" ] || [ -z "$namespace" ]; then
    # Get both cluster role bindings and role bindings from all namespaces
    bindings=$(oc get rolebinding,clusterrolebinding -o json --all-namespaces | jq '.items[]')
  else
    # Get only role bindings from specified namespace
    bindings=$(oc get rolebinding -n "$namespace" -o json | jq '.items[]')
  fi
  
  # Process each binding to extract subjects and roles
  echo "$bindings" | jq -r '
    {
      kind: .kind,
      name: .metadata.name,
      namespace: (.metadata.namespace // "cluster-wide"),
      roleName: .roleRef.name,
      roleKind: .roleRef.kind,
      subjects: (.subjects // [])
    } | 
    if .subjects | length > 0 then
      .subjects[] as $subject | 
      {
        bindingKind: .kind,
        bindingName: .name,
        bindingNamespace: .namespace,
        roleKind: .roleKind,
        roleName: .roleName,
        subjectKind: $subject.kind,
        subjectName: $subject.name,
        subjectNamespace: ($subject.namespace // "default")
      }
    else
      empty
    end
  '
}

# Function to get permissions for a role
get_role_permissions() {
  local role_kind="$1"
  local role_name="$2"
  local namespace="$3"
  
  local role_json
  
  if [ "$role_kind" == "ClusterRole" ]; then
    role_json=$(oc get clusterrole "$role_name" -o json 2>/dev/null || echo '{}')
  else
    role_json=$(oc get role "$role_name" -n "$namespace" -o json 2>/dev/null || echo '{}')
  fi
  
  # Extract rules from the role
  echo "$role_json" | jq -r '(.rules // [])'
}

# Function to verify if a role has prohibited permissions
check_role_for_prohibited() {
  local role_kind="$1"
  local role_name="$2"
  local namespace="$3"
  
  local prohibited_found=0
  local prohibited_details=""
  
  # Get role permissions
  local role_rules=$(get_role_permissions "$role_kind" "$role_name" "$namespace")
  
  # For each rule in the role - using process substitution to avoid subshell issues
  while read -r rule; do
    local apiGroups=$(echo "$rule" | jq -r '(.apiGroups // [""])')
    local resources=$(echo "$rule" | jq -r '(.resources // [])')
    local verbs=$(echo "$rule" | jq -r '(.verbs // [])')
    
    # Check each combination of API group, resource, and verb
    while read -r apiGroup; do
      while read -r resource; do
        # Combine API group and resource correctly
        local full_resource
        if [ "$apiGroup" == "" ]; then
          full_resource="$resource"
        else
          full_resource="${apiGroup}/${resource}"
        fi
        
        while read -r verb; do
          if is_prohibited "$full_resource" "$verb"; then
            prohibited_found=1
            prohibited_details="${prohibited_details}${full_resource}:${verb}\n"
          fi
        done < <(echo "$verbs" | jq -r '.[]')
      done < <(echo "$resources" | jq -r '.[]')
    done < <(echo "$apiGroups" | jq -r '.[]')
  done < <(echo "$role_rules" | jq -c '.[]')
  
  if [ $prohibited_found -eq 1 ]; then
    echo -e "$prohibited_details"
    return 0  # Prohibited permissions found
  else
    return 1  # No prohibited permissions found
  fi
}

# Function to check a specific subject for prohibited permissions
check_subject() {
  local subject_type="$1"
  local subject_name="$2"
  local namespace="$3"
  
  parse_config
  
  # Determine the query namespace based on input
  local query_namespace
  if [ -n "$namespace" ] && [ "$namespace" != "all" ]; then
    query_namespace="$namespace"
  else
    query_namespace="all"
  fi
  
  echo "Checking subject $subject_type:$subject_name for prohibited permissions..."
  
  # Get all roles bound to this subject
  local subject_roles=$(get_all_subjects "$query_namespace" | 
    jq -r --arg kind "$subject_type" --arg name "$subject_name" 'select(.subjectKind == $kind and .subjectName == $name)')
  
  if [ -z "$subject_roles" ]; then
    echo "No roles found for $subject_type:$subject_name in namespace $query_namespace"
    return
  fi
  
  echo "BINDING_KIND\tBINDING_NAME\tBINDING_NAMESPACE\tROLE_KIND\tROLE_NAME\tPROHIBITED_PERMISSIONS"
  
  # Check each role
  while read -r role_entry; do
    local binding_kind=$(echo "$role_entry" | jq -r '.bindingKind')
    local binding_name=$(echo "$role_entry" | jq -r '.bindingName')
    local binding_namespace=$(echo "$role_entry" | jq -r '.bindingNamespace')
    local role_kind=$(echo "$role_entry" | jq -r '.roleKind')
    local role_name=$(echo "$role_entry" | jq -r '.roleName')
    
    local prohibited_perms=$(check_role_for_prohibited "$role_kind" "$role_name" "$binding_namespace")
    
    if [ -n "$prohibited_perms" ]; then
      echo "$binding_kind\t$binding_name\t$binding_namespace\t$role_kind\t$role_name\t$prohibited_perms"
    elif [ "$VERBOSE" == "true" ]; then
      echo "$binding_kind\t$binding_name\t$binding_namespace\t$role_kind\t$role_name\tNone"
    fi
  done < <(echo "$subject_roles")
}

# Function to check a specific role for prohibited permissions
check_role() {
  local role_name="$1"
  local namespace="$2"
  
  parse_config
  
  # Determine if this is a cluster role or namespace role
  local role_kind="Role"
  local role_exists
  
  # Try to get the role from the namespace
  if [ -n "$namespace" ]; then
    role_exists=$(oc get role "$role_name" -n "$namespace" 2>/dev/null)
    if [ -z "$role_exists" ]; then
      echo "Role '$role_name' not found in namespace '$namespace'"
      return 1
    fi
  else
    # Try as cluster role
    role_exists=$(oc get clusterrole "$role_name" 2>/dev/null)
    if [ -n "$role_exists" ]; then
      role_kind="ClusterRole"
    else
      echo "ClusterRole '$role_name' not found"
      return 1
    fi
  fi
  
  echo "Checking $role_kind '$role_name' for prohibited permissions..."
  
  # Check the role for prohibited permissions
  local prohibited_perms=$(check_role_for_prohibited "$role_kind" "$role_name" "$namespace")
  
  if [ -n "$prohibited_perms" ]; then
    echo "Prohibited permissions found in $role_kind '$role_name':"
    echo "$prohibited_perms" | sort | uniq | sed 's/^/  /'
  else
    echo "No prohibited permissions found in $role_kind '$role_name'"
  fi
  
  # Check which subjects are bound to this role
  echo ""
  echo "Subjects bound to this $role_kind:"
  
  local bindings
  if [ "$role_kind" == "ClusterRole" ]; then
    # Get cluster role bindings directly to this role
    bindings=$(oc get clusterrolebinding -o json | 
      jq -r --arg role "$role_name" '.items[] | select(.roleRef.name == $role and .roleRef.kind == "ClusterRole")')
    
    # Get role bindings to this cluster role
    local rb_bindings
    rb_bindings=$(oc get rolebinding --all-namespaces -o json | 
      jq -r --arg role "$role_name" '.items[] | select(.roleRef.name == $role and .roleRef.kind == "ClusterRole")')
    if [ -n "$rb_bindings" ]; then
      if [ -n "$bindings" ]; then
        bindings="$bindings
$rb_bindings"
      else
        bindings="$rb_bindings"
      fi
    fi
  else
    # Get role bindings to this role in the namespace
    bindings=$(oc get rolebinding -n "$namespace" -o json | 
      jq -r --arg role "$role_name" '.items[] | select(.roleRef.name == $role and .roleRef.kind == "Role")')
  fi
  
  if [ -z "$bindings" ]; then
    echo "  No subjects are bound to this $role_kind"
    return 0
  fi
  
  echo "BINDING_KIND\tBINDING_NAME\tNAMESPACE\tSUBJECT_KIND\tSUBJECT_NAME"
  echo "$bindings" | jq -r '.kind as $kind | .metadata.name as $name | .metadata.namespace as $ns | 
    .subjects[] | [$kind, $name, $ns, .kind, .name] | join("\t")'
}

# Function to check all subjects in a namespace
check_namespace() {
  local namespace="$1"
  
  parse_config
  
  # Validate namespace exists
  local ns_exists=$(oc get namespace "$namespace" 2>/dev/null)
  if [ -z "$ns_exists" ]; then
    echo "Error: Namespace '$namespace' not found"
    return 1
  fi
  
  echo "Checking all subjects in namespace '$namespace' for prohibited permissions..."
  
  # Get all subjects in namespace
  local ns_subjects=$(get_all_subjects "$namespace" | 
    jq -r '[.subjectKind, .subjectName] | join(":")' | sort | uniq)
  
  if [ -z "$ns_subjects" ]; then
    echo "No subjects found in namespace '$namespace'"
    return 0
  fi
  
  # Check each subject
  while read -r subject; do
    local subject_type=$(echo "$subject" | cut -d':' -f1)
    local subject_name=$(echo "$subject" | cut -d':' -f2)
    
    echo ""
    echo "Subject: $subject_type:$subject_name"
    echo "----------------------------------------------------------"
    check_subject "$subject_type" "$subject_name" "$namespace"
  done < <(echo "$ns_subjects")
}

# Function to list subjects with high-risk permissions
list_high_risk_subjects() {
  parse_config
  
  echo "Finding subjects with high-risk permissions..."
  
  # Get all subjects and their roles
  local all_subjects=$(get_all_subjects "all")
  
  # Process each subject-role combination
  echo "SUBJECT_TYPE\tSUBJECT_NAME\tBINDING_KIND\tBINDING_NAME\tBINDING_NAMESPACE\tROLE_KIND\tROLE_NAME\tPROHIBITED_PERMISSIONS"
  
  while read -r subject_entry; do
    local subject_kind=$(echo "$subject_entry" | jq -r '.subjectKind')
    local subject_name=$(echo "$subject_entry" | jq -r '.subjectName')
    local binding_kind=$(echo "$subject_entry" | jq -r '.bindingKind')
    local binding_name=$(echo "$subject_entry" | jq -r '.bindingName')
    local binding_namespace=$(echo "$subject_entry" | jq -r '.bindingNamespace')
    local role_kind=$(echo "$subject_entry" | jq -r '.roleKind')
    local role_name=$(echo "$subject_entry" | jq -r '.roleName')
    
    local prohibited_perms=$(check_role_for_prohibited "$role_kind" "$role_name" "$binding_namespace")
    
    if [ -n "$prohibited_perms" ]; then
      echo "$subject_kind\t$subject_name\t$binding_kind\t$binding_name\t$binding_namespace\t$role_kind\t$role_name\t$prohibited_perms"
    fi
  done < <(echo "$all_subjects")
}

# Function to list all roles and cluster roles
list_roles() {
  local namespace="$1"
  
  # Set namespace options
  local ns_option=""
  if [ -n "$namespace" ] && [ "$namespace" != "all" ]; then
    ns_option="-n $namespace"
    echo "Listing roles in namespace '$namespace':"
  else
    ns_option="--all-namespaces"
    echo "Listing all roles across all namespaces:"
  fi
  
  # List roles
  if [ "$namespace" == "all" ] || [ -z "$namespace" ]; then
    echo "NAMESPACE\tNAME\tTYPE"
    echo "cluster-wide\t$(oc get clusterroles -o name | wc -l)\tClusterRole"
    oc get namespace -o name | cut -d'/' -f2 | while read -r ns; do
      local role_count=$(oc get roles -n "$ns" -o name 2>/dev/null | wc -l)
      if [ "$role_count" -gt 0 ]; then
        echo "$ns\t$role_count\tRole"
      fi
    done
  else
    echo "NAME\tKIND\tAGE"
    oc get roles -n "$namespace" -o custom-columns=NAME:.metadata.name,KIND:.kind,AGE:.metadata.creationTimestamp
  fi
  
  echo ""
  echo "Total ClusterRoles: $(oc get clusterroles -o name | wc -l)"
  echo "Total Roles: $(oc get roles --all-namespaces -o name | wc -l)"
}

# Function to list all role bindings and cluster role bindings
list_bindings() {
  local namespace="$1"
  
  # Set namespace options
  local ns_option=""
  if [ -n "$namespace" ] && [ "$namespace" != "all" ]; then
    ns_option="-n $namespace"
    echo "Listing role bindings in namespace '$namespace':"
  else
    ns_option="--all-namespaces"
    echo "Listing all role bindings across all namespaces:"
  fi
  
  # List bindings
  if [ "$namespace" == "all" ] || [ -z "$namespace" ]; then
    echo "NAMESPACE\tNAME\tTYPE"
    echo "cluster-wide\t$(oc get clusterrolebindings -o name | wc -l)\tClusterRoleBinding"
    oc get namespace -o name | cut -d'/' -f2 | while read -r ns; do
      local binding_count=$(oc get rolebindings -n "$ns" -o name 2>/dev/null | wc -l)
      if [ "$binding_count" -gt 0 ]; then
        echo "$ns\t$binding_count\tRoleBinding"
      fi
    done
  else
    echo "NAME\tROLE\tSUBJECTS"
    oc get rolebindings -n "$namespace" -o custom-columns=NAME:.metadata.name,ROLE:.roleRef.name,SUBJECTS:.subjects[*].name
  fi
  
  echo ""
  echo "Total ClusterRoleBindings: $(oc get clusterrolebindings -o name | wc -l)"
  echo "Total RoleBindings: $(oc get rolebindings --all-namespaces -o name | wc -l)"
}

# Function to audit all subjects against prohibited permissions
audit_all_subjects() {
  parse_config
  
  echo "Auditing all subjects for prohibited permissions..."
  
  # Get all subjects and their roles
  local all_subjects=$(get_all_subjects "all")
  
  # Process each subject and their roles
  echo "SUBJECT_TYPE\tSUBJECT_NAME\tBINDING_NAMESPACE\tROLE_KIND\tROLE_NAME\tPROHIBITED_PERMISSION"
  
  while read -r subject_entry; do
    local subject_kind=$(echo "$subject_entry" | jq -r '.subjectKind')
    local subject_name=$(echo "$subject_entry" | jq -r '.subjectName')
    local binding_namespace=$(echo "$subject_entry" | jq -r '.bindingNamespace')
    local role_kind=$(echo "$subject_entry" | jq -r '.roleKind')
    local role_name=$(echo "$subject_entry" | jq -r '.roleName')
    
    # Skip subjects if subject type filter is set
    if [ -n "$SUBJECT_TYPE" ] && [ "$subject_kind" != "$SUBJECT_TYPE" ]; then
      continue
    fi
    
    # Skip subjects if namespace filter is set
    if [ -n "$NAMESPACE" ] && [ "$NAMESPACE" != "all" ] && [ "$binding_namespace" != "$NAMESPACE" ]; then
      continue
    fi
    
    local prohibited_perms=$(check_role_for_prohibited "$role_kind" "$role_name" "$binding_namespace")
    
    if [ -n "$prohibited_perms" ]; then
      while read -r perm; do
        if [ -n "$perm" ]; then
          echo "$subject_kind\t$subject_name\t$binding_namespace\t$role_kind\t$role_name\t$perm"
        fi
      done < <(echo -e "$prohibited_perms")
    fi
  done < <(echo "$all_subjects")
}

# Parse command line arguments
parse_args() {
  COMMAND=""
  CONFIG_FILE=".ocp-rbac-audit.conf"
  NAMESPACE=""
  SUBJECT_TYPE=""
  VERBOSE=false
  OUTPUT_FORMAT="table"
  ALL_NAMESPACES=false
  SUBJECT_NAME=""
  ROLE_NAME=""
  
  while [[ $# -gt 0 ]]; do
    case "$1" in
      audit|define-prohibited|list-prohibited|check-subject|check-role|check-ns|list-high-risk|list-roles|list-bindings|help)
        COMMAND="$1"
        shift
        ;;
      -c|--config)
        if [[ $# -lt 2 ]] || [[ "$2" == -* ]]; then
          echo "Error: Missing argument for $1"
          exit 1
        fi
        CONFIG_FILE="$2"
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
      -s|--subject-type)
        if [[ $# -lt 2 ]] || [[ "$2" == -* ]]; then
          echo "Error: Missing argument for $1"
          exit 1
        fi
        SUBJECT_TYPE="$2"
        shift 2
        ;;
      -v|--verbose)
        VERBOSE=true
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
      -a|--all-namespaces)
        ALL_NAMESPACES=true
        NAMESPACE="all"
        shift
        ;;
      -h|--help)
        show_usage
        exit 0
        ;;
      --version)
        echo "OpenShift RBAC Audit Tool v${VERSION}"
        exit 0
        ;;
      *)
        # For commands that take a positional argument
        if [ "$COMMAND" == "check-subject" ]; then
          if [ -z "$SUBJECT_NAME" ]; then
            SUBJECT_NAME="$1"
          else
            echo "Error: Unknown argument: $1"
            show_usage
            exit 1
          fi
        elif [ "$COMMAND" == "check-role" ]; then
          if [ -z "$ROLE_NAME" ]; then
            ROLE_NAME="$1"
          else
            echo "Error: Unknown argument: $1"
            show_usage
            exit 1
          fi
        elif [ "$COMMAND" == "check-ns" ]; then
          if [ -z "$NAMESPACE" ]; then
            NAMESPACE="$1"
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
  
  # Handle all namespaces flag
  if [ "$ALL_NAMESPACES" == "true" ]; then
    NAMESPACE="all"
  fi
}

# Main function
main() {
  parse_args "$@"
  check_prereqs
  
  case "$COMMAND" in
    audit)
      audit_all_subjects
      ;;
    define-prohibited)
      define_prohibited_permissions
      ;;
    list-prohibited)
      list_prohibited_permissions
      ;;
    check-subject)
      local subject_parts=("${SUBJECT_NAME//:/ }")
      if [ ${#subject_parts[@]} -ne 2 ]; then
        echo "Error: Subject must be in format 'Type:Name'"
        echo "Example: User:admin or ServiceAccount:default"
        exit 1
      fi
      check_subject "${subject_parts[0]}" "${subject_parts[1]}" "$NAMESPACE"
      ;;
    check-role)
      check_role "$ROLE_NAME" "$NAMESPACE"
      ;;
    check-ns)
      check_namespace "$NAMESPACE"
      ;;
    list-high-risk)
      list_high_risk_subjects
      ;;
    list-roles)
      list_roles "$NAMESPACE"
      ;;
    list-bindings)
      list_bindings "$NAMESPACE"
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