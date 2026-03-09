#!/bin/bash

# ==============================================================================
# GCP COMPREHENSIVE PROJECT AUDIT SCRIPT - FIXED VERSION
# Description: Audits all accessible GCP projects for permissions, owners, 
#              services, and resource usage (read-only operations)
# ==============================================================================

# Remove strict error handling that causes premature exit
# set -euo pipefail  # <-- REMOVED -e which causes exit on any error

set -uo pipefail  # Keep -u (undefined vars) and -o pipefail, but not -e

# Colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Output directory for reports
REPORT_DIR="$HOME/gcp_audit_reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$REPORT_DIR/gcp_audit_${TIMESTAMP}.md"
JSON_REPORT="$REPORT_DIR/gcp_audit_${TIMESTAMP}.json"

# Create report directory
mkdir -p "$REPORT_DIR"

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

print_header() {
    echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════════${NC}\n"
}

print_section() {
    echo -e "\n${CYAN}▶ $1${NC}"
    echo -e "${CYAN}$(printf '─%.0s' {1..60})${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# ==============================================================================
# INITIALIZATION
# ==============================================================================

init_audit() {
    print_header "GCP PROJECT AUDIT TOOL"
    
    # Check if gcloud is installed
    if ! command -v gcloud &> /dev/null; then
        print_error "gcloud CLI not found. Please install Google Cloud SDK."
        exit 1
    fi
    
    # Check authentication
    CURRENT_ACCOUNT=$(gcloud config get-value account 2>/dev/null || echo "")
    if [[ -z "$CURRENT_ACCOUNT" ]]; then
        print_error "Not authenticated. Run: gcloud auth login"
        exit 1
    fi
    
    print_success "Authenticated as: $CURRENT_ACCOUNT"
    
    # Initialize JSON structure (safer approach)
    cat > "$JSON_REPORT" << EOF
{
  "audit_timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "auditor": "$CURRENT_ACCOUNT",
  "projects": []
}
EOF
    
    # Count total projects for progress
    TOTAL_PROJECTS=$(gcloud projects list --format="value(projectId)" 2>/dev/null | wc -l | tr -d ' ')
    print_info "Found $TOTAL_PROJECTS accessible projects"
    print_info "Reports will be saved to: $REPORT_DIR"
    sleep 2
}

# ==============================================================================
# PROJECT DISCOVERY
# ==============================================================================

get_all_projects() {
    print_section "DISCOVERING ACCESSIBLE PROJECTS"
    
    # Get all projects user has access to
    gcloud projects list --format="table(projectId,name,projectNumber,createTime,lifecycleState)" 2>/dev/null | tee -a "$REPORT_FILE"
    
    # Store project IDs in array
    PROJECTS=$(gcloud projects list --format="value(projectId)" 2>/dev/null)
    
    if [[ -z "$PROJECTS" ]]; then
        print_warning "No projects found or no access to any projects"
        return 1
    fi
    
    print_success "Discovered $TOTAL_PROJECTS projects"
    return 0
}

# ==============================================================================
# PERMISSIONS & IAM ANALYSIS
# ==============================================================================

analyze_project_permissions() {
    local project_id=$1
    local project_num=$2
    
    print_section "IAM POLICY ANALYSIS: $project_id"
    
    # Get IAM policy
    local iam_policy
    iam_policy=$(gcloud projects get-iam-policy "$project_id" --format=json 2>/dev/null) || {
        print_warning "Cannot get IAM policy for $project_id (insufficient permissions)"
        return 1
    }
    
    echo -e "\n${BOLD}Current User Permissions:${NC}"
    
    # Extract current user's roles - safer jq handling
    local user_roles=""
    if command -v jq &> /dev/null && [[ -n "$iam_policy" ]]; then
        user_roles=$(echo "$iam_policy" | jq -r --arg user "user:$CURRENT_ACCOUNT" --arg sa "serviceAccount:$CURRENT_ACCOUNT" '
            .bindings[]? | select(.members[]? | contains($user) or contains($sa)) | .role' 2>/dev/null | sort -u)
    fi
    
    if [[ -n "$user_roles" ]]; then
        echo "$user_roles" | while read -r role; do
            [[ -z "$role" ]] && continue
            echo "  • $role"
            # Get permissions for this role
            local permissions
            permissions=$(gcloud iam roles describe "$role" --format="value(includedPermissions)" 2>/dev/null | tr ';' '\n' | head -10)
            if [[ -n "$permissions" ]]; then
                echo "    Key permissions:"
                echo "$permissions" | sed 's/^/      - /'
            fi
        done
    else
        print_warning "No direct project-level roles found (may have inherited permissions)"
    fi
    
    # Check for basic roles (Owner/Editor/Viewer)
    echo -e "\n${BOLD}Project Owners:${NC}"
    if command -v jq &> /dev/null && [[ -n "$iam_policy" ]]; then
        echo "$iam_policy" | jq -r '.bindings[]? | select(.role == "roles/owner") | .members[]?' 2>/dev/null | sed 's/^/  • /' || echo "  None found"
    else
        echo "  (jq not available for parsing)"
    fi
    
    echo -e "\n${BOLD}Project Editors:${NC}"
    if command -v jq &> /dev/null && [[ -n "$iam_policy" ]]; then
        echo "$iam_policy" | jq -r '.bindings[]? | select(.role == "roles/editor") | .members[]?' 2>/dev/null | sed 's/^/  • /' || echo "  None found"
    fi
    
    echo -e "\n${BOLD}All IAM Bindings:${NC}"
    if command -v jq &> /dev/null && [[ -n "$iam_policy" ]]; then
        echo "$iam_policy" | jq -r '.bindings[]? | "\(.role): \(.members | join(", "))"' 2>/dev/null | sed 's/^/  • /' || echo "  Unable to parse"
    else
        echo "  (Raw IAM policy saved to JSON)"
    fi
    
    # Update JSON safely
    update_project_json "$project_id" "$iam_policy"
    
    return 0
}

# Safer JSON update function
update_project_json() {
    local project_id=$1
    local iam_policy="$2"
    
    # Create temp file with new project entry
    local temp_file="${JSON_REPORT}.tmp.$$"
    
    if command -v jq &> /dev/null; then
        # Safely update JSON using jq
        jq --arg proj "$project_id" --argjson policy "$iam_policy" \
           '(.projects[] | select(.projectId == $proj) | .iamPolicy) = $policy' \
           "$JSON_REPORT" > "$temp_file" 2>/dev/null && mv "$temp_file" "$JSON_REPORT" || {
            print_warning "Could not update JSON for $project_id"
            rm -f "$temp_file"
        }
    fi
}

# ==============================================================================
# ENABLED SERVICES ANALYSIS
# ==============================================================================

analyze_enabled_services() {
    local project_id=$1
    
    print_section "ENABLED SERVICES: $project_id"
    
    # List enabled services
    local services
    services=$(gcloud services list --project="$project_id" --format="table(config.name,config.title,state)" 2>/dev/null) || {
        print_warning "Cannot list services for $project_id"
        return 1
    }
    
    if [[ -n "$services" ]]; then
        echo "$services"
        local count
        count=$(echo "$services" | tail -n +2 | wc -l | tr -d ' ')
        print_success "$count services enabled"
    else
        print_warning "No services enabled or no permission to view"
    fi
    
    # Get high-impact services only
    echo -e "\n${BOLD}Key Infrastructure Services:${NC}"
    gcloud services list --project="$project_id" --format="value(config.name)" 2>/dev/null | grep -E "(compute|storage|bigquery|cloudsql|gke|run|functions|appengine)" | sed 's/^/  • /' || true
    
    return 0
}

# ==============================================================================
# RESOURCE INVENTORY (USING ASSET INVENTORY - FREE READ-ONLY)
# ==============================================================================

inventory_resources() {
    local project_id=$1
    
    print_section "RESOURCE INVENTORY: $project_id"
    
    # Check if Cloud Asset API is enabled
    if ! gcloud services list --project="$project_id" --format="value(config.name)" 2>/dev/null | grep -q "cloudasset.googleapis.com"; then
        print_warning "Cloud Asset API not enabled - using alternative discovery methods"
        
        # Fallback: Check specific resources manually
        check_compute_resources "$project_id"
        check_storage_resources "$project_id"
        check_gke_resources "$project_id"
        return 0
    fi
    
    # Use Asset Inventory to search all resources (FREE, read-only)
    print_info "Querying Cloud Asset Inventory..."
    
    # Count total resources
    local resource_count
    resource_count=$(gcloud asset search-all-resources --scope="projects/$project_id" --format="value(name)" 2>/dev/null | wc -l | tr -d ' ')
    print_success "Found $resource_count total resources"
    
    # List compute instances
    echo -e "\n${BOLD}Compute Instances:${NC}"
    gcloud asset search-all-resources \
        --scope="projects/$project_id" \
        --asset-types="compute.googleapis.com/Instance" \
        --format="table(displayName,location,state,labels)" 2>/dev/null | head -20 || echo "  None found"
    
    # List storage buckets
    echo -e "\n${BOLD}Storage Buckets:${NC}"
    gcloud asset search-all-resources \
        --scope="projects/$project_id" \
        --asset-types="storage.googleapis.com/Bucket" \
        --format="table(displayName,location,labels)" 2>/dev/null | head -10 || echo "  None found"
    
    # List Cloud SQL instances
    echo -e "\n${BOLD}Cloud SQL Instances:${NC}"
    gcloud asset search-all-resources \
        --scope="projects/$project_id" \
        --asset-types="sqladmin.googleapis.com/Instance" \
        --format="table(displayName,location,state)" 2>/dev/null | head -10 || echo "  None found"
    
    # List GKE clusters
    echo -e "\n${BOLD}GKE Clusters:${NC}"
    gcloud asset search-all-resources \
        --scope="projects/$project_id" \
        --asset-types="container.googleapis.com/Cluster" \
        --format="table(displayName,location,state)" 2>/dev/null | head -10 || echo "  None found"
    
    return 0
}

# Fallback resource checks
check_compute_resources() {
    local project_id=$1
    echo -e "\n${BOLD}Compute Instances:${NC}"
    gcloud compute instances list --project="$project_id" --format="table(name,zone,status,machineType)" 2>/dev/null | head -10 || echo "  None found or no access"
}

check_storage_resources() {
    local project_id=$1
    echo -e "\n${BOLD}Storage Buckets:${NC}"
    gsutil ls -p "$project_id" 2>/dev/null | head -10 || echo "  None found or no access"
}

check_gke_resources() {
    local project_id=$1
    echo -e "\n${BOLD}GKE Clusters:${NC}"
    gcloud container clusters list --project="$project_id" --format="table(name,location,status)" 2>/dev/null | head -10 || echo "  None found or no access"
}

# ==============================================================================
# BILLING INFORMATION (METADATA ONLY - NO COSTS)
# ==============================================================================

get_billing_info() {
    local project_id=$1
    
    print_section "BILLING INFORMATION: $project_id"
    
    # Get billing account info (metadata only)
    local billing_info
    billing_info=$(gcloud beta billing projects describe "$project_id" --format=json 2>/dev/null) || {
        print_warning "Cannot retrieve billing info for $project_id"
        return 1
    }
    
    local billing_account=""
    if command -v jq &> /dev/null && [[ -n "$billing_info" ]]; then
        billing_account=$(echo "$billing_info" | jq -r '.billingAccountName // "Not linked"')
    else
        billing_account="Unknown (jq not available)"
    fi
    
    if [[ "$billing_account" == "Not linked" ]]; then
        print_warning "No billing account linked"
    else
        print_success "Linked to: $billing_account"
        
        # Get billing account display name
        local account_name
        account_name=$(gcloud beta billing accounts describe "$billing_account" --format="value(displayName)" 2>/dev/null || echo "Unknown")
        echo "  Account Name: $account_name"
    fi
    
    # Note about cost data
    echo -e "\n${YELLOW}Note: Detailed cost data requires Billing Account Viewer permissions.${NC}"
    echo -e "${YELLOW}Visit https://console.cloud.google.com/billing/reports for detailed costs.${NC}"
    
    return 0
}

# ==============================================================================
# PROJECT METADATA
# ==============================================================================

get_project_metadata() {
    local project_id=$1
    
    print_section "PROJECT METADATA: $project_id"
    
    # Get detailed project info
    local proj_info
    proj_info=$(gcloud projects describe "$project_id" --format=json 2>/dev/null)
    
    if [[ -n "$proj_info" ]] && command -v jq &> /dev/null; then
        echo "$proj_info" | jq -r '
            "Project Number: \(.projectNumber // "N/A")",
            "Name: \(.name // "N/A")",
            "State: \(.lifecycleState // "N/A")",
            "Created: \(.createTime // "N/A")",
            "Parent: \(.parent // "None")",
            "Labels: \(.labels // "None")"
        ' 2>/dev/null | sed 's/^/  /'
        
        # Get organization info if available
        local org_id
        org_id=$(echo "$proj_info" | jq -r '.parent.id // empty' 2>/dev/null)
        if [[ -n "$org_id" ]] && [[ "$org_id" =~ ^[0-9]{10,}$ ]]; then
            echo "  Organization ID: $org_id"
        fi
    else
        # Fallback if jq not available
        gcloud projects describe "$project_id" --format="table(projectNumber,name,lifecycleState,createTime)" 2>/dev/null | sed 's/^/  /'
    fi
}

# ==============================================================================
# AUDIT TRAIL (ACTIVITY LOGS - RECENT ONLY)
# ==============================================================================

get_recent_activity() {
    local project_id=$1
    
    print_section "RECENT ACTIVITY (Last 7 Days): $project_id"
    
    # Read audit logs (requires logging.viewer permission)
    local activity
    activity=$(gcloud logging read "protoPayload.serviceName!=''" \
        --project="$project_id" \
        --limit=10 \
        --format="table(timestamp,protoPayload.methodName,protoPayload.authenticationInfo.principalEmail)" \
        --freshness=7d 2>/dev/null) || {
        print_warning "Cannot read activity logs (requires Logging Viewer permission)"
        return 1
    }
    
    if [[ -n "$activity" ]]; then
        echo "$activity"
    else
        print_info "No recent activity found"
    fi
}

# ==============================================================================
# MAIN AUDIT LOOP
# ==============================================================================

run_audit() {
    local current=0
    
    # Read projects into array properly
    local project_array=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && project_array+=("$line")
    done <<< "$PROJECTS"
    
    for project_id in "${project_array[@]}"; do
        [[ -z "$project_id" ]] && continue
        
        ((current++)) || true
        
        # Clear any previous error state
        :
        
        print_header "AUDITING PROJECT [$current/$TOTAL_PROJECTS]: $project_id"
        
        # Initialize project in JSON (safely)
        if command -v jq &> /dev/null; then
            local temp_file="${JSON_REPORT}.tmp.$$"
            jq --arg proj "$project_id" '.projects += [{"projectId": $proj, "status": "auditing"}]' \
               "$JSON_REPORT" > "$temp_file" 2>/dev/null && mv "$temp_file" "$JSON_REPORT" || rm -f "$temp_file"
        fi
        
        # Get project number
        local project_num
        project_num=$(gcloud projects describe "$project_id" --format="value(projectNumber)" 2>/dev/null || echo "unknown")
        
        # Run all audit functions with error handling
        get_project_metadata "$project_id" || true
        analyze_project_permissions "$project_id" "$project_num" || true
        analyze_enabled_services "$project_id" || true
        inventory_resources "$project_id" || true
        get_billing_info "$project_id" || true
        get_recent_activity "$project_id" || true
        
        # Update status (safely)
        if command -v jq &> /dev/null; then
            local temp_file="${JSON_REPORT}.tmp.$$"
            jq --arg proj "$project_id" '(.projects[] | select(.projectId == $proj) | .status) = "completed"' \
               "$JSON_REPORT" > "$temp_file" 2>/dev/null && mv "$temp_file" "$JSON_REPORT" || rm -f "$temp_file"
        fi
        
        echo -e "\n${GREEN}✓ Completed audit for $project_id${NC}"
        echo -e "${CYAN}$(printf '=%.0s' {1..60})${NC}"
        sleep 1
    done
}

# ==============================================================================
# REPORT GENERATION
# ==============================================================================

generate_summary() {
    print_header "AUDIT SUMMARY"
    
    local completed=0
    if [[ -f "$JSON_REPORT" ]] && command -v jq &> /dev/null; then
        completed=$(jq '.projects | length' "$JSON_REPORT" 2>/dev/null || echo "0")
    fi
    
    cat << EOF | tee -a "$REPORT_FILE"

================================================================================
                    GCP PROJECT AUDIT SUMMARY
================================================================================
Audit Date: $(date)
Auditor: $CURRENT_ACCOUNT
Total Projects Audited: $completed
Report Location: $REPORT_DIR

FILES GENERATED:
  • Markdown Report: $REPORT_FILE
  • JSON Data: $JSON_REPORT

RECOMMENDATIONS:
  1. Review IAM bindings for over-privileged accounts
  2. Check for unused enabled services to reduce attack surface
  3. Verify billing account linkage for cost tracking
  4. Monitor projects with Owner access from external accounts
  5. Enable Cloud Asset Inventory API for better resource visibility

NEXT STEPS:
  • For detailed cost analysis, visit: https://console.cloud.google.com/billing/reports
  • Export billing data to BigQuery for advanced analysis
  • Set up budget alerts for cost monitoring

================================================================================
EOF

    print_success "Audit complete! Reports saved to:"
    echo "  $REPORT_FILE"
    echo "  $JSON_REPORT"
}

# ==============================================================================
# SCRIPT ENTRY POINT
# ==============================================================================

main() {
    # Handle interrupts gracefully
    trap 'print_error "Audit interrupted"; exit 1' INT TERM
    
    init_audit
    get_all_projects
    run_audit
    generate_summary
}

# Run main function
main "$@"
