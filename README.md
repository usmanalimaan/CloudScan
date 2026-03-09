# GCP Comprehensive Project Audit Tool

A production-ready Bash script for security auditing and inventory discovery across Google Cloud Platform projects.

## Features

- 🔍 **Multi-Project Discovery** - Automatically audits all accessible projects
- 👥 **IAM Permission Analysis** - Maps roles, owners, and privilege escalation paths
- 🛠️ **Service Enumeration** - Identifies enabled APIs and potential attack surfaces
- 📦 **Resource Inventory** - Discovers Compute, Storage, GKE, and SQL resources
- 💰 **Billing Verification** - Checks account linkage status
- 📊 **Dual Report Output** - Markdown for humans, JSON for automation
- 🛡️ **Read-Only & Safe** - Zero risk to production environments

## Prerequisites

- [Google Cloud SDK](https://cloud.google.com/sdk/docs/install) installed
- Authenticated gcloud session (`gcloud auth login`)
- `jq` installed (optional but recommended for JSON processing)
- One of these IAM roles at organization/folder/project level:
  - `roles/viewer`
  - `roles/browser` 
  - `roles/securityReviewer`

## Installation

```bash
# Clone or download the script
curl -O https://raw.githubusercontent.com/yourrepo/gcp-audit/main/gcp_audit.sh
chmod +x gcp_audit.sh


Usage
bash
Copy
# Basic execution
./gcp_audit.sh

# Output
# Reports saved to: ~/gcp_audit_reports/
#   - gcp_audit_20240308_143022.md   (Human-readable)
#   - gcp_audit_20240308_143022.json (Machine-readable)
Report Contents
Markdown Report Includes:
Executive summary with recommendations
Per-project IAM policy analysis
Enabled services inventory
Resource counts and metadata
Recent activity logs (7 days)
Billing linkage status
JSON Structure:
JSON
Copy
{
  "audit_timestamp": "2024-03-08T14:30:22Z",
  "auditor": "user@company.com",
  "projects": [
    {
      "projectId": "my-project-123",
      "status": "completed",
      "iamPolicy": { ... }
    }
  ]
}
Permissions Required
Table
Feature	Required Permission
Project listing	resourcemanager.projects.list
IAM analysis	resourcemanager.projects.getIamPolicy
Service inventory	serviceusage.services.list
Resource discovery	cloudasset.assets.searchAllResources or service-specific viewer roles
Billing info	billing.resourceAssociations.get
Activity logs	logging.logEntries.list
Security Use Cases
Privilege Review - Identify over-provisioned service accounts
Shadow IT Discovery - Find unauthorized projects or resources
Compliance Baseline - Establish initial security posture
Offboarding Verification - Confirm removed access across all projects
M&A Due Diligence - Rapid infrastructure assessment
Limitations
Does not retrieve actual cost/spend data (requires Billing Account Viewer)
Cloud Asset Inventory API must be enabled for comprehensive resource discovery
Activity logs limited to 7 days (Logging retention dependent)
Subject to GCP API rate limits on large organizations
Troubleshooting
Table
Issue	Solution
gcloud: command not found	Install Google Cloud SDK
Cannot get IAM policy	Request roles/viewer on target project
Cloud Asset API not enabled	Enable at gcloud services enable cloudasset.googleapis.com
Empty JSON output	Install jq: apt-get install jq or brew install jq
License
MIT License - Use at your own risk for authorized security assessments only.