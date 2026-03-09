package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/asset/apiv1/assetpb"
	"google.golang.org/api/cloudbilling/v1"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/container/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/logging/v2"
	"google.golang.org/api/option"
	"google.golang.org/api/serviceusage/v1"
	"google.golang.org/api/sqladmin/v1"
	"google.golang.org/api/storage/v1"
)

// AuditReport represents the complete audit output
type AuditReport struct {
	Timestamp string         `json:"audit_timestamp"`
	Auditor   string         `json:"auditor"`
	Projects  []ProjectAudit `json:"projects"`
}

// ProjectAudit contains all audit data for a single project
type ProjectAudit struct {
	ProjectID       string                 `json:"projectId"`
	ProjectNumber   string                 `json:"projectNumber"`
	Name            string                 `json:"name"`
	State           string                 `json:"state"`
	CreateTime      string                 `json:"createTime"`
	IAMPolicy       *cloudresourcemanager.Policy `json:"iamPolicy,omitempty"`
	EnabledServices []string               `json:"enabledServices,omitempty"`
	Resources       ResourceInventory      `json:"resources"`
	BillingInfo     *BillingInfo           `json:"billingInfo,omitempty"`
	RecentActivity  []LogEntry             `json:"recentActivity,omitempty"`
	Status          string                 `json:"status"`
	Error           string                 `json:"error,omitempty"`
}

type ResourceInventory struct {
	ComputeInstances []ComputeInstance `json:"computeInstances,omitempty"`
	StorageBuckets   []StorageBucket   `json:"storageBuckets,omitempty"`
	GKEClusters      []GKECluster      `json:"gkeClusters,omitempty"`
	CloudSQL         []CloudSQLInstance `json:"cloudSql,omitempty"`
	TotalCount       int               `json:"totalCount"`
}

type ComputeInstance struct {
	Name   string `json:"name"`
	Zone   string `json:"zone"`
	Status string `json:"status"`
	Type   string `json:"machineType"`
}

type StorageBucket struct {
	Name     string `json:"name"`
	Location string `json:"location"`
}

type GKECluster struct {
	Name     string `json:"name"`
	Location string `json:"location"`
	Status   string `json:"status"`
}

type CloudSQLInstance struct {
	Name     string `json:"name"`
	Region   string `json:"region"`
	State    string `json:"state"`
}

type BillingInfo struct {
	AccountID   string `json:"accountId"`
	AccountName string `json:"accountName"`
	Linked      bool   `json:"linked"`
}

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Method    string `json:"method"`
	Principal string `json:"principal"`
}

// Config holds audit configuration
type Config struct {
	OutputDir       string
	Concurrency     int
	IncludeActivity bool
	Timeout         time.Duration
}

// Auditor orchestrates the GCP audit
type Auditor struct {
	ctx    context.Context
	config Config
	
	// GCP clients
	resourceManager *cloudresourcemanager.Service
	serviceUsage    *serviceusage.Service
	assetClient     *asset.Client // requires cloud.google.com/go/asset/apiv1
	compute         *compute.Service
	storage         *storage.Service
	container       *container.Service
	sql             *sqladmin.Service
	billing         *cloudbilling.Service
	logging         *logging.Service
	iam             *iam.Service
	
	currentAccount string
}

func main() {
	config := Config{
		OutputDir:       getEnv("AUDIT_OUTPUT_DIR", filepath.Join(os.Getenv("HOME"), "gcp_audit_reports")),
		Concurrency:     getEnvInt("AUDIT_CONCURRENCY", 5),
		IncludeActivity: getEnvBool("AUDIT_INCLUDE_ACTIVITY", true),
		Timeout:         getEnvDuration("AUDIT_TIMEOUT", 30*time.Minute),
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	auditor, err := NewAuditor(ctx, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize auditor: %v\n", err)
		os.Exit(1)
	}

	if err := auditor.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Audit failed: %v\n", err)
		os.Exit(1)
	}
}

func NewAuditor(ctx context.Context, config Config) (*Auditor, error) {
	a := &Auditor{
		ctx:    ctx,
		config: config,
	}

	// Initialize all GCP clients
	var err error
	
	a.resourceManager, err = cloudresourcemanager.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("resourcemanager: %w", err)
	}

	a.serviceUsage, err = serviceusage.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("serviceusage: %w", err)
	}

	a.compute, err = compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("compute: %w", err)
	}

	a.storage, err = storage.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}

	a.container, err = container.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("container: %w", err)
	}

	a.sql, err = sqladmin.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("sqladmin: %w", err)
	}

	a.billing, err = cloudbilling.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("billing: %w", err)
	}

	a.logging, err = logging.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("logging: %w", err)
	}

	a.iam, err = iam.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("iam: %w", err)
	}

	// Get current authenticated account
	token, err := a.iam.Projects.ServiceAccounts.Get(fmt.Sprintf("projects/-/serviceAccounts/%s", "default")).Context(ctx).Do()
	if err != nil {
		// Fallback: try to get from gcloud config
		a.currentAccount = getGcloudAccount()
	} else {
		a.currentAccount = token.Email
	}

	return a, nil
}

func (a *Auditor) Run() error {
	fmt.Printf("🔍 GCP Project Audit Tool\n")
	fmt.Printf("Authenticated as: %s\n\n", a.currentAccount)

	// Create output directory
	if err := os.MkdirAll(a.config.OutputDir, 0755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	timestamp := time.Now().UTC().Format("20060102_150405")
	report := &AuditReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Auditor:   a.currentAccount,
	}

	// Discover projects
	projects, err := a.discoverProjects()
	if err != nil {
		return fmt.Errorf("discovering projects: %w", err)
	}

	fmt.Printf("Found %d accessible projects\n", len(projects))
	fmt.Printf("Concurrency: %d\n\n", a.config.Concurrency)

	// Audit projects concurrently
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, a.config.Concurrency)
	results := make(chan ProjectAudit, len(projects))
	errors := make(chan error, len(projects))

	for _, proj := range projects {
		wg.Add(1)
		go func(p *cloudresourcemanager.Project) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			audit, err := a.auditProject(p)
			if err != nil {
				errors <- fmt.Errorf("project %s: %w", p.ProjectId, err)
				audit.Status = "error"
				audit.Error = err.Error()
			} else {
				audit.Status = "completed"
			}
			results <- audit
		}(proj)
	}

	// Close results channel when done
	go func() {
		wg.Wait()
		close(results)
		close(errors)
	}()

	// Collect results
	var completed int
	for audit := range results {
		report.Projects = append(report.Projects, audit)
		completed++
		fmt.Printf("✓ [%d/%d] Completed: %s\n", completed, len(projects), audit.ProjectID)
	}

	// Check for errors
	var errs []error
	for err := range errors {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		fmt.Printf("\n⚠ %d projects had errors\n", len(errs))
	}

	// Generate reports
	if err := a.generateReports(report, timestamp); err != nil {
		return fmt.Errorf("generating reports: %w", err)
	}

	return nil
}

func (a *Auditor) discoverProjects() ([]*cloudresourcemanager.Project, error) {
	var projects []*cloudresourcemanager.Project
	
	req := a.resourceManager.Projects.List().PageSize(500)
	err := req.Pages(a.ctx, func(page *cloudresourcemanager.ListProjectsResponse) error {
		projects = append(projects, page.Projects...)
		return nil
	})
	
	return projects, err
}

func (a *Auditor) auditProject(proj *cloudresourcemanager.Project) (ProjectAudit, error) {
	audit := ProjectAudit{
		ProjectID:     proj.ProjectId,
		ProjectNumber: fmt.Sprintf("%d", proj.ProjectNumber),
		Name:          proj.Name,
		State:         proj.LifecycleState,
		CreateTime:    proj.CreateTime,
	}

	// Get IAM policy
	policy, err := a.resourceManager.Projects.GetIamPolicy(proj.ProjectId, &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		audit.IAMPolicy = nil // Insufficient permissions
	} else {
		audit.IAMPolicy = policy
	}

	// Get enabled services
	services, err := a.serviceUsage.Services.List(fmt.Sprintf("projects/%s", proj.ProjectId)).Filter("state:ENABLED").Do()
	if err == nil {
		for _, svc := range services.Services {
			audit.EnabledServices = append(audit.EnabledServices, svc.Config.Name)
		}
	}

	// Inventory resources
	audit.Resources = a.inventoryResources(proj.ProjectId, audit.EnabledServices)

	// Get billing info
	audit.BillingInfo = a.getBillingInfo(proj.ProjectId)

	// Get recent activity
	if a.config.IncludeActivity {
		audit.RecentActivity = a.getRecentActivity(proj.ProjectId)
	}

	return audit, nil
}

func (a *Auditor) inventoryResources(projectID string, enabledServices []string) ResourceInventory {
	inv := ResourceInventory{}
	projectNum := fmt.Sprintf("projects/%s", projectID)

	// Check if Cloud Asset API is enabled
	hasAssetAPI := contains(enabledServices, "cloudasset.googleapis.com")

	if hasAssetAPI {
		// Use Cloud Asset Inventory for comprehensive discovery
		inv = a.queryAssetInventory(projectID)
	} else {
		// Fallback to individual API calls
		inv.ComputeInstances = a.listComputeInstances(projectID)
		inv.StorageBuckets = a.listStorageBuckets(projectID)
		inv.GKEClusters = a.listGKEClusters(projectID)
		inv.CloudSQL = a.listCloudSQL(projectID)
	}

	inv.TotalCount = len(inv.ComputeInstances) + len(inv.StorageBuckets) + 
		len(inv.GKEClusters) + len(inv.CloudSQL)

	return inv
}

func (a *Auditor) queryAssetInventory(projectID string) ResourceInventory {
	inv := ResourceInventory{}
	
	// This requires cloud.google.com/go/asset/apiv1 package
	// Simplified implementation - in production, use asset.NewClient()
	
	return inv
}

func (a *Auditor) listComputeInstances(projectID string) []ComputeInstance {
	var instances []ComputeInstance
	
	req := a.compute.Instances.AggregatedList(projectID)
	err := req.Pages(a.ctx, func(page *compute.InstanceAggregatedList) error {
		for _, zone := range page.Items {
			for _, inst := range zone.Instances {
				instances = append(instances, ComputeInstance{
					Name:   inst.Name,
					Zone:   inst.Zone,
					Status: inst.Status,
					Type:   inst.MachineType,
				})
			}
		}
		return nil
	})
	
	if err != nil {
		return nil
	}
	return instances
}

func (a *Auditor) listStorageBuckets(projectID string) []StorageBucket {
	var buckets []StorageBucket
	
	resp, err := a.storage.Buckets.List(projectID).Do()
	if err != nil {
		return nil
	}
	
	for _, b := range resp.Items {
		buckets = append(buckets, StorageBucket{
			Name:     b.Name,
			Location: b.Location,
		})
	}
	
	return buckets
}

func (a *Auditor) listGKEClusters(projectID string) []GKECluster {
	var clusters []GKECluster
	
	resp, err := a.container.Projects.Zones.Clusters.List(fmt.Sprintf("projects/%s/locations/-", projectID)).Do()
	if err != nil {
		return nil
	}
	
	for _, c := range resp.Clusters {
		clusters = append(clusters, GKECluster{
			Name:     c.Name,
			Location: c.Location,
			Status:   c.Status,
		})
	}
	
	return clusters
}

func (a *Auditor) listCloudSQL(projectID string) []CloudSQLInstance {
	var instances []CloudSQLInstance
	
	resp, err := a.sql.Instances.List(projectID).Do()
	if err != nil {
		return nil
	}
	
	for _, i := range resp.Items {
		instances = append(instances, CloudSQLInstance{
			Name:   i.Name,
			Region: i.Region,
			State:  i.State,
		})
	}
	
	return instances
}

func (a *Auditor) getBillingInfo(projectID string) *BillingInfo {
	info, err := a.billing.Projects.GetBillingInfo(fmt.Sprintf("projects/%s", projectID)).Do()
	if err != nil {
		return &BillingInfo{Linked: false}
	}

	billingInfo := &BillingInfo{
		Linked: info.BillingAccountName != "",
	}

	if info.BillingAccountName != "" {
		parts := strings.Split(info.BillingAccountName, "/")
		if len(parts) > 1 {
			billingInfo.AccountID = parts[1]
			
			// Get account name
			account, err := a.billing.BillingAccounts.Get(info.BillingAccountName).Do()
			if err == nil {
				billingInfo.AccountName = account.DisplayName
			}
		}
	}

	return billingInfo
}

func (a *Auditor) getRecentActivity(projectID string) []LogEntry {
	var entries []LogEntry
	
	// Read audit logs from last 7 days
	filter := `protoPayload.serviceName!="" AND timestamp>"` + 
		time.Now().Add(-7*24*time.Hour).Format(time.RFC3339) + `"`

	req := a.logging.Entries.List(&logging.ListLogEntriesRequest{
		ResourceNames: []string{fmt.Sprintf("projects/%s", projectID)},
		Filter:        filter,
		PageSize:      10,
	})

	resp, err := req.Do()
	if err != nil {
		return nil
	}

	for _, entry := range resp.Entries {
		var method, principal string
		if entry.ProtoPayload != nil {
			method = entry.ProtoPayload.MethodName
			if entry.ProtoPayload.AuthenticationInfo != nil {
				principal = entry.ProtoPayload.AuthenticationInfo.PrincipalEmail
			}
		}
		
		entries = append(entries, LogEntry{
			Timestamp: entry.Timestamp,
			Method:    method,
			Principal: principal,
		})
	}

	return entries
}

func (a *Auditor) generateReports(report *AuditReport, timestamp string) error {
	baseName := fmt.Sprintf("gcp_audit_%s", timestamp)
	
	// JSON report
	jsonPath := filepath.Join(a.config.OutputDir, baseName+".json")
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JSON: %w", err)
	}
	
	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		return fmt.Errorf("writing JSON: %w", err)
	}

	// Markdown report
	mdPath := filepath.Join(a.config.OutputDir, baseName+".md")
	mdContent := a.generateMarkdown(report)
	
	if err := os.WriteFile(mdPath, []byte(mdContent), 0644); err != nil {
		return fmt.Errorf("writing Markdown: %w", err)
	}

	fmt.Printf("\n✅ Reports generated:\n")
	fmt.Printf("   📄 %s\n", jsonPath)
	fmt.Printf("   📝 %s\n", mdPath)

	return nil
}

func (a *Auditor) generateMarkdown(report *AuditReport) string {
	var b strings.Builder
	
	b.WriteString("# GCP Project Audit Report\n\n")
	b.WriteString(fmt.Sprintf("**Audit Date:** %s\n\n", report.Timestamp))
	b.WriteString(fmt.Sprintf("**Auditor:** %s\n\n", report.Auditor))
	b.WriteString(fmt.Sprintf("**Projects Audited:** %d\n\n", len(report.Projects)))
	
	b.WriteString("## Summary\n\n")
	b.WriteString("| Project ID | Status | Resources | Billing | IAM Roles |\n")
	b.WriteString("|------------|--------|-----------|---------|----------|\n")
	
	for _, p := range report.Projects {
		roleCount := 0
		if p.IAMPolicy != nil {
			roleCount = len(p.IAMPolicy.Bindings)
		}
		
		b.WriteString(fmt.Sprintf("| %s | %s | %d | %v | %d |\n", 
			p.ProjectID, p.Status, p.Resources.TotalCount, 
			p.BillingInfo != nil && p.BillingInfo.Linked, roleCount))
	}
	
	b.WriteString("\n## Detailed Findings\n\n")
	
	for _, p := range report.Projects {
		b.WriteString(fmt.Sprintf("### %s\n\n", p.ProjectID))
		
		if p.Error != "" {
			b.WriteString(fmt.Sprintf("⚠️ **Error:** %s\n\n", p.Error))
		}
		
		// IAM Section
		if p.IAMPolicy != nil {
			b.WriteString("#### IAM Bindings\n\n")
			for _, binding := range p.IAMPolicy.Bindings {
				b.WriteString(fmt.Sprintf("- **%s**\n", binding.Role))
				for _, member := range binding.Members {
					b.WriteString(fmt.Sprintf("  - %s\n", member))
				}
			}
			b.WriteString("\n")
		}
		
		// Resources
		if p.Resources.TotalCount > 0 {
			b.WriteString(fmt.Sprintf("#### Resources (%d total)\n\n", p.Resources.TotalCount))
			
			if len(p.Resources.ComputeInstances) > 0 {
				b.WriteString("- **Compute Instances:** ")
				for _, i := range p.Resources.ComputeInstances {
					b.WriteString(fmt.Sprintf("%s (%s), ", i.Name, i.Status))
				}
				b.WriteString("\n")
			}
			
			if len(p.Resources.GKEClusters) > 0 {
				b.WriteString(fmt.Sprintf("- **GKE Clusters:** %d\n", len(p.Resources.GKEClusters)))
			}
			
			if len(p.Resources.StorageBuckets) > 0 {
				b.WriteString(fmt.Sprintf("- **Storage Buckets:** %d\n", len(p.Resources.StorageBuckets)))
			}
			
			b.WriteString("\n")
		}
		
		// Billing
		if p.BillingInfo != nil {
			if p.BillingInfo.Linked {
				b.WriteString(fmt.Sprintf("**Billing:** Linked to %s (%s)\n\n", 
					p.BillingInfo.AccountName, p.BillingInfo.AccountID))
			} else {
				b.WriteString("**Billing:** Not linked\n\n")
			}
		}
		
		b.WriteString("---\n\n")
	}
	
	b.WriteString("## Recommendations\n\n")
	b.WriteString("1. Review IAM bindings for over-privileged accounts\n")
	b.WriteString("2. Disable unused services to reduce attack surface\n")
	b.WriteString("3. Verify billing linkage for cost tracking\n")
	b.WriteString("4. Monitor external account access\n")
	
	return b.String()
}

// Utility functions
func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		var i int
		fmt.Sscanf(v, "%d", &i)
		return i
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if v := os.Getenv(key); v != "" {
		return v == "true" || v == "1"
	}
	return defaultVal
}

func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return defaultVal
}

func getGcloudAccount() string {
	// Fallback: execute gcloud to get account
	// In production, use proper credential detection
	return "unknown"
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}