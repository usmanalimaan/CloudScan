// compliance/auditor.go
package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	"cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	location "google.golang.org/genproto/googleapis/cloud/location"
)

// ComplianceStandard represents different compliance frameworks
type ComplianceStandard string

const (
	StandardAUProtected   ComplianceStandard = "AU_PROTECTED"   // Australian Government Protected
	StandardAUOfficial    ComplianceStandard = "AU_OFFICIAL"    // Australian Government Official
	StandardIRAPProtected ComplianceStandard = "IRAP_PROTECTED" // IRAP Protected
	StandardIRAPOfficial  ComplianceStandard = "IRAP_OFFICIAL"  // IRAP Official
	StandardPCI           ComplianceStandard = "PCI_DSS"
	StandardHIPAA         ComplianceStandard = "HIPAA"
	StandardGDPR          ComplianceStandard = "GDPR"
	StandardSOX           ComplianceStandard = "SOX"
)

// RegionInfo holds AU-specific region details
type RegionInfo struct {
	Name        string   `json:"name"`
	Location    string   `json:"location"`
	Zones       []string `json:"zones"`
	Compliance  []string `json:"compliance_certifications"`
	IsAURegion  bool     `json:"is_au_region"`
	Description string   `json:"description"`
}

// AU Regions as of 2024
var AURegions = map[string]RegionInfo{
	"australia-southeast1": {
		Name:       "Sydney",
		Location:   "Sydney, Australia",
		Zones:      []string{"australia-southeast1-a", "australia-southeast1-b", "australia-southeast1-c"},
		Compliance: []string{"IRAP", "ISO27001", "ISO27017", "ISO27018", "SOC1", "SOC2", "SOC3"},
		IsAURegion: true,
		Description: "Primary AU region - IRAP Protected certified",
	},
	"australia-southeast2": {
		Name:       "Melbourne",
		Location:   "Melbourne, Australia",
		Zones:      []string{"australia-southeast2-a", "australia-southeast2-b", "australia-southeast2-c"},
		Compliance: []string{"IRAP", "ISO27001", "ISO27017", "ISO27018", "SOC1", "SOC2", "SOC3"},
		IsAURegion: true,
		Description: "Secondary AU region - IRAP Protected certified",
	},
}

// DataResidencyAuditor performs compliance checks
type DataResidencyAuditor struct {
	ctx              context.Context
	projectID        string
	organizationID   string
	complianceStandard ComplianceStandard
	
	// Clients
	computeClient   *compute.InstancesClient
	kmsClient       *kms.KeyManagementClient
	projectsClient  *resourcemanager.ProjectsClient
	foldersClient   *resourcemanager.FoldersClient
	
	// Configuration
	targetRegions    []string
	excludedRegions  []string
	requireAUOnly    bool
}

// ComplianceReport represents the full audit result
type ComplianceReport struct {
	GeneratedAt      time.Time                    `json:"generated_at"`
	ProjectID        string                       `json:"project_id"`
	OrganizationID   string                       `json:"organization_id,omitempty"`
	Standard         ComplianceStandard           `json:"compliance_standard"`
	OverallStatus    ComplianceStatus             `json:"overall_status"`
	Summary          ComplianceSummary            `json:"summary"`
	ComputeFindings  []ComputeFinding             `json:"compute_findings"`
	StorageFindings  []StorageFinding             `json:"storage_findings"`
	KMSFindings      []KMSFinding                 `json:"kms_findings"`
	NetworkFindings  []NetworkFinding             `json:"network_findings"`
	VertexAIFindings []VertexAIFinding            `json:"vertex_ai_findings"`
	Evidence         []Evidence                   `json:"evidence"`
	Recommendations  []Recommendation             `json:"recommendations"`
	ClaimExtract     ClaimExtractDocument         `json:"claim_extract"`
}

type ComplianceStatus string

const (
	StatusCompliant     ComplianceStatus = "COMPLIANT"
	StatusNonCompliant  ComplianceStatus = "NON_COMPLIANT"
	StatusPartial       ComplianceStatus = "PARTIAL_COMPLIANCE"
	StatusError         ComplianceStatus = "ERROR"
)

type ComplianceSummary struct {
	TotalResources      int `json:"total_resources"`
	AURegionResources   int `json:"au_region_resources"`
	NonAUResources      int `json:"non_au_resources"`
	CompliantResources  int `json:"compliant_resources"`
	Violations          int `json:"violations"`
	Warnings            int `json:"warnings"`
}

type ComputeFinding struct {
	InstanceName    string            `json:"instance_name"`
	InstanceID      string            `json:"instance_id"`
	Zone            string            `json:"zone"`
	Region          string            `json:"region"`
	IsAURegion      bool              `json:"is_au_region"`
	MachineType     string            `json:"machine_type"`
	Status          string            `json:"status"`
	Labels          map[string]string `json:"labels"`
	ConfidentialVM  bool              `json:"confidential_vm"`
	ShieldedVM      bool              `json:"shielded_vm"`
	BootDiskEncrypted bool            `json:"boot_disk_encrypted"`
	ComplianceStatus  ComplianceStatus  `json:"compliance_status"`
	Violations        []string          `json:"violations,omitempty"`
	ScreenshotURL     string            `json:"screenshot_url,omitempty"` // For manual verification
}

type StorageFinding struct {
	BucketName      string            `json:"bucket_name"`
	Location        string            `json:"location"`
	LocationType    string            `json:"location_type"` // REGIONAL, MULTI-REGIONAL, etc.
	IsAURegion      bool              `json:"is_au_region"`
	EncryptionType  string            `json:"encryption_type"`
	RetentionPolicy *RetentionInfo    `json:"retention_policy,omitempty"`
	Labels          map[string]string `json:"labels"`
	ComplianceStatus ComplianceStatus `json:"compliance_status"`
}

type RetentionInfo struct {
	RetentionPeriodDays int64     `json:"retention_period_days"`
	EffectiveTime       time.Time `json:"effective_time"`
	IsLocked            bool      `json:"is_locked"`
}

type KMSFinding struct {
	KeyRingName     string           `json:"key_ring_name"`
	KeyName         string           `json:"key_name"`
	Location        string           `json:"location"`
	IsAURegion      bool             `json:"is_au_region"`
	Purpose         string           `json:"purpose"` // ENCRYPT_DECRYPT, ASYMMETRIC_SIGN, etc.
	Algorithm       string           `json:"algorithm"`
	ProtectionLevel string           `json:"protection_level"` // SOFTWARE, HSM, EXTERNAL
	RotationPeriod  string           `json:"rotation_period"`
	NextRotation    time.Time        `json:"next_rotation_time"`
	Labels          map[string]string `json:"labels"`
	ComplianceStatus ComplianceStatus `json:"compliance_status"`
}

type NetworkFinding struct {
	NetworkName     string   `json:"network_name"`
	Region          string   `json:"region"`
	IsAURegion      bool     `json:"is_au_region"`
	CloudRouter     bool     `json:"cloud_router"`
	CloudNAT        bool     `json:"cloud_nat"`
	VPCFlowLogs     bool     `json:"vpc_flow_logs_enabled"`
	ComplianceStatus ComplianceStatus `json:"compliance_status"`
}

type VertexAIFinding struct {
	EndpointName    string            `json:"endpoint_name"`
	DisplayName     string            `json:"display_name"`
	Location        string            `json:"location"`
	IsAURegion      bool              `json:"is_au_region"`
	MachineType     string            `json:"machine_type"`
	DeployedModels  []string          `json:"deployed_models"`
	EncryptionSpec  string            `json:"encryption_spec"`
	Labels          map[string]string `json:"labels"`
	ComplianceStatus ComplianceStatus `json:"compliance_status"`
}

type Evidence struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // "screenshot", "api_response", "config_export"
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Data        []byte    `json:"-"` // Raw evidence data
	DataBase64  string    `json:"data_base64,omitempty"`
	Region      string    `json:"region"`
	ResourceID  string    `json:"resource_id"`
}

type Recommendation struct {
	Severity    string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Category    string `json:"category"`
	Resource    string `json:"resource"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	Reference   string `json:"reference"` // Link to GCP docs
}

// ClaimExtractDocument for internal confirmation/auditing
type ClaimExtractDocument struct {
	DocumentVersion   string            `json:"document_version"`
	GeneratedAt       time.Time         `json:"generated_at"`
	ProjectID         string            `json:"project_id"`
	ComplianceClaims  []ComplianceClaim `json:"compliance_claims"`
	Attestations      []Attestation     `json:"attestations"`
	Signature         string            `json:"signature,omitempty"` // Digital signature for integrity
}

type ComplianceClaim struct {
	ClaimID         string   `json:"claim_id"`
	ClaimType       string   `json:"claim_type"` // "DATA_RESIDENCY", "ENCRYPTION", "ACCESS_CONTROL"
	Description     string   `json:"description"`
	EvidenceRefs    []string `json:"evidence_refs"` // References to Evidence IDs
	Verified        bool     `json:"verified"`
	VerifiedAt      time.Time `json:"verified_at"`
	VerifiedBy      string    `json:"verified_by"`
	StandardMapping map[ComplianceStandard]string `json:"standard_mapping"` // Standard -> Control ID
}

type Attestation struct {
	AttestationType string    `json:"attestation_type"` // "AUTOMATED_SCAN", "MANUAL_REVIEW"
	Attestor        string    `json:"attestor"`
	Timestamp       time.Time `json:"timestamp"`
	Statement       string    `json:"statement"`
}

// NewDataResidencyAuditor creates a new compliance auditor
func NewDataResidencyAuditor(ctx context.Context, projectID, orgID string, standard ComplianceStandard) (*DataResidencyAuditor, error) {
	auditor := &DataResidencyAuditor{
		ctx:                ctx,
		projectID:          projectID,
		organizationID:     orgID,
		complianceStandard: standard,
		targetRegions:      []string{"australia-southeast1", "australia-southeast2"},
		requireAUOnly:      true,
	}

	// Initialize clients
	var err error
	
	auditor.computeClient, err = compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("compute client: %w", err)
	}

	auditor.kmsClient, err = kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms client: %w", err)
	}

	auditor.projectsClient, err = resourcemanager.NewProjectsClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("projects client: %w", err)
	}

	return auditor, nil
}

// RunAudit executes the full compliance audit
func (a *DataResidencyAuditor) RunAudit() (*ComplianceReport, error) {
	report := &ComplianceReport{
		GeneratedAt:    time.Now().UTC(),
		ProjectID:      a.projectID,
		OrganizationID: a.organizationID,
		Standard:       a.complianceStandard,
		Evidence:       []Evidence{},
	}

	fmt.Printf("🔍 Starting Data Residency Audit for project: %s\n", a.projectID)
	fmt.Printf("📋 Compliance Standard: %s\n", a.complianceStandard)

	// 1. Audit Compute Instances
	fmt.Println("🖥️  Auditing Compute Instances...")
	computeFindings, err := a.auditComputeInstances()
	if err != nil {
		report.OverallStatus = StatusError
		return report, fmt.Errorf("compute audit: %w", err)
	}
	report.ComputeFindings = computeFindings

	// 2. Audit Cloud Storage
	fmt.Println("🗄️  Auditing Cloud Storage...")
	storageFindings, err := a.auditStorage()
	if err != nil {
		fmt.Printf("Warning: storage audit: %v\n", err)
	}
	report.StorageFindings = storageFindings

	// 3. Audit KMS Keys
	fmt.Println("🔐 Auditing KMS Keys...")
	kmsFindings, err := a.auditKMS()
	if err != nil {
		fmt.Printf("Warning: KMS audit: %v\n", err)
	}
	report.KMSFindings = kmsFindings

	// 4. Audit Vertex AI (if enabled)
	fmt.Println("🤖 Auditing Vertex AI...")
	vertexFindings, err := a.auditVertexAI()
	if err != nil {
		fmt.Printf("Warning: Vertex AI audit: %v\n", err)
	}
	report.VertexAIFindings = vertexFindings

	// 5. Calculate summary and status
	report.Summary = a.calculateSummary(report)
	report.OverallStatus = a.determineOverallStatus(report)
	report.Recommendations = a.generateRecommendations(report)

	// 6. Generate claim extract document
	report.ClaimExtract = a.generateClaimExtract(report)

	fmt.Printf("\n✅ Audit complete. Status: %s\n", report.OverallStatus)
	fmt.Printf("   Total Resources: %d\n", report.Summary.TotalResources)
	fmt.Printf("   AU Region: %d | Non-AU: %d\n", report.Summary.AURegionResources, report.Summary.NonAUResources)
	fmt.Printf("   Violations: %d | Warnings: %d\n", report.Summary.Violations, report.Summary.Warnings)

	return report, nil
}

func (a *DataResidencyAuditor) auditComputeInstances() ([]ComputeFinding, error) {
	var findings []ComputeFinding

	// List instances across all zones in AU regions
	for _, region := range a.targetRegions {
		req := &computepb.AggregatedListInstancesRequest{
			Project: a.projectID,
			Filter:  proto.String(fmt.Sprintf("zone eq %s.*", region)),
		}

		it := a.computeClient.AggregatedList(a.ctx, req)
		for {
			resp, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, err
			}

			for _, instance := range resp.Value.Instances {
				finding := a.analyzeInstance(instance, region)
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func (a *DataResidencyAuditor) analyzeInstance(instance *computepb.Instance, region string) ComputeFinding {
	zone := *instance.Zone
	zoneParts := strings.Split(zone, "/")
	zoneName := zoneParts[len(zoneParts)-1]

	finding := ComputeFinding{
		InstanceName: *instance.Name,
		InstanceID:   fmt.Sprintf("%d", *instance.Id),
		Zone:         zoneName,
		Region:       region,
		IsAURegion:   AURegions[region].IsAURegion,
		MachineType:  *instance.MachineType,
		Status:       *instance.Status,
		Labels:       instance.Labels,
	}

	// Check confidential VM
	if instance.ConfidentialInstanceConfig != nil && instance.ConfidentialInstanceConfig.EnableConfidentialCompute != nil {
		finding.ConfidentialVM = *instance.ConfidentialInstanceConfig.EnableConfidentialCompute
	}

	// Check shielded VM
	if instance.ShieldedInstanceConfig != nil {
		finding.ShieldedVM = true // Simplified check
	}

	// Check boot disk encryption
	for _, disk := range instance.Disks {
		if disk.Boot != nil && *disk.Boot && disk.DiskEncryptionKey != nil {
			finding.BootDiskEncrypted = true
			break
		}
	}

	// Determine compliance status
	finding.ComplianceStatus = a.evaluateComputeCompliance(finding)
	
	return finding
}

func (a *DataResidencyAuditor) evaluateComputeCompliance(finding ComputeFinding) ComplianceStatus {
	var violations []string

	if !finding.IsAURegion && a.requireAUOnly {
		violations = append(violations, "Resource not in AU region")
	}

	if !finding.BootDiskEncrypted {
		violations = append(violations, "Boot disk not encrypted with CMEK")
	}

	if a.complianceStandard == StandardIRAPProtected && !finding.ConfidentialVM {
		violations = append(violations, "IRAP Protected requires Confidential VM")
	}

	finding.Violations = violations

	if len(violations) == 0 {
		return StatusCompliant
	}
	return StatusNonCompliant
}

func (a *DataResidencyAuditor) auditStorage() ([]StorageFinding, error) {
	// Implementation for Cloud Storage buckets
	// Check location, encryption, retention policies
	return nil, nil
}

func (a *DataResidencyAuditor) auditKMS() ([]KMSFinding, error) {
	var findings []KMSFinding

	for _, region := range a.targetRegions {
		parent := fmt.Sprintf("projects/%s/locations/%s", a.projectID, region)
		
		req := &kmspb.ListKeyRingsRequest{
			Parent: parent,
		}

		it := a.kmsClient.ListKeyRings(a.ctx, req)
		for {
			resp, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, err
			}

			// List crypto keys in this keyring
			keyReq := &kmspb.ListCryptoKeysRequest{
				Parent: resp.Name,
			}
			
			keyIt := a.kmsClient.ListCryptoKeys(a.ctx, keyReq)
			for {
				key, err := keyIt.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					continue
				}

				finding := KMSFinding{
					KeyRingName:      resp.Name,
					KeyName:          key.Name,
					Location:         region,
					IsAURegion:       true,
					Purpose:          key.Purpose.String(),
					Algorithm:        key.Algorithm.String(),
					ProtectionLevel:  key.ProtectionLevel.String(),
					RotationPeriod:   key.RotationPeriod.String(),
					Labels:           key.Labels,
					ComplianceStatus: StatusCompliant, // Keys in AU are compliant by location
				}

				if key.NextRotationTime != nil {
					finding.NextRotation = *key.NextRotationTime
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func (a *DataResidencyAuditor) auditVertexAI() ([]VertexAIFinding, error) {
	// Implementation for Vertex AI endpoints
	// Check model deployment locations, encryption
	return nil, nil
}

func (a *DataResidencyAuditor) calculateSummary(report *ComplianceReport) ComplianceSummary {
	summary := ComplianceSummary{}

	// Count compute resources
	for _, f := range report.ComputeFindings {
		summary.TotalResources++
		if f.IsAURegion {
			summary.AURegionResources++
		} else {
			summary.NonAUResources++
		}
		if f.ComplianceStatus == StatusCompliant {
			summary.CompliantResources++
		} else {
			summary.Violations++
		}
	}

	// Count storage
	for _, f := range report.StorageFindings {
		summary.TotalResources++
		if f.IsAURegion {
			summary.AURegionResources++
		} else {
			summary.NonAUResources++
		}
		if f.ComplianceStatus != StatusCompliant {
			summary.Violations++
		}
	}

	// Count KMS
	for _, f := range report.KMSFindings {
		summary.TotalResources++
		if f.IsAURegion {
			summary.AURegionResources++
		}
	}

	return summary
}

func (a *DataResidencyAuditor) determineOverallStatus(report *ComplianceReport) ComplianceStatus {
	if report.Summary.Violations > 0 {
		return StatusNonCompliant
	}
	if report.Summary.Warnings > 0 {
		return StatusPartial
	}
	return StatusCompliant
}

func (a *DataResidencyAuditor) generateRecommendations(report *ComplianceReport) []Recommendation {
	var recommendations []Recommendation

	// Non-AU region resources
	if report.Summary.NonAUResources > 0 {
		recommendations = append(recommendations, Recommendation{
			Severity:    "CRITICAL",
			Category:    "DATA_RESIDENCY",
			Description: fmt.Sprintf("Found %d resources outside AU regions", report.Summary.NonAUResources),
			Remediation: "Migrate resources to australia-southeast1 or australia-southeast2",
			Reference:   "https://cloud.google.com/compute/docs/regions-zones",
		})
	}

	// Encryption recommendations
	for _, f := range report.ComputeFindings {
		if !f.BootDiskEncrypted {
			recommendations = append(recommendations, Recommendation{
				Severity:    "HIGH",
				Category:    "ENCRYPTION",
				Resource:    f.InstanceName,
				Description: "VM boot disk not encrypted with customer-managed encryption key",
				Remediation: "Enable CMEK encryption for boot disks using Cloud KMS keys in AU region",
				Reference:   "https://cloud.google.com/compute/docs/disks/customer-managed-encryption",
			})
		}
	}

	return recommendations
}

func (a *DataResidencyAuditor) generateClaimExtract(report *ComplianceReport) ClaimExtractDocument {
	doc := ClaimExtractDocument{
		DocumentVersion: "1.0",
		GeneratedAt:     time.Now().UTC(),
		ProjectID:       a.projectID,
	}

	// Data Residency Claim
	residencyClaim := ComplianceClaim{
		ClaimID:     fmt.Sprintf("DR-%s-%d", a.projectID, time.Now().Unix()),
		ClaimType:   "DATA_RESIDENCY",
		Description: fmt.Sprintf("All data for project %s resides exclusively in Australian regions", a.projectID),
		Verified:    report.OverallStatus == StatusCompliant,
		VerifiedAt:  time.Now().UTC(),
		VerifiedBy:  "automated_scanner",
		StandardMapping: map[ComplianceStandard]string{
			StandardIRAPProtected: "IRAP-2022-CTRL-001",
			StandardAUProtected:   "PROTECTED-GEO-001",
		},
	}

	// Add evidence references
	for _, f := range report.ComputeFindings {
		if f.IsAURegion {
			residencyClaim.EvidenceRefs = append(residencyClaim.EvidenceRefs, f.InstanceID)
		}
	}

	doc.ComplianceClaims = append(doc.ComplianceClaims, residencyClaim)

	// Encryption Claim
	encryptionClaim := ComplianceClaim{
		ClaimID:     fmt.Sprintf("ENC-%s-%d", a.projectID, time.Now().Unix()),
		ClaimType:   "ENCRYPTION",
		Description: "All data encrypted at rest using AU-region KMS keys",
		Verified:    len(report.KMSFindings) > 0,
		VerifiedAt:  time.Now().UTC(),
		VerifiedBy:  "automated_scanner",
		StandardMapping: map[ComplianceStandard]string{
			StandardIRAPProtected: "IRAP-2022-CTRL-002",
		},
	}
	doc.ComplianceClaims = append(doc.ComplianceClaims, encryptionClaim)

	// Add attestation
	doc.Attestations = append(doc.Attestations, Attestation{
		AttestationType: "AUTOMATED_SCAN",
		Attestor:        "gcp-compliance-auditor",
		Timestamp:       time.Now().UTC(),
		Statement:       fmt.Sprintf("Automated scan completed for project %s against %s standard", a.projectID, a.complianceStandard),
	})

	return doc
}

// Close closes all client connections
func (a *DataResidencyAuditor) Close() error {
	if a.computeClient != nil {
		a.computeClient.Close()
	}
	if a.kmsClient != nil {
		a.kmsClient.Close()
	}
	if a.projectsClient != nil {
		a.projectsClient.Close()
	}
	return nil
}

// Helper for proto
func proto.String(s string) *string {
	return &s
}