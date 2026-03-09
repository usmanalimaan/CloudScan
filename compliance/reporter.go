// compliance/reporter.go
package compliance

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"
)

// ReportGenerator generates various report formats
type ReportGenerator struct {
	outputDir string
}

// NewReportGenerator creates a report generator
func NewReportGenerator(outputDir string) *ReportGenerator {
	return &ReportGenerator{
		outputDir: outputDir,
	}
}

// GenerateJSON outputs JSON report
func (r *ReportGenerator) GenerateJSON(report *ComplianceReport) (string, error) {
	filename := fmt.Sprintf("compliance_report_%s.json", report.GeneratedAt.Format("20060102_150405"))
	path := filepath.Join(r.outputDir, filename)

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", err
	}

	return path, nil
}

// GenerateMarkdown generates human-readable report
func (r *ReportGenerator) GenerateMarkdown(report *ComplianceReport) (string, error) {
	filename := fmt.Sprintf("compliance_report_%s.md", report.GeneratedAt.Format("20060102_150405"))
	path := filepath.Join(r.outputDir, filename)

	var md strings.Builder

	// Header
	md.WriteString("# GCP Data Residency Compliance Report\n\n")
	md.WriteString(fmt.Sprintf("**Generated:** %s  \n", report.GeneratedAt.Format(time.RFC3339)))
	md.WriteString(fmt.Sprintf("**Project:** `%s`  \n", report.ProjectID))
	md.WriteString(fmt.Sprintf("**Standard:** %s  \n", report.Standard))
	md.WriteString(fmt.Sprintf("**Overall Status:** %s  \n\n", report.OverallStatus))

	// Executive Summary
	md.WriteString("## Executive Summary\n\n")
	md.WriteString(fmt.Sprintf("- **Total Resources Audited:** %d\n", report.Summary.TotalResources))
	md.WriteString(fmt.Sprintf("- **Compliant Resources:** %d (%.1f%%)\n", 
		report.Summary.CompliantResources, 
		float64(report.Summary.CompliantResources)/float64(report.Summary.TotalResources)*100))
	md.WriteString(fmt.Sprintf("- **AU Region Resources:** %d\n", report.Summary.AURegionResources))
	md.WriteString(fmt.Sprintf("- **Non-AU Resources:** %d ⚠️\n", report.Summary.NonAUResources))
	md.WriteString(fmt.Sprintf("- **Violations:** %d\n", report.Summary.Violations))
	md.WriteString(fmt.Sprintf("- **Warnings:** %d\n\n", report.Summary.Warnings))

	// Status Badge
	switch report.OverallStatus {
	case StatusCompliant:
		md.WriteString("![Compliant](https://img.shields.io/badge/Status-COMPLIANT-brightgreen)\n\n")
	case StatusPartial:
		md.WriteString("![Partial](https://img.shields.io/badge/Status-PARTIAL-yellow)\n\n")
	case StatusNonCompliant:
		md.WriteString("![Non-Compliant](https://img.shields.io/badge/Status-NON--COMPLIANT-red)\n\n")
	}

	// Compute Findings
	if len(report.ComputeFindings) > 0 {
		md.WriteString("## Compute Engine Findings\n\n")
		md.WriteString("| Instance | Region | Zone | Type | Status | Encrypted | Compliance |\n")
		md.WriteString("|----------|--------|------|------|--------|-----------|------------|\n")
		
		for _, f := range report.ComputeFindings {
			region := "🌏 AU"
			if !f.IsAURegion {
				region = "⚠️ " + f.Region
			}
			
			encrypted := "❌"
			if f.BootDiskEncrypted {
				encrypted = "✅"
			}
			
			status := "✅"
			if f.ComplianceStatus != StatusCompliant {
				status = "❌ " + strings.Join(f.Violations, ", ")
			}
			
			md.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s |\n",
				f.InstanceName, region, f.Zone, f.MachineType, f.Status, encrypted, status))
		}
		md.WriteString("\n")
	}

	// KMS Findings
	if len(report.KMSFindings) > 0 {
		md.WriteString("## KMS Key Findings\n\n")
		md.WriteString("| Key Ring | Key Name | Location | Protection Level | Rotation |\n")
		md.WriteString("|----------|----------|----------|------------------|----------|\n")
		
		for _, f := range report.KMSFindings {
			md.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
				filepath.Base(f.KeyRingName), filepath.Base(f.KeyName), 
				f.Location, f.ProtectionLevel, f.RotationPeriod))
		}
		md.WriteString("\n")
	}

	// Recommendations
	if len(report.Recommendations) > 0 {
		md.WriteString("## Recommendations\n\n")
		
		for i, rec := range report.Recommendations {
			severityEmoji := "🔵"
			switch rec.Severity {
			case "CRITICAL":
				severityEmoji = "🔴"
			case "HIGH":
				severityEmoji = "🟠"
			case "MEDIUM":
				severityEmoji = "🟡"
			}
			
			md.WriteString(fmt.Sprintf("### %s %d. %s\n\n", severityEmoji, i+1, rec.Description))
			md.WriteString(fmt.Sprintf("- **Category:** %s\n", rec.Category))
			md.WriteString(fmt.Sprintf("- **Resource:** `%s`\n", rec.Resource))
			md.WriteString(fmt.Sprintf("- **Severity:** %s\n", rec.Severity))
			md.WriteString(fmt.Sprintf("- **Remediation:** %s\n", rec.Remediation))
			md.WriteString(fmt.Sprintf("- **Reference:** [%s](%s)\n\n", rec.Reference, rec.Reference))
		}
	}

	// Claim Extract
	md.WriteString("## Claim Extract Document\n\n")
	md.WriteString(fmt.Sprintf("**Document Version:** %s  \n", report.ClaimExtract.DocumentVersion))
	md.WriteString(fmt.Sprintf("**Generated At:** %s  \n\n", report.ClaimExtract.GeneratedAt.Format(time.RFC3339)))
	
	for _, claim := range report.ClaimExtract.ComplianceClaims {
		md.WriteString(fmt.Sprintf("### Claim: %s\n\n", claim.ClaimID))
		md.WriteString(fmt.Sprintf("- **Type:** %s\n", claim.ClaimType))
		md.WriteString(fmt.Sprintf("- **Description:** %s\n", claim.Description))
		md.WriteString(fmt.Sprintf("- **Verified:** %v\n", claim.Verified))
		md.WriteString(fmt.Sprintf("- **Verified By:** %s at %s\n", claim.VerifiedBy, claim.VerifiedAt.Format(time.RFC3339)))
		
		if len(claim.StandardMapping) > 0 {
			md.WriteString("- **Standard Mappings:**\n")
			for std, ctrl := range claim.StandardMapping {
				md.WriteString(fmt.Sprintf("  - %s: `%s`\n", std, ctrl))
			}
		}
		md.WriteString("\n")
	}

	// Footer
	md.WriteString("---\n\n")
	md.WriteString("*This report was generated automatically by the GCP Data Residency Compliance Auditor.*\n")

	if err := os.WriteFile(path, []byte(md.String()), 0644); err != nil {
		return "", err
	}

	return path, nil
}

// GenerateClaimExtractJSON outputs the claim extract as standalone JSON
func (r *ReportGenerator) GenerateClaimExtractJSON(report *ComplianceReport) (string, error) {
	filename := fmt.Sprintf("claim_extract_%s.json", report.GeneratedAt.Format("20060102_150405"))
	path := filepath.Join(r.outputDir, filename)

	data, err := json.MarshalIndent(report.ClaimExtract, "", "  ")
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", err
	}

	return path, nil
}