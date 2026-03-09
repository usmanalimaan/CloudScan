// cmd/audit/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/yourorg/gcp-audit/compliance"
)

func main() {
	var (
		projectID   = flag.String("project", "", "GCP Project ID (required)")
		orgID       = flag.String("org", "", "GCP Organization ID (optional)")
		standard    = flag.String("standard", "IRAP_PROTECTED", "Compliance standard: IRAP_PROTECTED, IRAP_OFFICIAL, AU_PROTECTED, PCI, HIPAA")
		outputDir   = flag.String("output", "./compliance-reports", "Output directory for reports")
		screenshots = flag.Bool("screenshots", false, "Capture VM screenshots for evidence")
		timeout     = flag.Duration("timeout", 30*time.Minute, "Audit timeout")
	)
	flag.Parse()

	if *projectID == "" {
		fmt.Fprintf(os.Stderr, "Error: -project flag is required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Create output directory
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Initialize auditor
	auditor, err := compliance.NewDataResidencyAuditor(ctx, *projectID, *orgID, compliance.ComplianceStandard(*standard))
	if err != nil {
		log.Fatalf("Failed to create auditor: %v", err)
	}
	defer auditor.Close()

	// Run audit
	report, err := auditor.RunAudit()
	if err != nil {
		log.Fatalf("Audit failed: %v", err)
	}

	// Capture screenshots if requested
	if *screenshots {
		fmt.Println("📸 Capturing VM screenshots...")
		screenshotter, err := compliance.NewScreenshotCapture(ctx)
		if err != nil {
			fmt.Printf("Warning: screenshot capture unavailable: %v\n", err)
		} else {
			defer screenshotter.Close()
			
			for _, finding := range report.ComputeFindings {
				if finding.Status == "RUNNING" {
					evidence, err := screenshotter.CaptureScreenshot(*projectID, finding.Zone, finding.InstanceName)
					if err != nil {
						fmt.Printf("  ⚠️  Failed to capture %s: %v\n", finding.InstanceName, err)
						continue
					}
					report.Evidence = append(report.Evidence, *evidence)
					fmt.Printf("  ✅ Captured %s\n", finding.InstanceName)
				}
			}
		}
	}

	// Generate reports
	generator := compliance.NewReportGenerator(*outputDir)

	jsonPath, err := generator.GenerateJSON(report)
	if err != nil {
		log.Printf("Failed to generate JSON report: %v", err)
	} else {
		fmt.Printf("📄 JSON Report: %s\n", jsonPath)
	}

	mdPath, err := generator.GenerateMarkdown(report)
	if err != nil {
		log.Printf("Failed to generate Markdown report: %v", err)
	} else {
		fmt.Printf("📝 Markdown Report: %s\n", mdPath)
	}

	claimPath, err := generator.GenerateClaimExtractJSON(report)
	if err != nil {
		log.Printf("Failed to generate claim extract: %v", err)
	} else {
		fmt.Printf("📋 Claim Extract: %s\n", claimPath)
	}

	// Exit with error code if non-compliant
	if report.OverallStatus == compliance.StatusNonCompliant {
		fmt.Println("\n❌ Audit completed with violations")
		os.Exit(2)
	}

	fmt.Println("\n✅ Audit completed successfully")
}