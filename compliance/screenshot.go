// compliance/screenshot.go
package compliance

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image/png"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/protobuf/proto"
)

// ScreenshotCapture handles VM screenshot capture for evidence
type ScreenshotCapture struct {
	ctx           context.Context
	computeClient *compute.InstancesClient
}

// NewScreenshotCapture creates a screenshot capturer
func NewScreenshotCapture(ctx context.Context) (*ScreenshotCapture, error) {
	client, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return nil, err
	}
	
	return &ScreenshotCapture{
		ctx:           ctx,
		computeClient: client,
	}, nil
}

// CaptureScreenshot captures a screenshot of a running VM
func (s *ScreenshotCapture) CaptureScreenshot(projectID, zone, instanceName string) (*Evidence, error) {
	req := &computepb.GetScreenshotRequest{
		Project:  projectID,
		Zone:     zone,
		Instance: instanceName,
	}

	resp, err := s.computeClient.GetScreenshot(s.ctx, req)
	if err != nil {
		return nil, fmt.Errorf("getting screenshot: %w", err)
	}

	// Decode base64 screenshot data
	screenshotData, err := base64.StdEncoding.DecodeString(resp.GetContents())
	if err != nil {
		return nil, fmt.Errorf("decoding screenshot: %w", err)
	}

	// Convert to PNG for consistency
	img, err := png.Decode(bytes.NewReader(screenshotData))
	if err != nil {
		// If already PNG or conversion fails, use raw data
		screenshotData = screenshotData
	} else {
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err == nil {
			screenshotData = buf.Bytes()
		}
	}

	evidence := &Evidence{
		ID:          fmt.Sprintf("screenshot-%s-%d", instanceName, time.Now().Unix()),
		Type:        "screenshot",
		Description: fmt.Sprintf("VM screenshot for %s in %s", instanceName, zone),
		Timestamp:   time.Now().UTC(),
		Data:        screenshotData,
		DataBase64:  base64.StdEncoding.EncodeToString(screenshotData),
		Region:      zone,
		ResourceID:  fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zone, instanceName),
	}

	return evidence, nil
}

// Close closes the client
func (s *ScreenshotCapture) Close() error {
	if s.computeClient != nil {
		return s.computeClient.Close()
	}
	return nil
}