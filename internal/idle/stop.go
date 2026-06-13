package idle

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Runner runs a command (same shape as session.Runner) so Stop can shell out to
// the AWS CLI without pulling in the AWS SDK.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

const imdsBase = "http://169.254.169.254/latest"

// StopSelf returns a Stop function that stops the current EC2 instance: it reads
// the instance id + region from IMDSv2 and runs `aws ec2 stop-instances`. The
// instance role must allow ec2:StopInstances on itself (as in v1, NF/F-11).
func StopSelf(run Runner) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		id, region, err := imdsIdentity(ctx)
		if err != nil {
			return fmt.Errorf("imds: %w", err)
		}
		out, err := run(ctx, "aws", "ec2", "stop-instances", "--instance-ids", id, "--region", region)
		if err != nil {
			return fmt.Errorf("stop-instances %s: %w (%s)", id, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}

func imdsIdentity(ctx context.Context) (instanceID, region string, err error) {
	client := &http.Client{Timeout: 3 * time.Second}
	token, err := imdsToken(ctx, client)
	if err != nil {
		return "", "", err
	}
	if instanceID, err = imdsGet(ctx, client, token, "/meta-data/instance-id"); err != nil {
		return "", "", err
	}
	if region, err = imdsGet(ctx, client, token, "/meta-data/placement/region"); err != nil {
		return "", "", err
	}
	return instanceID, region, nil
}

func imdsToken(ctx context.Context, client *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, imdsBase+"/api/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(b)), nil
}

func imdsGet(ctx context.Context, client *http.Client, token, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imdsBase+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("imds %s returned %d", path, resp.StatusCode)
	}
	return strings.TrimSpace(string(b)), nil
}
