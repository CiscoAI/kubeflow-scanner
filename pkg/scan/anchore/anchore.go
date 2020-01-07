package anchore

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

// GetImageVulnerabilities sends a POST request to the Anchore Engine to fetch vulnerabilities
// needs the ANCHORE credentials and the service URL to authenticate
func GetImageVulnerabilities(ctx context.Context, imageName string) error {
	anchoreUsername := os.Getenv("ANCHORE_CLI_USER")
	anchorePassword := os.Getenv("ANCHORE_CLI_PASS")
	anchoreURL := os.Getenv("ANCHORE_CLI_URL") + "/images?force=true&autosubscribe=false"
	anchoreAccount := os.Getenv("ANCHORE_ACCOUNT")

	jsonRequestData := []byte(fmt.Sprintf(`{
		"tag": "%v"
		}`, imageName))

	req, err := http.NewRequestWithContext(ctx, "POST", anchoreURL, bytes.NewBuffer(jsonRequestData))
	if err != nil {
		return err
	}
	req.SetBasicAuth(anchoreUsername, anchorePassword)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("x-anchore-account", anchoreAccount)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("%s", body)
	}
	fmt.Printf("Image Analysis result: %s", body)

	return nil
}

// Implementation Notes

// Anchore Scanning Workflow
// Step 1. Add new image to Anchore
// Step 2. Wait for automatic analysis
// Step 3. Poll image for Analysis Status
// Step 4. Fetch all Critical and High Vulnerabilities
