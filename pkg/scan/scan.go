package scan

import (
	"bufio"
	"context"
	"fmt"
	"os"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
	log "github.com/sirupsen/logrus"
	"google.golang.org/api/iterator"
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
)

type ResourceCVEList struct {
	ResourceURI  string
	CVENotes     []string
	SeverityList []float32
}

func findVulnerabilityOccurrencesForImage(resourceURL, projectID string) ([]*grafeaspb.Occurrence, error) {
	ctx := context.Background()
	client, err := containeranalysis.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewClient: %v", err)
	}
	defer client.Close()

	log.Infof("Checking vulnerabilities for resource: %v", resourceURL)
	req := &grafeaspb.ListOccurrencesRequest{
		Parent: fmt.Sprintf("projects/%s", projectID),
		Filter: fmt.Sprintf("resourceUrl = %q kind = %q", resourceURL, "PACKAGE_VULNERABILITY"),
	}

	var occurenceList []*grafeaspb.Occurrence
	it := client.GetGrafeasClient().ListOccurrences(ctx, req)
	for {
		occ, err := it.Next()
		if occ == nil {
			return nil, fmt.Errorf("unable to fetch occurence, occurence is nil")
		}
		if err == iterator.Done {
			break
		} else if err != nil {
			return nil, fmt.Errorf("occurrence iteration error: %v", err)
		}
		if occ.GetVulnerability().GetSeverity() == grafeaspb.Severity_HIGH || occ.GetVulnerability().GetSeverity() == grafeaspb.Severity_CRITICAL || occ.GetVulnerability().GetCvssScore() > 7.5 {
			occurenceList = append(occurenceList, occ)
		}
	}
	return occurenceList, nil
}

// listVulnerabilities lists all vulnerabilities for images given
func listVulnerabilities(imageList []string, gcpProject string) ([]*ResourceCVEList, error) {
	var cveList []*ResourceCVEList

	// fetch vulnerabilities for GCR repo images using Container Analysis API
	for _, image := range imageList {
		occurenceList, err := findVulnerabilityOccurrencesForImage(image, gcpProject)
		if err != nil {
			return nil, err
		}

		if len(occurenceList) == 0 {
			log.Infof("No vulnerabilties found for resource: %v\n\n", image)
		} else {
			cveResource := &ResourceCVEList{}
			cveResource.ResourceURI = image
			for _, occurence := range occurenceList {
				cveResource.CVENotes = append(cveResource.CVENotes, occurence.GetNoteName())
				cveResource.SeverityList = append(cveResource.SeverityList, occurence.GetVulnerability().GetCvssScore())
			}
			cveList = append(cveList, cveResource)
		}
	}

	return cveList, nil
}

// WriteVulnerabilitiesToFile writes all vulnerabilties from images to the given file
func WriteVulnerabilitiesToFile(imageList []string, gcpProject string, outputFileName string) error {
	cveList, err := listVulnerabilities(imageList, gcpProject)
	if err != nil {
		return err
	}

	cveFile, err := os.Create(outputFileName)
	if err != nil {
		return err
	}
	defer cveFile.Close()

	for _, cveResource := range cveList {
		cveWriter := bufio.NewWriter(cveFile)

		_, err = cveWriter.WriteString(string(fmt.Sprintf("### CVE for Resource ###\n")))
		_, err = cveWriter.WriteString(string(fmt.Sprintf("image: %v\n", cveResource.ResourceURI)))
		_, err = cveWriter.WriteString(string(fmt.Sprintf("### Listing CVEs and corresponding severity ###\n")))
		for index, cveNote := range cveResource.CVENotes {
			_, err = cveWriter.WriteString(string(fmt.Sprintf("  CVEName: %v\n  CvssScore: %v\n", cveNote, cveResource.SeverityList[index])))
		}
		cveWriter.Flush()
	}

	return nil
}
