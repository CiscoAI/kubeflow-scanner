// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

// [START containeranalysis_filter_vulnerability_occurrences]

import (
	"bufio"
	"context"
	"flag"
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
			log.Errorf("nil error encountered")
		}
		if err == iterator.Done {
			break
		} else if err != nil {
			return nil, fmt.Errorf("occurrence iteration error: %v", err)
		}
		for _, pkg := range occ.GetVulnerability().GetPackageIssue() {
			log.Infof("affected package: %v", pkg.AffectedPackage)
		}
		if occ.GetVulnerability().GetSeverity() == grafeaspb.Severity_HIGH || occ.GetVulnerability().GetSeverity() == grafeaspb.Severity_CRITICAL {
			occurenceList = append(occurenceList, occ)
		}
	}
	return occurenceList, nil
}

func buildResourceURL(textfile string) []string {
	file, err := os.Open(textfile)
	if err != nil {
		fmt.Printf("Error reading images text file: %v", err)
		return nil
	}
	defer file.Close()

	var imagesList []string
	fileScanner := bufio.NewScanner(file)
	for fileScanner.Scan() {
		imagesList = append(imagesList, "https://"+fileScanner.Text())
	}
	err = fileScanner.Err()
	if err != nil {
		return nil
	}
	return imagesList
}

func main() {
	// Use the result of `gcrane ls` from the textfile and build the resourceURLs
	var filepath string
	var gcpProjectName string
	flag.StringVar(&filepath, "file", "images.txt", "file path to the resule of `gcrane ls`")
	flag.StringVar(&gcpProjectName, "project", "", "GCP project with which container scanning is done")
	flag.Parse()

	resourceURLs := buildResourceURL("images.txt")
	var cveResources []*ResourceCVEList

	for _, resourceURL := range resourceURLs {
		occurenceList, err := findVulnerabilityOccurrencesForImage(resourceURL, gcpProjectName)
		if err != nil {
			fmt.Printf("Error fetching vulnerabilities: %v\n", err)
			return
		}
		if len(occurenceList) == 0 {
			log.Infof("No vulnerabilties found for resource: %v\n", resourceURL)
		} else {
			cveResource := &ResourceCVEList{}
			cveResource.ResourceURI = resourceURL
			for _, occurence := range occurenceList {
				cveResource.CVENotes = append(cveResource.CVENotes, occurence.GetNoteName())
				cveResource.SeverityList = append(cveResource.SeverityList, occurence.GetVulnerability().GetCvssScore())
			}
			cveResources = append(cveResources, cveResource)
		}
	}
	log.Info("Wrote all vulnerabilities to cvelist.yaml\n\n")
	// Create a file and write cveData to it
	cveFile, err := os.Create("cvelist.yaml")
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return
	}
	defer cveFile.Close()

	for _, cveResource := range cveResources {
		cveWriter := bufio.NewWriter(cveFile)

		_, err = cveWriter.WriteString(string(fmt.Sprintf("### CVE for Resource ###\n")))
		_, err = cveWriter.WriteString(string(fmt.Sprintf("image: %v\n", cveResource.ResourceURI)))
		_, err = cveWriter.WriteString(string(fmt.Sprintf("### Listing CVEs and corresponding severity ###\n")))
		for index, cveNote := range cveResource.CVENotes {
			_, err = cveWriter.WriteString(string(fmt.Sprintf("  CVEName: %v\n  CvssScore: %v\n", cveNote, cveResource.SeverityList[index])))
		}
		cveWriter.Flush()
	}
}
