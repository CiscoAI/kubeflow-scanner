package kubernetes

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	pbv1alpha1 "github.com/CiscoAI/kubeflow-scanner/gen/pb-go/proto/v1alpha1"
	"github.com/CiscoAI/kubeflow-scanner/pkg/scan/anchore"
	"github.com/cenkalti/backoff"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

var lock sync.Mutex

func ImageScanWorkflow(image string) (*pbv1alpha1.ImageVulnerabilityReport, error) {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	err := anchore.ScanImage(ctx, image)
	if err != nil {
		return nil, nil
	}
	retryGetImage := func() error {
		err = anchore.GetImage(ctx, image)
		if err != nil {
			return err
		}
		return nil
	}
	getScanbackoff := backoff.NewExponentialBackOff()
	getScanbackoff.MaxElapsedTime = 5 * time.Minute
	err = backoff.Retry(retryGetImage, getScanbackoff)
	if err != nil {
		return nil, err
	}
	vulns, err := anchore.GetVuln(ctx, image)
	if err != nil {
		return nil, err
	}
	return vulns, nil
}

// ScanCluster - given a KF cluster iterate through all images and compile a VulnReport
func ScanCluster(namespace string) (*pbv1alpha1.NamespaceVulnerabilityReport, error) {
	vulnReport := &pbv1alpha1.NamespaceVulnerabilityReport{}
	// Iterate through pods, get all images and scan them for vulns
	images, err := ImageLister(namespace)
	if err != nil {
		return vulnReport, err
	}
	vulnReport.Namespace = namespace
	for _, image := range images {
		vulnPerImageReport, err := ImageScanWorkflow(image)
		if err != nil {
			return vulnReport, nil
		}
		if vulnPerImageReport.Vulns == nil && vulnPerImageReport.BadVulns > 0 {
			return vulnReport, fmt.Errorf("Vulns returned nil for scan")
		}
		if vulnPerImageReport.BadVulns > 0 {
			vulnReport.ImageVulnReport = append(vulnReport.ImageVulnReport, vulnPerImageReport)
		}
		vulnReport.BadVulns += vulnPerImageReport.BadVulns
		log.Infof("--------------------")
	}
	return vulnReport, nil
}

func WriteReportToFile(outputFilePath string, vulnReport *pbv1alpha1.NamespaceVulnerabilityReport) error {
	err := save(outputFilePath, vulnReport)
	if err != nil {
		return err
	}
	return nil
}

func save(path string, object interface{}) error {
	lock.Lock()
	defer lock.Unlock()

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	objectData, err := yaml.Marshal(object)
	if err != nil {
		return err
	}
	_, err = io.Copy(file, bytes.NewReader(objectData))
	if err != nil {
		return err
	}
	return nil
}
