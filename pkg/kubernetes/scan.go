package kubernetes

import (
	"context"
	"time"

	"github.com/CiscoAI/kubeflow-scanner/pkg/scan"
	"github.com/CiscoAI/kubeflow-scanner/pkg/scan/anchore"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// KFVuln holds the pod-wise vuln
type KFVuln struct {
	PodName     string
	VulnByImage map[string][]scan.Vulnerability
}

// ScanCluster - given a KF cluster iterate through all images and compile a VulnReport
func ScanCluster(kubeconfig string, namespace string) (scan.VulnerabilityReport, error) {
	vulnReport := scan.VulnerabilityReport{}
	// Authenticate to Kubernetes cluster
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return scan.VulnerabilityReport{}, err
	}
	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return scan.VulnerabilityReport{}, err
	}

	// Fetch all pods in the namespace
	pods, err := clientset.CoreV1().Pods(namespace).List(metav1.ListOptions{})
	if err != nil {
		return scan.VulnerabilityReport{}, err
	}
	//var kfVuln []KFVuln
	// Iterate through pods, get all images and scan them for vulns
	for _, pod := range pods.Items {
		currentVuln := &KFVuln{}
		//var currentImageVuln map[string][]scan.Vulnerability
		log.Infof("Scanning pod: %s", pod.Name)
		currentVuln.PodName = pod.Name
		for _, container := range pod.Spec.Containers {
			log.Infof("Scanning Container Image: %v", container.Image)
			ctx := context.Background()
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			_, err := anchore.GetVuln(ctx, container.Image)
			if err != nil {
				return scan.VulnerabilityReport{}, err
			}

		}
		log.Infof("-----------------")
	}
	return vulnReport, nil
}

func ScanKFCluster(kfdef string, kubeconfig string, namespace string) (scan.KFVulnerabilityReport, error) {
	return scan.KFVulnerabilityReport{}, nil
}
