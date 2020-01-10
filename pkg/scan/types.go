package scan

// Vulnerability type for all backends
type Vulnerability struct {
	Identifier     string
	PackageName    string
	PackageVersion string
	Fix            string
	URL            string
	Severity       string
}

// ImageVulnerabilityReport holds vulnerability information per container image
type ImageVulnerabilityReport struct {
	Image    string
	BadVulns int // Bad Vulnerability = High + Critical
	Vulns    []*Vulnerability
}

// NamespaceVulnerabilityReport holds vulnerability information for a k8s cluster
type NamespaceVulnerabilityReport struct {
	Namespace   string
	BadVulns    int // Total High + Critical vulns
	VulnByImage []*ImageVulnerabilityReport
}

// KFVulnerabilityReport holds vulnerability information across all images in a Kubeflow deployment
type KFVulnerabilityReport struct {
	KFDef           string
	Platform        string
	BadVulns        int // Total High + Critical vulns
	VulnByNamespace []*NamespaceVulnerabilityReport
}

// ClusterVulnerabilityReport k8s cluster-wide vulnerability report
type ClusterVulnerabilityReport struct {
	ClusterContext  string
	BadVulns        int
	VulnByNamespace []*NamespaceVulnerabilityReport
}
