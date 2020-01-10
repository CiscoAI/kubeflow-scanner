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

// VulnerabilityReport holds vulnerability information for a k8s cluster
type VulnerabilityReport struct {
	Namespace   string
	BadVulns    int // Total High + Critical vulns
	VulnByImage map[string][]*Vulnerability
}

// KFVulnerabilityReport holds vulnerability information across all images in a Kubeflow deployment
type KFVulnerabilityReport struct {
	KFDef       string
	Platform    string
	VulnByImage map[string][]*Vulnerability
	//BadVulns    int // Total High + Critical vulns
}
