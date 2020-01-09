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

// VulnerabilityReport holds vulnerability information for a k8s cluster
type VulnerabilityReport struct {
	Vulns           []Vulnerability
	VulnsBySeverity map[string][]Vulnerability
	BadVulns        int // High or Critical vulns
}

// KFVulnerabilityReport holds vulnerability information across all images in a Kubeflow deployment
type KFVulnerabilityReport struct {
	KFDef           string
	Platform        string
	Vulns           []Vulnerability
	VulnsBySeverity map[string][]Vulnerability
	BadVulns        int // High or Critical vulns
}
