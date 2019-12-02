# Kubeflow Scanner

## What is Kubeflow Scanner?

Kubeflow Scanner is a tool to walk through images in the kubeflow-images-public repo and list all CRITICAL and HIGH vulnerabilities.

Long term, this is a tool that can be run as part of your CI/CD pipeline to blacklist and whitelist vulnerabilities for your Kubeflow deployment.

## Quick Start

```bash
export GOOGLE_APPLICATION_CREDENTIALS=<path-to-service-account-key>
```

`make all`

## Container Analysis Backends

|Backend|Platform|Known to Work?|Status
|---	|---	|---	|---	|---
|[GCP API](https://cloud.google.com/container-registry/docs/reference/rest/)|CLI   	|Yes :heavy_check_mark:| :heavy_check_mark:|   	
|[GCP API](https://cloud.google.com/container-registry/docs/reference/rest/)|Kubernetes   	|Unsure :question:| None   	|
|[Clair](https://github.com/quay/clair)|Kubernetes   	|Unsure :question:| :hammer_and_wrench:   	|
|[Anchore Engine](https://github.com/quay/clair)|Kubernetes   	|Unsure :question:| None   	|

## Caveats

- Even if a repo is public, one does not simply list vulnerabilities for the repo (unless you have write access).

### TODO

- Add option to write results file to object store (GCS, S3...)
- CoreOS Clair as a backend
