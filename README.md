# Kubeflow Scanner

## What is Kubeflow Scanner?

Kubeflow Scanner is a tool to walk through images in the kubeflow-images-public repo and list all CRITICAL and HIGH vulnerabilities.

Long term, this is a tool that can be run as part of your CI/CD pipeline to blacklist and whitelist vulnerabilities for your Kubeflow deployment.

## Quick Start

```bash
export IMAGE_FILE_NAME=images.txt
export GCP_PROJECT=<YOUR_GCP_PROJECT>
```

`make all`
