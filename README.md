# Kubeflow Scanner

## What is Kubeflow Scanner?

Kubeflow Scanner is a tool to walk through all images in the kubeflow-images-public repo and list all CRITICAL and HIGH vulnerabilities.

## Quick Start

```bash
export IMAGE_FILE_NAME=images.txt
export GCP_PROJECT=<YOUR_GCP_PROJECT>
```

`make all`
