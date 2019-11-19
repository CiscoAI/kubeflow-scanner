GO111MODULE=on go get -u github.com/google/go-containerregistry/cmd/gcrane
#gcrane cp -r gcr.io/kubeflow-images-public gcr.io/{GCP_PROJECT}
# remove the grep command to list all images in the repo to the images.txt
gcrane ls -r gcr.io/${GCP_PROJECT} | grep tensorflow-1.14.0 > images.txt
