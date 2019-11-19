all: list-images mod run

list-images:
	chmod +x list-images.sh
	bash list-images.sh
run:
	go run kubeflow-images/kubeflow-images.go --file ${IMAGE_FILE_NAME} --project ${GCP_PROJECT}
mod:
	go mod tidy
	go mod download
