all: mod run

mod:
	go mod tidy
	go mod download

gen-proto:
	bash scripts/generate_protos.sh

run:
	go run cmd/scanr.go

run-server:
	go run cmd/scanr.go server

build: gen-proto mod
	GOOS=linux GOARCH=amd64 go build -o cmd/bin/linux/scanr cmd/scanr.go
	GOOS=darwin GOARCH=amd64 go build -o cmd/bin/darwin/scanr cmd/scanr.go
