all: mod run

mod:
	go mod tidy
	go mod download

gen-proto:
	bash scripts/generate_protos.sh

build:
	go build -o cmd/bin/scanr-mac cmd/scanr.go

run:
	go run cmd/scanr.go

run-server:
	go run cmd/scanr.go server
