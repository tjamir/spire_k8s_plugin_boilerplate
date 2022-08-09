GOOS ?= "linux"
GOARCH ?= "amd64"
build:
	go mod tidy
	mkdir -p ./bin
	go build -o bin/psat_iid_agent agent/nodeattestor.go
	go build -o bin/psat_iid_server server/nodeattestor.go

test:
	go test -v -cover ./agent
	go test -v -cover ./server

images:
	docker build -f docker/agent.Dockerfile -t spire-agent-psat-iid .
	docker build -f docker/server.Dockerfile -t spire-server-psat-iid .

lint:
	go lint ./...
	
all: lint build test #images

clean:
	rm -rf ./bin
