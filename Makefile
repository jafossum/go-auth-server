# Go parameters
MODELS=${PWD}/models
GO_SVC=docker
MOCK=mocks

TEST_PKGS=./crypto/... ./handlers/
GEN_PKGS=./handlers/...
VET_PKGS=./crypto/... ./handlers/... ./models ./utils/...

.PHONY: all proto test fmt docker

all: clean proto test fmt

clean:
	rm -rf ${MOCK}

test:
	go generate $(GEN_PKGS)
	go vet $(VET_PKGS)
	go test -v $(TEST_PKGS)

fmt:
	go fmt $(VET_PKGS)

proto:
	protoc -I .  --proto_path=${MODELS}/proto --go_out=${MODELS} auth.proto

# Docker commands
docker:
	docker build -t auth-svc -f ./$(GO_SVC)/Dockerfile .
