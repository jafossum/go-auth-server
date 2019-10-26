# Go parameters
MODELS=${PWD}/models

# .PHONY: binaries

all: proto

proto:
	protoc -I .  --proto_path=${MODELS}/proto --go_out=${MODELS} auth.proto
