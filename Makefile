# Go parameters
AUTH=./config/auth/auth

# .PHONY: binaries

all: proto

proto:
	protoc -I .  --go_out=. ${AUTH}.proto
