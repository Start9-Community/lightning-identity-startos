.PHONY: proto test build

# Regenerates internal/lndrpc from the vendored protos. Needs buf,
# protoc-gen-go and protoc-gen-go-grpc on PATH (see proto/lnrpc/README.md).
proto:
	buf generate

test:
	go test ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o bin/ ./cmd/...
