.PHONY: all build test clean install cross-compile

BINARY_NAME=sketchy
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.Version=${VERSION}"

all: build

build:
	go build ${LDFLAGS} -o ${BINARY_NAME} .

test:
	go test -v ./...
	./${BINARY_NAME} test-files/test/test_malicious.py
	./${BINARY_NAME} -high-only test-files/test/test_malicious.py | grep -c "HIGH RISK" || true
	@echo "Tests completed"

clean:
	go clean
	rm -f ${BINARY_NAME}
	rm -f ${BINARY_NAME}-*

install: build
	sudo mv ${BINARY_NAME} /usr/local/bin/

cross-compile:
	@echo "Building for multiple platforms..."
	# macOS AMD64
	GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY_NAME}-darwin-amd64 .
	# macOS ARM64 (M1/M2)
	GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o ${BINARY_NAME}-darwin-arm64 .
	# Linux AMD64
	GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY_NAME}-linux-amd64 .
	# Linux ARM64
	GOOS=linux GOARCH=arm64 go build ${LDFLAGS} -o ${BINARY_NAME}-linux-arm64 .
	# Windows AMD64
	GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY_NAME}-windows-amd64.exe .
	# Windows ARM64
	GOOS=windows GOARCH=arm64 go build ${LDFLAGS} -o ${BINARY_NAME}-windows-arm64.exe .
	@echo "Cross-compilation complete!"

release: cross-compile
	@echo "Creating release archives..."
	tar czf ${BINARY_NAME}-darwin-amd64.tar.gz ${BINARY_NAME}-darwin-amd64
	tar czf ${BINARY_NAME}-darwin-arm64.tar.gz ${BINARY_NAME}-darwin-arm64
	tar czf ${BINARY_NAME}-linux-amd64.tar.gz ${BINARY_NAME}-linux-amd64
	tar czf ${BINARY_NAME}-linux-arm64.tar.gz ${BINARY_NAME}-linux-arm64
	zip ${BINARY_NAME}-windows-amd64.zip ${BINARY_NAME}-windows-amd64.exe
	zip ${BINARY_NAME}-windows-arm64.zip ${BINARY_NAME}-windows-arm64.exe
	@echo "Release archives created!"

run:
	./${BINARY_NAME} test-files/test/

run-high:
	./${BINARY_NAME} -high-only test-files/test/

help:
	@echo "Available targets:"
	@echo "  make build         - Build for current platform"
	@echo "  make test          - Run tests"
	@echo "  make clean         - Clean build artifacts"
	@echo "  make install       - Install to /usr/local/bin"
	@echo "  make cross-compile - Build for all platforms"
	@echo "  make release       - Create release archives"
	@echo "  make run           - Run on test directory"
	@echo "  make run-high      - Run on test directory (high risk only)"