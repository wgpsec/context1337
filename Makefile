.PHONY: build test run docker

# Local development
build:
	go build -o absec ./cmd/absec/

test:
	go test ./...

test-integration:
	go test -tags integration -v .

run: build
	./absec serve --port 8080 --data-dir ./data

# Docker — default: clones AboutSecurity from GitHub
docker:
	DOCKER_BUILDKIT=1 docker build -t context1337:latest -f build/Dockerfile .

# Build with a specific branch/tag
ABOUTSECURITY_REF ?= main
docker-ref:
	DOCKER_BUILDKIT=1 docker build -t context1337:latest -f build/Dockerfile \
		--build-arg ABOUTSECURITY_REF=$(ABOUTSECURITY_REF) .

# Build with local AboutSecurity repo (skip git clone)
ABOUTSECURITY_LOCAL ?= ../AboutSecurity
docker-local:
	DOCKER_BUILDKIT=1 docker build -t context1337:latest -f build/Dockerfile \
		--build-context aboutsecurity=$(ABOUTSECURITY_LOCAL) .

clean:
	rm -f absec
	rm -f data/runtime/runtime.db data/runtime/runtime.db-wal data/runtime/runtime.db-shm
