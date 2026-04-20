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

# Docker — self-contained build, clones AboutSecurity from GitHub
docker:
	docker build -t context1337:latest -f build/Dockerfile .

# Build with a specific branch/tag of AboutSecurity
# Example: make docker-ref ABOUTSECURITY_REF=dev
ABOUTSECURITY_REF ?= main
docker-ref:
	docker build -t context1337:latest -f build/Dockerfile \
		--build-arg ABOUTSECURITY_REF=$(ABOUTSECURITY_REF) .

clean:
	rm -f absec
	rm -f data/runtime/runtime.db data/runtime/runtime.db-wal data/runtime/runtime.db-shm
