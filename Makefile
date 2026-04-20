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

# Docker — must run from parent directory where AboutSecurity/ lives
# Example: cd .. && make -C aboutsecurity-mcp docker
docker:
	docker build -t context1337:latest -f build/Dockerfile ..

clean:
	rm -f absec
	rm -f data/runtime/runtime.db data/runtime/runtime.db-wal data/runtime/runtime.db-shm
