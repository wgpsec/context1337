.PHONY: build test test-integration run docker clean index link-data clean-benchmark

# Paths
ABOUTSECURITY_DIR ?= ../AboutSecurity
ABOUTSECURITY_REPO = https://github.com/wgpsec/AboutSecurity.git

# Local development
build:
	go build -o absec ./cmd/absec/

test:
	go test ./...

test-integration:
	go test -tags integration -v .

# Clone AboutSecurity repo if not present
$(ABOUTSECURITY_DIR):
	git clone --depth 1 $(ABOUTSECURITY_REPO) $(ABOUTSECURITY_DIR)

# Build FTS5 index from AboutSecurity data
data/builtin.db: build/build_index.py build/security_dict.txt | $(ABOUTSECURITY_DIR)
	pip3 install --quiet jieba pyyaml
	python3 build/build_index.py \
		--input $(ABOUTSECURITY_DIR) \
		--dict build/security_dict.txt \
		--output data/builtin.db

# Symlink AboutSecurity content directories into data/ for local development
link-data: | $(ABOUTSECURITY_DIR)
	@for dir in Payload Dic Tools skills Vuln; do \
		if [ -d "$(ABOUTSECURITY_DIR)/$$dir" ] && [ ! -e "data/$$dir" ]; then \
			ln -s "$$(cd $(ABOUTSECURITY_DIR) && pwd)/$$dir" data/$$dir; \
			echo "Linked data/$$dir -> $(ABOUTSECURITY_DIR)/$$dir"; \
		fi; \
	done

# Alias for just building the index
index: data/builtin.db

run: build data/builtin.db link-data
	./absec serve --port 8088 --data-dir ./data

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
	rm -f data/builtin.db
	rm -f data/Payload data/Dic data/Tools data/skills data/Vuln
	rm -f data/runtime/runtime.db data/runtime/runtime.db-wal data/runtime/runtime.db-shm

clean-benchmark:
	rm -rf data/benchmark/
