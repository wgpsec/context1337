# ---- Stage 0: Fetch AboutSecurity (default: git clone) ----
FROM alpine/git AS aboutsecurity-git
ARG ABOUTSECURITY_REPO=https://github.com/wgpsec/AboutSecurity.git
ARG ABOUTSECURITY_REF=master
RUN git clone --depth 1 --branch ${ABOUTSECURITY_REF} ${ABOUTSECURITY_REPO} /aboutsecurity

# Normalize path: data always at / regardless of source.
# Override this stage with: --build-context aboutsecurity=../AboutSecurity
FROM scratch AS aboutsecurity
COPY --from=aboutsecurity-git /aboutsecurity/ /

# ---- Stage 0b: Fetch the supported nuclei HTTP vulnerability sources ----
FROM alpine/git AS nuclei-templates-git
RUN git clone --depth 1 --branch main --filter=blob:none --sparse \
    https://github.com/projectdiscovery/nuclei-templates.git /nuclei-templates \
    && git -C /nuclei-templates sparse-checkout set --no-cone \
        '/http/cves/**' \
        '/http/cnvd/**' \
        '/http/vulnerabilities/**' \
        '/http/misconfiguration/**' \
        '/http/default-logins/**'

# Release builds override this stage with a workflow-provided build context.
FROM scratch AS nuclei-templates
COPY --from=nuclei-templates-git /nuclei-templates/http/ /http/

# ---- Stage 1: Build FTS5 index with Python + jieba ----
FROM python:3.12-slim AS indexer
RUN pip install --no-cache-dir jieba pyyaml
COPY --from=aboutsecurity / /src/AboutSecurity/
COPY build/build_index.py build/security_dict.txt /src/build/
RUN mkdir -p /artifacts && python /src/build/build_index.py \
    --input /src/AboutSecurity/ \
    --dict /src/build/security_dict.txt \
    --output /artifacts/builtin.db

# ---- Stage 2: Build Go binary ----
FROM golang:1.25-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN mkdir -p /artifacts && CGO_ENABLED=1 GOOS=linux go build -tags "fts5 sqlite_json" -ldflags="-s -w" -o /artifacts/absec ./cmd/absec/
COPY --from=indexer /artifacts/builtin.db /artifacts/builtin.db
RUN /artifacts/absec finalize-index --db /artifacts/builtin.db

# ---- Stage 3: Minimal runtime ----
FROM gcr.io/distroless/base-debian12
ARG NUCLEI_TEMPLATES_REVISION=dev
COPY --from=builder /artifacts/builtin.db /app/data/builtin.db
COPY --from=aboutsecurity /skills/ /app/data/skills/
COPY --from=aboutsecurity /Dic/ /app/data/Dic/
COPY --from=aboutsecurity /Payload/ /app/data/Payload/
COPY --from=nuclei-templates /http/ /app/data/nuclei-templates-${NUCLEI_TEMPLATES_REVISION}/http/
COPY --from=builder /artifacts/absec /app/absec
ENV NUCLEI_TEMPLATES_DIR=/app/data/nuclei-templates-${NUCLEI_TEMPLATES_REVISION}
ENV NUCLEI_MIN_SEVERITY=high
LABEL org.opencontainers.image.nuclei-templates.revision=${NUCLEI_TEMPLATES_REVISION}
VOLUME /app/data/runtime
VOLUME /app/data/team
EXPOSE 1337
ENTRYPOINT ["/app/absec"]
CMD ["serve", "--port", "1337", "--data-dir", "/app/data"]
