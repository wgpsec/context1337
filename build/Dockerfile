# ---- Stage 0: Fetch AboutSecurity (default: git clone) ----
FROM alpine/git AS aboutsecurity-git
ARG ABOUTSECURITY_REPO=https://github.com/wgpsec/AboutSecurity.git
ARG ABOUTSECURITY_REF=main
RUN git clone --depth 1 --branch ${ABOUTSECURITY_REF} ${ABOUTSECURITY_REPO} /aboutsecurity

# Normalize path: data always at / regardless of source.
# Override this stage with: --build-context aboutsecurity=../AboutSecurity
FROM scratch AS aboutsecurity
COPY --from=aboutsecurity-git /aboutsecurity/ /

# ---- Stage 1: Build FTS5 index with Python + jieba ----
FROM python:3.12-slim AS indexer
RUN pip install --no-cache-dir jieba pyyaml
COPY --from=aboutsecurity / /src/AboutSecurity/
COPY build/build_index.py build/security_dict.txt /src/build/
RUN python /src/build/build_index.py \
    --input /src/AboutSecurity/ \
    --dict /src/build/security_dict.txt \
    --output /artifacts/builtin.db

# ---- Stage 2: Build Go binary ----
FROM golang:1.25 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /artifacts/absec ./cmd/absec/

# ---- Stage 3: Minimal runtime ----
FROM gcr.io/distroless/static-debian12
COPY --from=indexer /artifacts/builtin.db /app/data/builtin.db
COPY --from=aboutsecurity /skills/ /app/data/skills/
COPY --from=aboutsecurity /Dic/ /app/data/Dic/
COPY --from=aboutsecurity /Payload/ /app/data/Payload/
COPY --from=builder /artifacts/absec /app/absec
VOLUME /app/data/runtime
VOLUME /app/data/team
EXPOSE 8088
ENTRYPOINT ["/app/absec"]
CMD ["serve", "--port", "8088", "--data-dir", "/app/data"]
