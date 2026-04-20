# Stage 1: Build FTS5 index with Python + jieba
FROM python:3.12-slim AS indexer
RUN pip install --no-cache-dir jieba pyyaml
# AboutSecurity is COPYed from parent context via docker build -f
COPY AboutSecurity/ /src/AboutSecurity/
COPY aboutsecurity-mcp/build/build_index.py aboutsecurity-mcp/build/security_dict.txt /src/build/
RUN python /src/build/build_index.py \
    --input /src/AboutSecurity/ \
    --dict /src/build/security_dict.txt \
    --output /artifacts/builtin.db

# Stage 2: Build Go binary
FROM golang:1.25 AS builder
WORKDIR /src
COPY aboutsecurity-mcp/go.mod aboutsecurity-mcp/go.sum ./
RUN go mod download
COPY aboutsecurity-mcp/ .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /artifacts/absec ./cmd/absec/

# Stage 3: Minimal runtime
FROM gcr.io/distroless/static-debian12
COPY --from=indexer /artifacts/builtin.db /app/data/builtin.db
COPY --from=indexer /src/AboutSecurity/skills/ /app/data/skills/
COPY --from=indexer /src/AboutSecurity/Dic/ /app/data/Dic/
COPY --from=indexer /src/AboutSecurity/Payload/ /app/data/Payload/
COPY --from=indexer /src/AboutSecurity/Tools/ /app/data/Tools/
COPY --from=builder /artifacts/absec /app/absec
VOLUME /app/data/runtime
VOLUME /app/data/team
EXPOSE 8080
ENTRYPOINT ["/app/absec"]
CMD ["serve", "--port", "8080", "--data-dir", "/app/data"]
