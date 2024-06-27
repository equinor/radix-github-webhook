# Build stage
FROM golang:1.22-alpine3.20 as builder
ENV CGO_ENABLED=0 \
    GOOS=linux
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -ldflags "-s -w" -o /build/radix-github-webhook

# Final stage, ref https://github.com/GoogleContainerTools/distroless/blob/main/base/README.md for distroless
FROM gcr.io/distroless/static
WORKDIR /app
COPY --from=builder /build/radix-github-webhook .
USER 1000
ENTRYPOINT ["/app/radix-github-webhook"]
