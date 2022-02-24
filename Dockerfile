FROM golang:1.17-alpine as builder

ENV GO111MODULE=on

RUN apk update && \
    apk add ca-certificates  && \
    apk add --no-cache gcc musl-dev && \
    go get -u golang.org/x/lint/golint

WORKDIR /go/src/github.com/equinor/radix-github-webhook/

# Install project dependencies
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# run tests and linting
RUN golint `go list ./...` && \
    go vet `go list ./...` && \
    CGO_ENABLED=0 GOOS=linux go test `go list ./...`

# build
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -a -installsuffix cgo -o /usr/local/bin/radix-github-webhook
RUN addgroup -S -g 1000 radix-github-webhook
RUN adduser -S -u 1000 -G radix-github-webhook radix-github-webhook

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/local/bin/radix-github-webhook /usr/local/bin/radix-github-webhook
COPY --from=builder /etc/passwd /etc/passwd
EXPOSE 3001
USER 1000
ENTRYPOINT ["/usr/local/bin/radix-github-webhook"]
