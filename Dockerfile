FROM golang:alpine3.7 as builder
RUN apk update && \
    apk add git && \
    apk add -y ca-certificates curl && \
    apk add --no-cache gcc musl-dev && \
    go get -u golang.org/x/lint/golint && \
    curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh

WORKDIR /go/src/github.com/equinor/radix-github-webhook/
COPY Gopkg.toml Gopkg.lock ./
RUN dep ensure -vendor-only
COPY . .

RUN golint `go list ./...` && \
    go vet `go list ./...` && \
    CGO_ENABLED=0 GOOS=linux go test ./...
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -a -installsuffix cgo -o /usr/local/bin/radix-github-webhook

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/local/bin/radix-github-webhook /usr/local/bin/radix-github-webhook
EXPOSE 3001
ENTRYPOINT ["/usr/local/bin/radix-github-webhook"]
