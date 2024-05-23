FROM golang:1.22-alpine3.19 as builder

ENV GO111MODULE=on

RUN apk update && \
    apk add ca-certificates  && \
    apk add --no-cache gcc musl-dev

WORKDIR /go/src/github.com/equinor/radix-github-webhook/

# Install project dependencies
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# build
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -a -installsuffix cgo -o /radix-github-webhook
RUN addgroup -S -g 1000 radix-github-webhook
RUN adduser -S -u 1000 -G radix-github-webhook radix-github-webhook

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /radix-github-webhook /usr/local/bin/radix-github-webhook
COPY --from=builder /etc/passwd /etc/passwd
EXPOSE 3001
USER 1000
ENTRYPOINT ["/usr/local/bin/radix-github-webhook"]
