FROM golang:alpine3.7 as builder
RUN apk update && apk add git && apk add -y ca-certificates curl && \
    curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
RUN mkdir -p /go/src/github.com/statoil/radix-github-webhook/
WORKDIR /go/src/github.com/statoil/radix-github-webhook/
COPY Gopkg.toml Gopkg.lock ./
RUN dep ensure -vendor-only
COPY . .
WORKDIR /go/src/github.com/statoil/radix-github-webhook/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -a -installsuffix cgo -o /usr/local/bin/radix-github-webhook
RUN adduser -D -g '' radix-github-webhook

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /usr/local/bin/radix-github-webhook /usr/local/bin/radix-github-webhook
USER radix-github-webhook
EXPOSE 3001
ENTRYPOINT ["/usr/local/bin/radix-github-webhook"]
