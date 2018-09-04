FROM golang:alpine as builder
RUN apk update && apk add git && apk add bash && apk add ca-certificates
RUN adduser -D -g '' appuser

COPY . $GOPATH/src/ingeknudsen/webhook/
WORKDIR $GOPATH/src/ingeknudsen/webhook/

RUN go get -d -v
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags='-w -s' -o /go/bin/app

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /go/bin/app /go/bin/app
USER appuser

EXPOSE 8000
ENTRYPOINT ["/go/bin/app"]
