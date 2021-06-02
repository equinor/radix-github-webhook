module github.com/equinor/radix-github-webhook

go 1.16

require (
	github.com/google/go-github/v35 v35.2.0
	github.com/gorilla/mux v1.7.3
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.10.0
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
)

replace (
	golang.org/x/crypto => golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
	golang.org/x/text => golang.org/x/text v0.3.6
)
