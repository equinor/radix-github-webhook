package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_get_api_service_endpoint_format(t *testing.T) {
	expect := "https://server-radix-api-prod.weekly-11.dev.radix.equinor.com/api"
	apiPrefix := "https://server-radix-api-prod"
	clusterName := "weekly-11"
	dnsZone := "dev.radix.equinor.com"

	_ = os.Setenv("API_SERVER_ENDPOINT_PREFIX", apiPrefix)
	_ = os.Setenv("RADIX_CLUSTERNAME", clusterName)
	_ = os.Setenv("RADIX_DNS_ZONE", dnsZone)

	url := getAPIServerEndpoint()

	assert.Equal(t, expect, url)

}
