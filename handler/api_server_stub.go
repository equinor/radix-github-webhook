package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	log "github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	"github.com/statoil/radix-github-webhook/models"
)

// APIServer Stub methods in order to mock endpoints
type APIServer interface {
	ShowApplications(bearerToken, sshURL string) ([]*models.ApplicationRegistration, error)
	TriggerPipeline(bearerToken, appName, branch string) (string, error)
}

const buildDeployPipeline = "build-deploy"

// TODO: Should we standardize on a port
const apiServerEndPoint = "http://server.radix-api-prod:3002/api"
const getRegistrationsEndPointPattern = apiServerEndPoint + "/v1/applications?sshRepo=%s"
const startPipelineEndPointPattern = apiServerEndPoint + "/v1/applications/%s/pipelines/%s"

// APIServerStub Makes calls to real API server
type APIServerStub struct {
}

// ShowApplications Implementation
func (api *APIServerStub) ShowApplications(bearerToken, sshURL string) ([]*models.ApplicationRegistration, error) {
	url := fmt.Sprintf(getRegistrationsEndPointPattern, url.QueryEscape(sshURL))
	response, err := makeRequest(bearerToken, "GET", url)
	if err != nil {
		return nil, err
	}

	rrs, err := unmarshal(response)
	if err != nil {
		return nil, err
	}

	return rrs, nil
}

// TriggerPipeline Implementation
func (api *APIServerStub) TriggerPipeline(bearerToken, appName, branch string) (string, error) {
	url := fmt.Sprintf(startPipelineEndPointPattern, appName, buildDeployPipeline)

	parameters := models.PipelineParameters{Branch: branch}
	body, err := json.Marshal(parameters)
	if err != nil {
		return "", err
	}

	response, err := makeRequestWithBody(bearerToken, "POST", url, body)
	if err != nil {
		return "", err
	}

	return string(response), nil
}

func makeRequest(bearerToken, method, url string) ([]byte, error) {
	return makeRequestWithBody(bearerToken, method, url, []byte{})
}

func makeRequestWithBody(bearerToken, method, url string, reqBody []byte) ([]byte, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, errors.Errorf("Unable create request for starting pipeline: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearerToken))

	log.Infof("%s: %s", method, url)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Errorf("Request failed: %v", err)
	}

	if resp.StatusCode != 200 {
		return nil, errors.Errorf("Request failed with error: %s", resp.Status)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Errorf("Invalid response: %v", err)
	}

	return body, nil
}

func unmarshal(b []byte) ([]*models.ApplicationRegistration, error) {
	var res []*models.ApplicationRegistration
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}
	return res, nil
}
