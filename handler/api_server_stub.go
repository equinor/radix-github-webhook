package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/equinor/radix-github-webhook/models"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// APIServer Stub methods in order to mock endpoints
type APIServer interface {
	ShowApplications(bearerToken, sshURL string) ([]*models.ApplicationSummary, error)
	GetApplication(bearerToken, appName string) (*models.Application, error)
	TriggerPipeline(bearerToken, appName, branch, commitID, triggeredBy string) (*models.JobSummary, error)
}

const buildDeployPipeline = "build-deploy"
const getApplicationSummariesEndPointPattern = "/v1/applications?sshRepo=%s"
const getApplicationEndPointPattern = "/v1/applications/%s"
const startPipelineEndPointPattern = "/v1/applications/%s/pipelines/%s"

// APIServerStub Makes calls to real API server
type APIServerStub struct {
	apiServerEndPoint string
}

// NewAPIServerStub Constructor
func NewAPIServerStub(apiServerEndPoint string) APIServer {
	return &APIServerStub{
		apiServerEndPoint: apiServerEndPoint,
	}
}

// ShowApplications Implementation
func (api *APIServerStub) ShowApplications(bearerToken, sshURL string) ([]*models.ApplicationSummary, error) {
	url := fmt.Sprintf(api.apiServerEndPoint+getApplicationSummariesEndPointPattern, url.QueryEscape(sshURL))
	response, err := makeRequest(bearerToken, "GET", url)
	if err != nil {
		return nil, err
	}

	rrs, err := unmarshalApplicationSummary(response)
	if err != nil {
		return nil, err
	}

	return rrs, nil
}

// GetApplication Implementation
func (api *APIServerStub) GetApplication(bearerToken, appName string) (*models.Application, error) {
	url := fmt.Sprintf(api.apiServerEndPoint+getApplicationEndPointPattern, appName)
	response, err := makeRequest(bearerToken, "GET", url)
	if err != nil {
		return nil, err
	}

	application, err := unmarshalApplication(response)
	if err != nil {
		return nil, err
	}

	return application, nil
}

// TriggerPipeline Implementation
func (api *APIServerStub) TriggerPipeline(bearerToken, appName, branch, commitID, triggeredBy string) (*models.JobSummary, error) {
	url := fmt.Sprintf(api.apiServerEndPoint+startPipelineEndPointPattern, appName, buildDeployPipeline)

	parameters := models.PipelineParameters{Branch: branch, CommitID: commitID, TriggeredBy: triggeredBy}

	body, err := json.Marshal(parameters)
	if err != nil {
		return nil, err
	}

	response, err := makeRequestWithBody(bearerToken, "POST", url, body)
	if err != nil {
		return nil, err
	}

	jobSummary, err := unmarshalJobSummary(response)
	if err != nil {
		return nil, err
	}

	return jobSummary, nil
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
		return nil, unmarshalError(resp)
	}

	body, err := readBody(resp)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func readBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Errorf("Invalid response: %v", err)
	}

	return body, nil
}

func unmarshalApplicationSummary(b []byte) ([]*models.ApplicationSummary, error) {
	var res []*models.ApplicationSummary
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func unmarshalApplication(b []byte) (*models.Application, error) {
	var res *models.Application
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func unmarshalJobSummary(b []byte) (*models.JobSummary, error) {
	var res *models.JobSummary
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func unmarshalError(resp *http.Response) error {
	body, err := readBody(resp)
	if err != nil {
		return err
	}

	var res *models.Error
	if err := json.Unmarshal(body, &res); err != nil {
		return err
	}

	return errors.Errorf("%s", res.Message)
}
