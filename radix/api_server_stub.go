package radix

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/equinor/radix-github-webhook/models"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const buildDeployPipeline = "build-deploy"
const getApplicationSummariesEndPointPattern = "/v1/applications?sshRepo=%s"
const getApplicationEndPointPattern = "/v1/applications/%s"
const startPipelineEndPointPattern = "/v1/applications/%s/pipelines/%s"

// APIServerStub Makes calls to real API server
type APIServerStub struct {
	apiServerEndPoint string
	client            *http.Client
}

// NewAPIServerStub Constructor
func NewAPIServerStub(apiServerEndPoint string, client *http.Client) APIServer {
	return &APIServerStub{
		apiServerEndPoint: apiServerEndPoint,
		client:            client,
	}
}

// ShowApplications Implementation
func (api *APIServerStub) ShowApplications(sshURL string) ([]*models.ApplicationSummary, error) {
	url := fmt.Sprintf(api.apiServerEndPoint+getApplicationSummariesEndPointPattern, url.QueryEscape(sshURL))
	response, err := api.makeRequest("GET", url)
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
func (api *APIServerStub) GetApplication(appName string) (*models.Application, error) {
	url := fmt.Sprintf(api.apiServerEndPoint+getApplicationEndPointPattern, appName)
	response, err := api.makeRequest("GET", url)
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
func (api *APIServerStub) TriggerPipeline(appName, branch, commitID, triggeredBy string) (*models.JobSummary, error) {
	url := fmt.Sprintf(api.apiServerEndPoint+startPipelineEndPointPattern, appName, buildDeployPipeline)
	parameters := models.PipelineParameters{Branch: branch, CommitID: commitID, TriggeredBy: triggeredBy}

	body, err := json.Marshal(parameters)
	if err != nil {
		return nil, err
	}

	response, err := api.makeRequestWithBody("POST", url, body)
	if err != nil {
		return nil, err
	}

	jobSummary, err := unmarshalJobSummary(response)
	if err != nil {
		return nil, err
	}

	return jobSummary, nil
}

func (api *APIServerStub) makeRequest(method, url string) ([]byte, error) {
	return api.makeRequestWithBody(method, url, []byte{})
}

func (api *APIServerStub) makeRequestWithBody(method, url string, reqBody []byte) ([]byte, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, errors.Errorf("Unable create request for starting pipeline: %v", err)
	}
	req.Header.Set("Accept", "application/json")

	log.Infof("%s: %s", method, url)
	resp, err := api.client.Do(req)
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
	body, err := io.ReadAll(resp.Body)
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
