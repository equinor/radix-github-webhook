package radix

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/equinor/radix-github-webhook/models"
	"github.com/rs/zerolog"
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
func (api *APIServerStub) ShowApplications(ctx context.Context, sshURL string) ([]*models.ApplicationSummary, error) {
	url := fmt.Sprintf(api.apiServerEndPoint+getApplicationSummariesEndPointPattern, url.QueryEscape(sshURL))
	response, err := api.makeRequest(ctx, "GET", url)
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
func (api *APIServerStub) GetApplication(ctx context.Context, appName string) (*models.Application, error) {
	url := fmt.Sprintf(api.apiServerEndPoint+getApplicationEndPointPattern, appName)
	response, err := api.makeRequest(ctx, "GET", url)
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
func (api *APIServerStub) TriggerPipeline(ctx context.Context, appName, branch, commitID, triggeredBy string) (*models.JobSummary, error) {
	url := fmt.Sprintf(api.apiServerEndPoint+startPipelineEndPointPattern, appName, buildDeployPipeline)
	parameters := models.PipelineParameters{Branch: branch, CommitID: commitID, TriggeredBy: triggeredBy}

	body, err := json.Marshal(parameters)
	if err != nil {
		return nil, err
	}

	response, err := api.makeRequestWithBody(ctx, "POST", url, body)
	if err != nil {
		return nil, err
	}

	jobSummary, err := unmarshalJobSummary(response)
	if err != nil {
		return nil, err
	}

	return jobSummary, nil
}

func (api *APIServerStub) makeRequest(ctx context.Context, method, url string) ([]byte, error) {
	return api.makeRequestWithBody(ctx, method, url, []byte{})
}

func (api *APIServerStub) makeRequestWithBody(ctx context.Context, method, url string, reqBody []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("unable create request for starting pipeline: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	zerolog.Ctx(ctx).Info().Str("method", method).Str("url", url).Msg("Request to Radix API")

	resp, err := api.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode >= 400 {
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
		return nil, fmt.Errorf("invalid response: %w", err)
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

	var res *ApiError
	if err := json.Unmarshal(body, &res); err != nil {
		return err
	}
	res.Code = resp.StatusCode
	return res
}
