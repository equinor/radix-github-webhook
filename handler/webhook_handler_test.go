package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/equinor/radix-github-webhook/models"
	"github.com/google/go-github/v28/github"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const anyJobName = "anyJobName"

func Test_GetBranch_RemovesRefsHead(t *testing.T) {
	assert.Equal(t, "master", getBranch(&github.PushEvent{Ref: strPtr("refs/heads/master")}))
	assert.Equal(t, "feature/RA-326-TestBranch", getBranch(&github.PushEvent{Ref: strPtr("refs/heads/feature/RA-326-TestBranch")}))
	assert.Equal(t, "hotfix/api/refs/heads/fix1", getBranch(&github.PushEvent{Ref: strPtr("refs/heads/hotfix/api/refs/heads/fix1")}))
}

func Test_get_radix_operator_repo_ssh_url_by_ping_url(t *testing.T) {
	pingURL := "https://api.github.com/repos/equinor/radix-operator/hooks/50561858"
	url := getSSHUrlFromPingURL(pingURL)

	assert.Equal(t, "git@github.com:equinor/radix-operator.git", url)
}

func Test_get_priv_repo_ssh_url_by_ping_url(t *testing.T) {
	pingURL := "https://api.github.com/repos/keaaa/go-roman/hooks/9917077"
	url := getSSHUrlFromPingURL(pingURL)

	assert.Equal(t, "git@github.com:keaaa/go-roman.git", url)
}

func TestSHA1MAC_CorrectlyEncrypted(t *testing.T) {
	salt := []byte("Any shared secret")
	message := []byte("Any message body\n")
	expected := "sha1=cdab0add853d4a7c1ab2db66830e7637ec8b4ecf"
	actual := SHA1HMAC(salt, message)

	assert.Equal(t, expected, actual, "SHA1HMAC - Incorrect encryption")
}

func TestHandleWebhookEvents_PullRequestEvent_FailsWithUnknownEvent(t *testing.T) {
	payload := NewGitHubPayloadBuilder().
		withURL("git@github.com:equinor/repo-1.git").
		BuildPullRequestEventPayload()
	_, err := triggerWebhook("pull_request", payload, "AnySharedSecret")
	assert.Error(t, err, "HandleWebhookEvents - Could not find matching repo")
}

func TestHandleWebhookEvents_PingEventUnmatchedRepo_Fails(t *testing.T) {
	payload := NewGitHubPayloadBuilder().
		withURL("https://api.github.com/repos/equinor/repo-4/hooks/12345678").
		BuildPingEventPayload()
	_, err := triggerWebhook("ping", payload, "AnySharedSecret")
	assert.Error(t, err, "HandleWebhookEvents - Could not find matching repo")
}

func TestHandleWebhookEvents_PingEventMatchedMultipleRepos_Fails(t *testing.T) {
	payload := NewGitHubPayloadBuilder().
		withURL("https://api.github.com/repos/equinor/repo-2/hooks/12345678").
		BuildPingEventPayload()
	_, err := triggerWebhook("ping", payload, "AnySharedSecret")
	assert.Error(t, err, "HandleWebhookEvents - Multiple matching registrations for the same repo is not allowed")
}

func TestHandleWebhookEvents_PingEventWithIncorrectSecret_Fails(t *testing.T) {
	payload := NewGitHubPayloadBuilder().
		withURL("https://api.github.com/repos/equinor/repo-1/hooks/12345678").
		BuildPingEventPayload()
	_, err := triggerWebhook("ping", payload, "IncorrectSecret")
	assert.Error(t, err, "HandleWebhookEvents - Shared secret was different and should cause error")
}

func TestHandleWebhookEvents_PingEventWithCorrectSecret_SucceedsWithCorrectMessage(t *testing.T) {
	const commitID = "4faca8595c5283a9d0f17a623b9255a0d9866a2e"
	payload := NewGitHubPayloadBuilder().
		withRef("refs/heads/master").
		withAfter(commitID).
		withURL("https://api.github.com/repos/equinor/repo-1/hooks/12345678").
		BuildPingEventPayload()
	response, err := triggerWebhook("ping", payload, "AnySharedSecret")
	assert.NoError(t, err, "HandleWebhookEvents - Error occured")

	expected := fmt.Sprintf("Webhook is configured correctly with for the Radix project %s", "app-1")
	assert.Equal(t, expected, response, "HandleWebhookEvents - Message not expected")
}

func TestHandleWebhookEvents_PushEventUnmatchedRepo_Fails(t *testing.T) {
	const commitID = "4faca8595c5283a9d0f17a623b9255a0d9866a2e"
	payload := NewGitHubPayloadBuilder().
		withRef("refs/heads/master").
		withAfter(commitID).
		withURL("git@github.com:equinor/repo-4.git").
		BuildPushEventPayload()
	_, err := triggerWebhook("push", payload, "AnySharedSecret")
	assert.Error(t, err, "HandleWebhookEvents - Could not find matching repo")
}

func TestHandleWebhookEvents_PushEventMatchedMultipleRepos_Fails(t *testing.T) {
	const commitID = "4faca8595c5283a9d0f17a623b9255a0d9866a2e"
	payload := NewGitHubPayloadBuilder().
		withRef("refs/heads/master").
		withAfter(commitID).
		withURL("git@github.com:equinor/repo-2.git").
		BuildPushEventPayload()
	_, err := triggerWebhook("push", payload, "AnySharedSecret")
	assert.Error(t, err, "HandleWebhookEvents - Multiple matching registrations for the same repo is not allowed")
}

func TestHandleWebhookEvents_PushEventOnMasterWithIncorrectSecret_Fails(t *testing.T) {
	const commitID = "4faca8595c5283a9d0f17a623b9255a0d9866a2e"
	payload := NewGitHubPayloadBuilder().
		withRef("refs/heads/master").
		withAfter(commitID).
		withURL("git@github.com:equinor/repo-1.git").
		BuildPushEventPayload()
	_, err := triggerWebhook("push", payload, "IncorrectSecret")
	assert.Error(t, err, "HandleWebhookEvents - Shared secret was different and should cause error")
}

func TestHandleWebhookEvents_PushEventOnMaster_SucceedsWithCorrectMessage(t *testing.T) {
	const commitID = "4faca8595c5283a9d0f17a623b9255a0d9866a2e"
	payload := NewGitHubPayloadBuilder().
		withRef("refs/heads/master").
		withAfter(commitID).
		withURL("git@github.com:equinor/repo-1.git").
		BuildPushEventPayload()
	response, err := triggerWebhook("push", payload, "AnySharedSecret")
	assert.NoError(t, err, "HandleWebhookEvents - No error occured")

	assert.Equal(t, getMessageForJob(anyJobName, "app-1", "master", commitID), response, "HandleWebhookEvents - Message not expected")
}

func triggerWebhook(event string, payload []byte, sharedSecret string) (string, error) {
	wh := NewWebHookHandler("token", NewAPIServerMock())
	w := httptest.NewRecorder()
	r, err := http.NewRequest("POST", "", bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %s", err)
	}
	r.Header.Add("X-GitHub-Event", event)
	r.Header.Add("X-Hub-Signature", SHA1HMAC([]byte(sharedSecret), payload))
	wh.handleEvent(w, r)

	var res response
	err = json.Unmarshal(w.Body.Bytes(), &res)
	if err != nil {
		return "", err
	}

	if w.Code != 200 {
		return res.Message, errors.Errorf("Request failed with error: %d", w.Code)
	}

	return res.Message, nil
}

type response struct {
	Message string `json:"message"`
}

type APIServerMock struct {
	radixRegistrations map[string][]*models.Application
}

func NewAPIServerMock() *APIServerMock {
	radixRegistrations := make(map[string][]*models.Application)
	app1 := models.NewApplicationBuilder().WithName("app-1").WithSharedSecret("AnySharedSecret").Build()
	app2 := models.NewApplicationBuilder().WithName("app-2").WithSharedSecret("AnySharedSecret").Build()
	app3 := models.NewApplicationBuilder().WithName("app-3").WithSharedSecret("AnySharedSecret3").Build()

	radixRegistrations["git@github.com:equinor/repo-1.git"] = []*models.Application{app1}
	radixRegistrations["git@github.com:equinor/repo-2.git"] = []*models.Application{app2, app3}

	return &APIServerMock{
		radixRegistrations: radixRegistrations}

}

func (api *APIServerMock) ShowApplications(bearerToken, url string) ([]*models.ApplicationSummary, error) {
	applicationSummaries := make([]*models.ApplicationSummary, len(api.radixRegistrations[url]))
	for index, application := range api.radixRegistrations[url] {
		applicationSummaries[index] = &models.ApplicationSummary{Name: application.Registration.Name}
	}

	return applicationSummaries, nil
}

func (api *APIServerMock) GetApplication(bearerToken, appName string) (*models.Application, error) {
	for _, applications := range api.radixRegistrations {
		for _, application := range applications {
			if strings.EqualFold(application.Registration.Name, appName) {
				return application, nil
			}
		}
	}

	return nil, nil
}

func (api *APIServerMock) TriggerPipeline(bearerToken, appName, branch, commitID, triggeredBy string) (*models.JobSummary, error) {
	return &models.JobSummary{
		Name:        anyJobName,
		AppName:     appName,
		Branch:      branch,
		CommitID:    commitID,
		TriggeredBy: triggeredBy,
	}, nil
}

// GitHubPayloadBuilder Handles construction of github payload
type GitHubPayloadBuilder interface {
	withRef(string) GitHubPayloadBuilder
	withAfter(string) GitHubPayloadBuilder
	withURL(string) GitHubPayloadBuilder
	BuildPushEventPayload() []byte
	BuildPingEventPayload() []byte
	BuildPullRequestEventPayload() []byte
}

type gitHubPayloadBuilder struct {
	ref   string
	after string
	url   string
}

// NewGitHubPayloadBuilder Constructor
func NewGitHubPayloadBuilder() GitHubPayloadBuilder {
	return &gitHubPayloadBuilder{}
}

func (pb *gitHubPayloadBuilder) withRef(ref string) GitHubPayloadBuilder {
	pb.ref = ref
	return pb
}

func (pb *gitHubPayloadBuilder) withAfter(after string) GitHubPayloadBuilder {
	pb.after = after
	return pb
}

func (pb *gitHubPayloadBuilder) withURL(url string) GitHubPayloadBuilder {
	pb.url = url
	return pb
}

func (pb *gitHubPayloadBuilder) BuildPushEventPayload() []byte {
	payload := `{
		"ref": "#REF#",
		"after": "#AFTER#",
		"repository": {
		  "ssh_url": "#SSHURL#"
		}
	}`

	payload = strings.Replace(payload, "#REF#", pb.ref, 1)
	payload = strings.Replace(payload, "#AFTER#", pb.after, 1)
	payload = strings.Replace(payload, "#SSHURL#", pb.url, 1)
	return []byte(payload)
}

func (pb *gitHubPayloadBuilder) BuildPingEventPayload() []byte {
	payload := `{
		"hook": {
		  "url": "#URL#"
		}
	}`

	payload = strings.Replace(payload, "#URL#", pb.url, 1)
	return []byte(payload)
}

func (pb *gitHubPayloadBuilder) BuildPullRequestEventPayload() []byte {
	payload := `{
		"repository": {
		  "ssh_url": "#SSHURL#"
		}
	}`

	payload = strings.Replace(payload, "#SSHURL#", pb.url, 1)
	return []byte(payload)
}

func strPtr(s string) *string {
	return &s
}
