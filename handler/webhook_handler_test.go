package handler

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/equinor/radix-github-webhook/models"
	"github.com/equinor/radix-github-webhook/radix"
	"github.com/equinor/radix-github-webhook/router"
	"github.com/golang/mock/gomock"
	"github.com/google/go-github/v45/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func Test_HandlerTestSuite(t *testing.T) {
	suite.Run(t, new(handlerTestSuite))
}

type handlerTestSuite struct {
	suite.Suite
	apiServer *radix.MockAPIServer
	w         *httptest.ResponseRecorder
	ctrl      *gomock.Controller
}

func (*handlerTestSuite) computeSignature(key, message []byte) string {
	digest := hmac.New(sha256.New, key)
	digest.Write(message)
	sum := digest.Sum(nil)
	return fmt.Sprintf("sha256=%x", sum)
}

func (s *handlerTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.apiServer = radix.NewMockAPIServer(s.ctrl)
	s.w = httptest.NewRecorder()
}

func (s *handlerTestSuite) Test_MissingEventTypeHeader() {
	sut := NewWebHookHandler("token", s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", nil)

	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal(notAGithubEventMessage, res.Error)
}

func (s *handlerTestSuite) Test_UnhandledEventType() {
	payload := NewGitHubPayloadBuilder().
		withURL("git@github.com:equinor/repo-1.git").
		BuildPullRequestEventPayload()

	sut := NewWebHookHandler("token", s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("X-GitHub-Event", "pull_request")
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal(unhandledEventTypeMessage("pull_request"), res.Error)
}

func (s *handlerTestSuite) Test_PingEventShowApplicationsReturnError() {
	payload := NewGitHubPayloadBuilder().
		withURL("https://api.github.com/repos/equinor/repo-4/hooks/12345678").
		BuildPingEventPayload()

	s.apiServer.EXPECT().ShowApplications("token", "git@github.com:equinor/repo-4.git").Return(nil, errors.New("any error")).Times(1)

	sut := NewWebHookHandler("token", s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("X-GitHub-Event", "ping")
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal("any error", res.Error)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PingEventUnmatchedRepo() {
	payload := NewGitHubPayloadBuilder().
		withURL("https://api.github.com/repos/equinor/repo-4/hooks/12345678").
		BuildPingEventPayload()

	s.apiServer.EXPECT().ShowApplications("token", "git@github.com:equinor/repo-4.git").Return(nil, nil).Times(1)

	sut := NewWebHookHandler("token", s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("X-GitHub-Event", "ping")
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal(unmatchedRepoMessage, res.Error)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PingEventMultipleRepos() {
	payload := NewGitHubPayloadBuilder().
		withURL("https://api.github.com/repos/equinor/repo-4/hooks/12345678").
		BuildPingEventPayload()

	s.apiServer.EXPECT().ShowApplications("token", "git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{{}, {}}, nil).Times(1)

	sut := NewWebHookHandler("token", s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("X-GitHub-Event", "ping")
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal(multipleMatchingReposMessage, res.Error)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PingEventGetApplicationReturnsError() {
	commitID := "4faca8595c5283a9d0f17a623b9255a0d9866a2e"
	appName := "appname"
	payload := NewGitHubPayloadBuilder().
		withRef("refs/heads/master").
		withAfter(commitID).
		withURL("https://api.github.com/repos/equinor/repo-1/hooks/12345678").
		BuildPingEventPayload()

	appSummary := models.ApplicationSummary{Name: appName}
	s.apiServer.EXPECT().ShowApplications("token", "git@github.com:equinor/repo-1.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication("token", appName).Return(nil, errors.New("any error")).Times(1)

	sut := NewWebHookHandler("token", s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("X-GitHub-Event", "ping")
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal("any error", res.Error)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PingEventIncorrectSecret() {
	appName := "appname"
	payload := NewGitHubPayloadBuilder().
		withURL("https://api.github.com/repos/equinor/repo-4/hooks/12345678").
		BuildPingEventPayload()
	appSummary := models.ApplicationSummary{Name: appName}
	appDetail := models.NewApplicationBuilder().WithName(appName).WithSharedSecret("sharedsecret").Build()
	s.apiServer.EXPECT().ShowApplications("token", "git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication("token", appName).Return(appDetail, nil).Times(1)

	sut := NewWebHookHandler("token", s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("X-GitHub-Event", "ping")
	req.Header.Add("X-Hub-Signature-256", s.computeSignature([]byte("incorrectsecret"), payload))
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal(webhookIncorrectConfiguration(appName, errors.New(payloadSignatureMismatchMessage)), res.Error)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PingEventWithCorrectSecret() {
	commitID := "4faca8595c5283a9d0f17a623b9255a0d9866a2e"
	appName := "appname"
	payload := NewGitHubPayloadBuilder().
		withRef("refs/heads/master").
		withAfter(commitID).
		withURL("https://api.github.com/repos/equinor/repo-1/hooks/12345678").
		BuildPingEventPayload()

	appSummary := models.ApplicationSummary{Name: appName}
	appDetail := models.NewApplicationBuilder().WithName(appName).WithSharedSecret("sharedsecret").Build()
	s.apiServer.EXPECT().ShowApplications("token", "git@github.com:equinor/repo-1.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication("token", appName).Return(appDetail, nil).Times(1)

	sut := NewWebHookHandler("token", s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("X-GitHub-Event", "ping")
	req.Header.Add("X-Hub-Signature-256", s.computeSignature([]byte("sharedsecret"), payload))
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusOK, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal(webhookCorrectConfiguration(appName), res.Message)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PushEventShowApplicationsReturnsError() {
	payload := NewGitHubPayloadBuilder().
		withRef("refs/heads/master").
		withURL("git@github.com:equinor/repo-4.git").
		BuildPushEventPayload()

	s.apiServer.EXPECT().ShowApplications("token", "git@github.com:equinor/repo-4.git").Return(nil, errors.New("any error")).Times(1)

	sut := NewWebHookHandler("token", s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("X-GitHub-Event", "push")
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal("any error", res.Error)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PushEventUnmatchedRepo() {
	payload := NewGitHubPayloadBuilder().
		withRef("refs/heads/master").
		withURL("git@github.com:equinor/repo-4.git").
		BuildPushEventPayload()

	s.apiServer.EXPECT().ShowApplications("token", "git@github.com:equinor/repo-4.git").Return(nil, nil).Times(1)

	sut := NewWebHookHandler("token", s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("X-GitHub-Event", "push")
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal(unmatchedRepoMessage, res.Error)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PushEventMultipleRepos() {
	payload := NewGitHubPayloadBuilder().
		withRef("refs/heads/master").
		withURL("git@github.com:equinor/repo-4.git").
		BuildPushEventPayload()

	s.apiServer.EXPECT().ShowApplications("token", "git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{{}, {}}, nil).Times(1)

	sut := NewWebHookHandler("token", s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("X-GitHub-Event", "push")
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal(multipleMatchingReposMessage, res.Error)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PushEventIncorrectSecret() {
	appName := "appname"
	payload := NewGitHubPayloadBuilder().
		withRef("refs/heads/master").
		withURL("git@github.com:equinor/repo-4.git").
		BuildPushEventPayload()
	appSummary := models.ApplicationSummary{Name: appName}
	appDetail := models.NewApplicationBuilder().WithName(appName).WithSharedSecret("sharedsecret").Build()
	s.apiServer.EXPECT().ShowApplications("token", "git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication("token", appName).Return(appDetail, nil).Times(1)

	sut := NewWebHookHandler("token", s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("X-GitHub-Event", "push")
	req.Header.Add("X-Hub-Signature-256", s.computeSignature([]byte("incorrectsecret"), payload))
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal(webhookIncorrectConfiguration(appName, errors.New(payloadSignatureMismatchMessage)), res.Error)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PushEventGetApplicationReturnsError() {
	appName := "appname"
	commitID := "4faca8595c5283a9d0f17a623b9255a0d9866a2e"
	payload := NewGitHubPayloadBuilder().
		withAfter(commitID).
		withRef("refs/heads/master").
		withURL("git@github.com:equinor/repo-4.git").
		BuildPushEventPayload()
	appSummary := models.ApplicationSummary{Name: appName}
	s.apiServer.EXPECT().ShowApplications("token", "git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication("token", appName).Return(nil, errors.New("any error")).Times(1)

	sut := NewWebHookHandler("token", s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("X-GitHub-Event", "push")
	req.Header.Add("X-Hub-Signature-256", s.computeSignature([]byte("sharedsecret"), payload))
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal("any error", res.Error)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PushEventTriggerPipelineReturnsError() {
	appName := "appname"
	commitID := "4faca8595c5283a9d0f17a623b9255a0d9866a2e"
	payload := NewGitHubPayloadBuilder().
		withAfter(commitID).
		withRef("refs/heads/master").
		withURL("git@github.com:equinor/repo-4.git").
		BuildPushEventPayload()
	appSummary := models.ApplicationSummary{Name: appName}
	appDetail := models.NewApplicationBuilder().WithName(appName).WithSharedSecret("sharedsecret").Build()
	apiError := errors.New("any error")
	s.apiServer.EXPECT().ShowApplications("token", "git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication("token", appName).Return(appDetail, nil).Times(1)
	s.apiServer.EXPECT().TriggerPipeline("token", appName, "master", commitID, "").Return(nil, apiError).Times(1)

	sut := NewWebHookHandler("token", s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("X-GitHub-Event", "push")
	req.Header.Add("X-Hub-Signature-256", s.computeSignature([]byte("sharedsecret"), payload))
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal(triggerPipelineErrorMessage(appName, apiError), res.Error)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PushEventCorrectSecret() {
	appName := "appname"
	commitID := "4faca8595c5283a9d0f17a623b9255a0d9866a2e"
	payload := NewGitHubPayloadBuilder().
		withAfter(commitID).
		withRef("refs/heads/master").
		withURL("git@github.com:equinor/repo-4.git").
		BuildPushEventPayload()
	appSummary := models.ApplicationSummary{Name: appName}
	appDetail := models.NewApplicationBuilder().WithName(appName).WithSharedSecret("sharedsecret").Build()
	jobSummary := models.JobSummary{Name: "jobname", AppName: "jobappname", Branch: "jobbranchname", CommitID: "jobcommitID", TriggeredBy: "anyuser"}
	s.apiServer.EXPECT().ShowApplications("token", "git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication("token", appName).Return(appDetail, nil).Times(1)
	s.apiServer.EXPECT().TriggerPipeline("token", appName, "master", commitID, "").Return(&jobSummary, nil).Times(1)

	sut := NewWebHookHandler("token", s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("X-GitHub-Event", "push")
	req.Header.Add("X-Hub-Signature-256", s.computeSignature([]byte("sharedsecret"), payload))
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusOK, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal(jobCreatedMessage(jobSummary.Name, jobSummary.AppName, jobSummary.Branch, jobSummary.CommitID), res.Message)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PushEventWithRefDeleted() {
	ref := "refs/heads/master"
	payload := NewGitHubPayloadBuilder().
		withDeleted(true).
		withRef(ref).
		withURL("git@github.com:equinor/repo-4.git").
		BuildPushEventPayload()

	sut := NewWebHookHandler("token", s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("X-GitHub-Event", "push")
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusAccepted, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal(refDeletionPushEventUnsupportedMessage(ref), res.Message)
	s.ctrl.Finish()
}

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

func TestSHA256MAC_CorrectlyEncrypted(t *testing.T) {
	key := []byte("Any shared secret")
	message := []byte("Any message body\n")
	expected := "sha256=be49b65412385a9181ed2e5edfb9daec2d4637cb286973a832b1913feff91ec1"
	actual := SHA256HMAC(key, message)

	assert.Equal(t, expected, actual, "SHA256HMAC - Incorrect encryption")
}

type response struct {
	Message string `json:"message"`
	Error   string `json:"error"`
}

// GitHubPayloadBuilder Handles construction of github payload
type GitHubPayloadBuilder interface {
	withRef(string) GitHubPayloadBuilder
	withAfter(string) GitHubPayloadBuilder
	withURL(string) GitHubPayloadBuilder
	withDeleted(deleted bool) GitHubPayloadBuilder
	BuildPushEventPayload() []byte
	BuildPingEventPayload() []byte
	BuildPullRequestEventPayload() []byte
}

type gitHubPayloadBuilder struct {
	ref     string
	after   string
	url     string
	deleted *bool
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

func (pb *gitHubPayloadBuilder) withDeleted(deleted bool) GitHubPayloadBuilder {
	pb.deleted = &deleted
	return pb
}

func (pb *gitHubPayloadBuilder) BuildPushEventPayload() []byte {
	type repo struct {
		SSHUrl string `json:"ssh_url"`
	}
	type pushEvent struct {
		Ref     string `json:"ref"`
		After   string `json:"after"`
		Deleted *bool  `json:"deleted,omitempty"`
		Repo    repo   `json:"repository"`
	}

	event := pushEvent{Ref: pb.ref, After: pb.after, Deleted: pb.deleted, Repo: repo{SSHUrl: pb.url}}
	payload, err := json.Marshal(event)
	if err != nil {
		panic("failed to marshal json for test")
	}
	return payload
}

func (pb *gitHubPayloadBuilder) BuildPingEventPayload() []byte {
	type hook struct {
		URL string `json:"url"`
	}
	type pingEvent struct {
		Hook hook `json:"hook"`
	}

	event := pingEvent{Hook: hook{URL: pb.url}}
	payload, err := json.Marshal(event)
	if err != nil {
		panic("failed to marshal json for test")
	}
	return payload
}

func (pb *gitHubPayloadBuilder) BuildPullRequestEventPayload() []byte {
	type repo struct {
		SSHUrl string `json:"ssh_url"`
	}
	type pullRequestEvent struct {
		Repo repo `json:"repository"`
	}

	event := pullRequestEvent{Repo: repo{SSHUrl: pb.url}}
	payload, err := json.Marshal(event)
	if err != nil {
		panic("failed to marshal json for test")
	}
	return payload
}

func strPtr(s string) *string {
	return &s
}
