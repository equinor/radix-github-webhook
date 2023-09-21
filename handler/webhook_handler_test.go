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
	"github.com/google/go-github/v53/github"
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
	sut := NewWebHookHandler(s.apiServer).HandleWebhookEvents()
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

	sut := NewWebHookHandler(s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "pull_request")
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal(unhandledEventTypeMessage("pull_request"), res.Error)
}

func (s *handlerTestSuite) Test_PingEventShowApplicationsReturnError() {
	payload := NewGitHubPayloadBuilder().
		withURL("git@github.com:equinor/repo-4.git").
		BuildPingEventPayload()

	s.apiServer.EXPECT().ShowApplications("git@github.com:equinor/repo-4.git").Return(nil, errors.New("any error")).Times(1)

	sut := NewWebHookHandler(s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
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
		withURL("git@github.com:equinor/repo-4.git").
		BuildPingEventPayload()

	s.apiServer.EXPECT().ShowApplications("git@github.com:equinor/repo-4.git").Return(nil, nil).Times(1)

	sut := NewWebHookHandler(s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
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
		withURL("git@github.com:equinor/repo-4.git").
		BuildPingEventPayload()

	s.apiServer.EXPECT().ShowApplications("git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{{}, {}}, nil).Times(1)

	sut := NewWebHookHandler(s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "ping")
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal(multipleMatchingReposMessageWithoutAppName, res.Error)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PingEventGetApplicationReturnsError() {
	commitID := "4faca8595c5283a9d0f17a623b9255a0d9866a2e"
	appName := "appname"
	payload := NewGitHubPayloadBuilder().
		withRef("refs/heads/master").
		withAfter(commitID).
		withURL("git@github.com:equinor/repo-1.git").
		BuildPingEventPayload()

	appSummary := models.ApplicationSummary{Name: appName}
	s.apiServer.EXPECT().ShowApplications("git@github.com:equinor/repo-1.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication(appName).Return(nil, errors.New("any error")).Times(1)

	sut := NewWebHookHandler(s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
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
		withURL("git@github.com:equinor/repo-4.git").
		BuildPingEventPayload()
	appSummary := models.ApplicationSummary{Name: appName}
	appDetail := models.NewApplicationBuilder().WithName(appName).WithSharedSecret("sharedsecret").Build()
	s.apiServer.EXPECT().ShowApplications("git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication(appName).Return(appDetail, nil).Times(1)

	sut := NewWebHookHandler(s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "ping")
	req.Header.Add("X-Hub-Signature-256", s.computeSignature([]byte("incorrectsecret"), payload))
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal(webhookIncorrectConfiguration(appName, errors.New("payload signature check failed")), res.Error)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PingEventWithCorrectSecret() {
	commitID := "4faca8595c5283a9d0f17a623b9255a0d9866a2e"
	appName := "appname"
	payload := NewGitHubPayloadBuilder().
		withRef("refs/heads/master").
		withAfter(commitID).
		withURL("git@github.com:equinor/repo-1.git").
		BuildPingEventPayload()

	appSummary := models.ApplicationSummary{Name: appName}
	appDetail := models.NewApplicationBuilder().WithName(appName).WithSharedSecret("sharedsecret").Build()
	s.apiServer.EXPECT().ShowApplications("git@github.com:equinor/repo-1.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication(appName).Return(appDetail, nil).Times(1)

	sut := NewWebHookHandler(s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
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

	s.apiServer.EXPECT().ShowApplications("git@github.com:equinor/repo-4.git").Return(nil, errors.New("any error")).Times(1)

	sut := NewWebHookHandler(s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "push")
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal("any error", res.Error)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PushEventUnmatchedRepo() {
	type expectedAppDetails struct {
		appName string
	}
	scenarios := []struct {
		name             string
		apps             []*models.ApplicationSummary
		url              string
		expectAppDetails []expectedAppDetails
		expectedHttpCode int
		expectedError    string
	}{
		{
			name:             "unmatched repo for multiple apps without appName",
			apps:             []*models.ApplicationSummary{{Name: "appName1"}, {Name: "appName2"}},
			url:              "/",
			expectedHttpCode: http.StatusBadRequest,
			expectedError:    multipleMatchingReposMessageWithoutAppName,
		},
		{
			name:             "unmatched repo for multiple apps by appName",
			apps:             []*models.ApplicationSummary{{Name: "appName1"}, {Name: "appName2"}},
			url:              "/?appName=appName3",
			expectedHttpCode: http.StatusBadRequest,
			expectedError:    unmatchedAppForMultipleMatchingReposMessage,
		},
		{
			name:             "unmatched repo for single apps by appName",
			apps:             []*models.ApplicationSummary{{Name: "appName1"}},
			url:              "/?appName=appName3",
			expectedHttpCode: http.StatusBadRequest,
			expectedError:    unmatchedRepoMessageByAppName,
		},
		{
			name:             "matched repo for single apps by appName",
			apps:             []*models.ApplicationSummary{{Name: "appName1"}},
			url:              "/?appName=appName1",
			expectAppDetails: []expectedAppDetails{{appName: "appName1"}},
			expectedHttpCode: http.StatusOK,
			expectedError:    "",
		},
		{
			name:             "matched repo for multiple apps by appName",
			apps:             []*models.ApplicationSummary{{Name: "appName1"}, {Name: "appName2"}},
			url:              "/?appName=appName2",
			expectAppDetails: []expectedAppDetails{{appName: "appName2"}},
			expectedHttpCode: http.StatusOK,
			expectedError:    "",
		},
	}
	commitID := "4faca8595c5283a9d0f17a623b9255a0d9866a2e"
	payload := NewGitHubPayloadBuilder().
		withRef("refs/heads/master").
		withURL("git@github.com:equinor/repo-4.git").
		withAfter(commitID).
		BuildPushEventPayload()
	const sharedSecret = "sharedsecret"

	for _, scenario := range scenarios {
		s.T().Logf("Test: %s", scenario.name)
		s.w = httptest.NewRecorder()
		s.apiServer.EXPECT().ShowApplications("git@github.com:equinor/repo-4.git").Return(scenario.apps, nil).Times(1)
		for _, expectAppDetail := range scenario.expectAppDetails {
			appDetail := models.NewApplicationBuilder().WithName(expectAppDetail.appName).WithSharedSecret(sharedSecret).Build()
			s.apiServer.EXPECT().GetApplication(expectAppDetail.appName).
				Return(appDetail, nil).
				Times(1)
			jobSummary := models.JobSummary{Name: "jobname", AppName: expectAppDetail.appName, Branch: "master", CommitID: commitID, TriggeredBy: ""}
			s.apiServer.EXPECT().
				TriggerPipeline(expectAppDetail.appName, "master", commitID, "").
				Return(&jobSummary, nil).
				Times(1)
		}
		sut := NewWebHookHandler(s.apiServer).HandleWebhookEvents()
		req, _ := http.NewRequest("POST", scenario.url, bytes.NewReader(payload))
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("X-GitHub-Event", "push")
		req.Header.Add("X-Hub-Signature-256", s.computeSignature([]byte(sharedSecret), payload))
		router.New(sut).ServeHTTP(s.w, req)
		s.Equal(scenario.expectedHttpCode, s.w.Code)
		var res response
		json.Unmarshal(s.w.Body.Bytes(), &res)
		s.Equal(scenario.expectedError, res.Error)
		s.ctrl.Finish()
	}
}

func (s *handlerTestSuite) Test_PushEventMultipleReposWithoutAppName() {
	payload := NewGitHubPayloadBuilder().
		withRef("refs/heads/master").
		withURL("git@github.com:equinor/repo-4.git").
		BuildPushEventPayload()

	s.apiServer.EXPECT().ShowApplications("git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{{}, {}}, nil).Times(1)

	sut := NewWebHookHandler(s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "push")
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal(multipleMatchingReposMessageWithoutAppName, res.Error)
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
	s.apiServer.EXPECT().ShowApplications("git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication(appName).Return(appDetail, nil).Times(1)

	sut := NewWebHookHandler(s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "push")
	req.Header.Add("X-Hub-Signature-256", s.computeSignature([]byte("incorrectsecret"), payload))
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal(webhookIncorrectConfiguration(appName, errors.New("payload signature check failed")), res.Error)
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
	s.apiServer.EXPECT().ShowApplications("git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication(appName).Return(nil, errors.New("any error")).Times(1)

	sut := NewWebHookHandler(s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
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
	appSummary := models.ApplicationSummary{Name: appName}
	appDetail := models.NewApplicationBuilder().WithName(appName).WithSharedSecret("sharedsecret").Build()

	scenarios := []struct {
		name             string
		apiError         error
		expectedHttpCode int
		expectedMessage  string
		expectedError    string
	}{
		{
			name:             "push-event will return 400 on generic error",
			apiError:         errors.New("any error"),
			expectedHttpCode: http.StatusBadRequest,
			expectedMessage:  "",
			expectedError:    createPipelineJobErrorMessage("appname", errors.New("any error")),
		},
		{
			name: "push-event will return 202 when api-server returns Bad Request (400)",
			apiError: &models.Error{
				Message:    "any error",
				Err:        errors.New("any error"),
				StatusCode: 400,
			},
			expectedHttpCode: http.StatusAccepted,
			expectedMessage:  createPipelineJobErrorMessage("appname", errors.New("any error")),
			expectedError:    "",
		},
		{
			name: "push-event will return 400 when api-server returns status code > 400",
			apiError: &models.Error{
				Message:    "any error",
				Err:        errors.New("any error"),
				StatusCode: 404,
			},
			expectedHttpCode: http.StatusBadRequest,
			expectedMessage:  "",
			expectedError:    createPipelineJobErrorMessage("appname", errors.New("any error")),
		},
		{
			name: "push-event will return 400 when api-server returns status code == 500",
			apiError: &models.Error{
				Message:    "any error",
				Err:        errors.New("any error"),
				StatusCode: 500,
			},
			expectedHttpCode: http.StatusBadRequest,
			expectedMessage:  "",
			expectedError:    createPipelineJobErrorMessage("appname", errors.New("any error")),
		},
	}

	for _, scenario := range scenarios {
		s.T().Logf("Test: %s", scenario.name)
		s.w = httptest.NewRecorder()

		payload := NewGitHubPayloadBuilder().
			withAfter(commitID).
			withRef("refs/heads/master").
			withURL("git@github.com:equinor/repo-4.git").
			BuildPushEventPayload()

		s.apiServer.EXPECT().ShowApplications("git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
		s.apiServer.EXPECT().GetApplication(appName).Return(appDetail, nil).Times(1)
		s.apiServer.EXPECT().TriggerPipeline(appName, "master", commitID, "").Return(nil, scenario.apiError).Times(1)

		sut := NewWebHookHandler(s.apiServer).HandleWebhookEvents()
		req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("X-GitHub-Event", "push")
		req.Header.Add("X-Hub-Signature-256", s.computeSignature([]byte("sharedsecret"), payload))

		router.New(sut).ServeHTTP(s.w, req)

		var res response
		json.Unmarshal(s.w.Body.Bytes(), &res)
		s.Equal(scenario.expectedHttpCode, s.w.Code)
		s.Equal(scenario.expectedError, res.Error)
		s.Equal(scenario.expectedMessage, res.Message)
		s.ctrl.Finish()
	}
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
	s.apiServer.EXPECT().ShowApplications("git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication(appName).Return(appDetail, nil).Times(1)
	s.apiServer.EXPECT().TriggerPipeline(appName, "master", commitID, "").Return(&jobSummary, nil).Times(1)

	sut := NewWebHookHandler(s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "push")
	req.Header.Add("X-Hub-Signature-256", s.computeSignature([]byte("sharedsecret"), payload))
	router.New(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusOK, s.w.Code)
	var res response
	json.Unmarshal(s.w.Body.Bytes(), &res)
	s.Equal(createPipelineJobSuccessMessage(jobSummary.Name, jobSummary.AppName, jobSummary.Branch, jobSummary.CommitID), res.Message)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PushEventWithRefDeleted() {
	ref := "refs/heads/master"
	payload := NewGitHubPayloadBuilder().
		withDeleted(true).
		withRef(ref).
		withURL("git@github.com:equinor/repo-4.git").
		BuildPushEventPayload()

	sut := NewWebHookHandler(s.apiServer).HandleWebhookEvents()
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
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
	type repo struct {
		SSHUrl string `json:"ssh_url"`
	}
	type pingEvent struct {
		Repo repo `json:"repository"`
	}

	event := pingEvent{Repo: repo{SSHUrl: pb.url}}
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
