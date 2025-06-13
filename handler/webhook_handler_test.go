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
	"github.com/google/go-github/v72/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	sut := NewWebHookHandler(s.apiServer)
	req, _ := http.NewRequest("POST", "/", nil)
	router.NewWebhook(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	err := json.Unmarshal(s.w.Body.Bytes(), &res)
	require.NoError(s.T(), err)
	s.Equal(notAGithubEventMessage, res.Error)
}

func (s *handlerTestSuite) Test_UnhandledEventType() {
	payload := NewGitHubPayloadBuilder().
		withURL("git@github.com:equinor/repo-1.git").
		BuildPullRequestEventPayload()

	sut := NewWebHookHandler(s.apiServer)
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "pull_request")
	router.NewWebhook(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	err := json.Unmarshal(s.w.Body.Bytes(), &res)
	require.NoError(s.T(), err)
	s.Equal(unhandledEventTypeMessage("pull_request"), res.Error)
}

func (s *handlerTestSuite) Test_PingEventShowApplicationsReturnError() {
	payload := NewGitHubPayloadBuilder().
		withURL("git@github.com:equinor/repo-4.git").
		BuildPingEventPayload()

	s.apiServer.EXPECT().ShowApplications(gomock.Any(), "git@github.com:equinor/repo-4.git").Return(nil, errors.New("any error")).Times(1)

	sut := NewWebHookHandler(s.apiServer)
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "ping")
	router.NewWebhook(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	err := json.Unmarshal(s.w.Body.Bytes(), &res)
	require.NoError(s.T(), err)
	s.Equal("any error", res.Error)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PingEventUnmatchedRepo() {
	payload := NewGitHubPayloadBuilder().
		withURL("git@github.com:equinor/repo-4.git").
		BuildPingEventPayload()

	s.apiServer.EXPECT().ShowApplications(gomock.Any(), "git@github.com:equinor/repo-4.git").Return(nil, nil).Times(1)

	sut := NewWebHookHandler(s.apiServer)
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "ping")
	router.NewWebhook(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	err := json.Unmarshal(s.w.Body.Bytes(), &res)
	require.NoError(s.T(), err)
	s.Equal(unmatchedRepoMessage, res.Error)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PingEventMultipleRepos() {
	payload := NewGitHubPayloadBuilder().
		withURL("git@github.com:equinor/repo-4.git").
		BuildPingEventPayload()

	s.apiServer.EXPECT().ShowApplications(gomock.Any(), "git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{{}, {}}, nil).Times(1)

	sut := NewWebHookHandler(s.apiServer)
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "ping")
	router.NewWebhook(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	err := json.Unmarshal(s.w.Body.Bytes(), &res)
	require.NoError(s.T(), err)
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
	s.apiServer.EXPECT().ShowApplications(gomock.Any(), "git@github.com:equinor/repo-1.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication(gomock.Any(), appName).Return(nil, errors.New("any error")).Times(1)

	sut := NewWebHookHandler(s.apiServer)
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "ping")
	router.NewWebhook(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	err := json.Unmarshal(s.w.Body.Bytes(), &res)
	require.NoError(s.T(), err)
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
	s.apiServer.EXPECT().ShowApplications(gomock.Any(), "git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication(gomock.Any(), appName).Return(appDetail, nil).Times(1)

	sut := NewWebHookHandler(s.apiServer)
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "ping")
	req.Header.Add("X-Hub-Signature-256", s.computeSignature([]byte("incorrectsecret"), payload))
	router.NewWebhook(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	err := json.Unmarshal(s.w.Body.Bytes(), &res)
	require.NoError(s.T(), err)
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
	s.apiServer.EXPECT().ShowApplications(gomock.Any(), "git@github.com:equinor/repo-1.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication(gomock.Any(), appName).Return(appDetail, nil).Times(1)

	sut := NewWebHookHandler(s.apiServer)
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "ping")
	req.Header.Add("X-Hub-Signature-256", s.computeSignature([]byte("sharedsecret"), payload))
	router.NewWebhook(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusOK, s.w.Code)
	var res response
	err := json.Unmarshal(s.w.Body.Bytes(), &res)
	require.NoError(s.T(), err)
	s.Equal(webhookCorrectConfiguration(appName), res.Message)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PushEventShowApplicationsReturnsError() {
	payload := NewGitHubPayloadBuilder().
		withRef("refs/heads/master").
		withURL("git@github.com:equinor/repo-4.git").
		BuildPushEventPayload()

	s.apiServer.EXPECT().ShowApplications(gomock.Any(), "git@github.com:equinor/repo-4.git").Return(nil, errors.New("any error")).Times(1)

	sut := NewWebHookHandler(s.apiServer)
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "push")
	router.NewWebhook(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	err := json.Unmarshal(s.w.Body.Bytes(), &res)
	require.NoError(s.T(), err)
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
		s.apiServer.EXPECT().ShowApplications(gomock.Any(), "git@github.com:equinor/repo-4.git").Return(scenario.apps, nil).Times(1)
		for _, expectAppDetail := range scenario.expectAppDetails {
			appDetail := models.NewApplicationBuilder().WithName(expectAppDetail.appName).WithSharedSecret(sharedSecret).Build()
			s.apiServer.EXPECT().GetApplication(gomock.Any(), expectAppDetail.appName).
				Return(appDetail, nil).
				Times(1)
			jobSummary := models.JobSummary{Name: "jobname", AppName: expectAppDetail.appName, Branch: "master", CommitID: commitID, TriggeredBy: ""}
			s.apiServer.EXPECT().
				TriggerPipeline(gomock.Any(), expectAppDetail.appName, "master", "branch", commitID, "").
				Return(&jobSummary, nil).
				Times(1)
		}
		sut := NewWebHookHandler(s.apiServer)
		req, _ := http.NewRequest("POST", scenario.url, bytes.NewReader(payload))
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("X-GitHub-Event", "push")
		req.Header.Add("X-Hub-Signature-256", s.computeSignature([]byte(sharedSecret), payload))
		router.NewWebhook(sut).ServeHTTP(s.w, req)
		s.Equal(scenario.expectedHttpCode, s.w.Code)
		var res response
		err := json.Unmarshal(s.w.Body.Bytes(), &res)
		require.NoError(s.T(), err)
		s.Equal(scenario.expectedError, res.Error)
		s.ctrl.Finish()
	}
}

func (s *handlerTestSuite) Test_PushEventMultipleReposWithoutAppName() {
	payload := NewGitHubPayloadBuilder().
		withRef("refs/heads/master").
		withURL("git@github.com:equinor/repo-4.git").
		BuildPushEventPayload()

	s.apiServer.EXPECT().ShowApplications(gomock.Any(), "git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{{}, {}}, nil).Times(1)

	sut := NewWebHookHandler(s.apiServer)
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "push")
	router.NewWebhook(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	err := json.Unmarshal(s.w.Body.Bytes(), &res)
	require.NoError(s.T(), err)
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
	s.apiServer.EXPECT().ShowApplications(gomock.Any(), "git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication(gomock.Any(), appName).Return(appDetail, nil).Times(1)

	sut := NewWebHookHandler(s.apiServer)
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "push")
	req.Header.Add("X-Hub-Signature-256", s.computeSignature([]byte("incorrectsecret"), payload))
	router.NewWebhook(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	err := json.Unmarshal(s.w.Body.Bytes(), &res)
	require.NoError(s.T(), err)
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
	s.apiServer.EXPECT().ShowApplications(gomock.Any(), "git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication(gomock.Any(), appName).Return(nil, errors.New("any error")).Times(1)

	sut := NewWebHookHandler(s.apiServer)
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "push")
	req.Header.Add("X-Hub-Signature-256", s.computeSignature([]byte("sharedsecret"), payload))
	router.NewWebhook(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusBadRequest, s.w.Code)
	var res response
	err := json.Unmarshal(s.w.Body.Bytes(), &res)
	require.NoError(s.T(), err)
	s.Equal("any error", res.Error)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PushEventTriggerPipelineReturnsError() {
	appName := "appname"
	commitID := "4faca8595c5283a9d0f17a623b9255a0d9866a2e"
	appSummary := models.ApplicationSummary{Name: appName}
	appDetail := models.NewApplicationBuilder().WithName(appName).WithSharedSecret("sharedsecret").Build()
	anyError := errors.New("any error")

	scenarios := []struct {
		name             string
		apiError         error
		expectedHttpCode int
		expectedMessage  string
		expectedError    string
	}{
		{
			name:             "push-event will return 400 on generic error",
			apiError:         anyError,
			expectedHttpCode: http.StatusBadRequest,
			expectedMessage:  "",
			expectedError:    createPipelineJobErrorMessage(appName, anyError),
		},
		{
			name: "push-event will return 202 when api-server returns Bad Request (400)",
			apiError: &radix.ApiError{
				Message: anyError.Error(),
				Code:    400,
			},
			expectedHttpCode: http.StatusAccepted,
			expectedMessage:  createPipelineJobErrorMessage(appName, anyError),
			expectedError:    "",
		},
		{
			name: "push-event will return 400 when api-server returns status code > 400",
			apiError: &radix.ApiError{
				Message: anyError.Error(),
				Code:    404,
			},
			expectedHttpCode: http.StatusBadRequest,
			expectedMessage:  "",
			expectedError:    createPipelineJobErrorMessage(appName, anyError),
		},
		{
			name: "push-event will return 400 when api-server returns status code == 500",
			apiError: &radix.ApiError{
				Message: anyError.Error(),
				Code:    500,
			},
			expectedHttpCode: http.StatusBadRequest,
			expectedMessage:  "",
			expectedError:    createPipelineJobErrorMessage(appName, anyError),
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

		s.apiServer.EXPECT().ShowApplications(gomock.Any(), "git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
		s.apiServer.EXPECT().GetApplication(gomock.Any(), appName).Return(appDetail, nil).Times(1)
		s.apiServer.EXPECT().TriggerPipeline(gomock.Any(), appName, "master", "branch", commitID, "").Return(nil, scenario.apiError).Times(1)

		sut := NewWebHookHandler(s.apiServer)
		req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("X-GitHub-Event", "push")
		req.Header.Add("X-Hub-Signature-256", s.computeSignature([]byte("sharedsecret"), payload))

		router.NewWebhook(sut).ServeHTTP(s.w, req)

		var res response
		err := json.Unmarshal(s.w.Body.Bytes(), &res)
		require.NoError(s.T(), err)
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
	s.apiServer.EXPECT().ShowApplications(gomock.Any(), "git@github.com:equinor/repo-4.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication(gomock.Any(), appName).Return(appDetail, nil).Times(1)
	s.apiServer.EXPECT().TriggerPipeline(gomock.Any(), appName, "master", "branch", commitID, "").Return(&jobSummary, nil).Times(1)

	sut := NewWebHookHandler(s.apiServer)
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "push")
	req.Header.Add("X-Hub-Signature-256", s.computeSignature([]byte("sharedsecret"), payload))
	router.NewWebhook(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusOK, s.w.Code)
	var res response
	err := json.Unmarshal(s.w.Body.Bytes(), &res)
	require.NoError(s.T(), err)
	s.Equal(createPipelineJobSuccessMessage(jobSummary.Name, jobSummary.AppName, jobSummary.Branch, "branch", jobSummary.CommitID), res.Message)
	s.ctrl.Finish()
}

func (s *handlerTestSuite) Test_PushEventWithRefDeleted() {
	ref := "refs/heads/master"
	payload := NewGitHubPayloadBuilder().
		withDeleted(true).
		withRef(ref).
		withURL("git@github.com:equinor/repo-4.git").
		BuildPushEventPayload()

	sut := NewWebHookHandler(s.apiServer)
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "push")
	router.NewWebhook(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusAccepted, s.w.Code)
	var res response
	err := json.Unmarshal(s.w.Body.Bytes(), &res)
	require.NoError(s.T(), err)
	s.Equal(refDeletionPushEventUnsupportedMessage(ref), res.Message)
	s.ctrl.Finish()
}

func Test_GetBranch_RemovesRefsHead(t *testing.T) {
	gitRef, gitRefType := getGitRefWithType(&github.PushEvent{Ref: strPtr("refs/tags/v1.0.2")})
	assert.Equal(t, "v1.0.2", gitRef)
	assert.Equal(t, "tag", gitRefType)
	gitRef, gitRefType = getGitRefWithType(&github.PushEvent{Ref: strPtr("refs/heads/master")})
	assert.Equal(t, "master", gitRef)
	assert.Equal(t, "branch", gitRefType)
	gitRef, gitRefType = getGitRefWithType(&github.PushEvent{Ref: strPtr("refs/heads/feature/RA-326-TestBranch")})
	assert.Equal(t, "feature/RA-326-TestBranch", gitRef)
	assert.Equal(t, "branch", gitRefType)
	gitRef, gitRefType = getGitRefWithType(&github.PushEvent{Ref: strPtr("refs/heads/hotfix/api/refs/heads/fix1")})
	assert.Equal(t, "hotfix/api/refs/heads/fix1", gitRef)
	assert.Equal(t, "branch", gitRefType)
}

func (s *handlerTestSuite) Test_PushEventWithAnnotatedTag() {
	appName := "appname"
	headCommitID := "4faca8595c5283a9d0f17a623b9255a0d9866a2e"
	afterID := "e0ebacaa-fa4b-49aa-b184-67064e8fcd4c"
	tag := "v1"
	payload := NewGitHubPayloadBuilder().
		withRef("refs/tags/" + tag).
		withAfter(afterID).
		withHeadCommitID(headCommitID).
		withURL("git@github.com:equinor/repo-1.git").
		BuildPushEventPayload()

	appSummary := models.ApplicationSummary{Name: appName}
	appDetail := models.NewApplicationBuilder().WithName(appName).WithSharedSecret("sharedsecret").Build()
	jobSummary := models.JobSummary{Name: "jobname", AppName: "jobappname", Branch: "jobbranchname", CommitID: headCommitID, TriggeredBy: "anyuser"}
	s.apiServer.EXPECT().ShowApplications(gomock.Any(), "git@github.com:equinor/repo-1.git").Return([]*models.ApplicationSummary{&appSummary}, nil).Times(1)
	s.apiServer.EXPECT().GetApplication(gomock.Any(), appName).Return(appDetail, nil).Times(1)
	s.apiServer.EXPECT().TriggerPipeline(gomock.Any(), appName, tag, "tag", headCommitID, "").Return(&jobSummary, nil).Times(1)

	sut := NewWebHookHandler(s.apiServer)
	req, _ := http.NewRequest("POST", "/", bytes.NewReader(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-GitHub-Event", "push")
	req.Header.Add("X-Hub-Signature-256", s.computeSignature([]byte("sharedsecret"), payload))
	router.NewWebhook(sut).ServeHTTP(s.w, req)
	s.Equal(http.StatusOK, s.w.Code)
	var res response
	err := json.Unmarshal(s.w.Body.Bytes(), &res)
	require.NoError(s.T(), err)
	s.Equal(createPipelineJobSuccessMessage(jobSummary.Name, jobSummary.AppName, jobSummary.Branch, "branch", jobSummary.CommitID), res.Message)
	s.ctrl.Finish()
}

type response struct {
	Message string `json:"message"`
	Error   string `json:"error"`
}

// GitHubPayloadBuilder Handles construction of GitHub payload
type GitHubPayloadBuilder interface {
	withRef(refs string) GitHubPayloadBuilder
	withAfter(after string) GitHubPayloadBuilder
	withURL(url string) GitHubPayloadBuilder
	withDeleted(deleted bool) GitHubPayloadBuilder
	withHeadCommitID(commitID string) GitHubPayloadBuilder
	BuildPushEventPayload() []byte
	BuildPingEventPayload() []byte
	BuildPullRequestEventPayload() []byte
}

type gitHubPayloadBuilder struct {
	ref          string
	after        string
	url          string
	deleted      *bool
	headCommitID string
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

func (pb *gitHubPayloadBuilder) withHeadCommitID(commitID string) GitHubPayloadBuilder {
	pb.headCommitID = commitID
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
	type headCommit struct {
		ID string `json:"id"`
	}
	type pushEvent struct {
		Ref        string     `json:"ref"`
		After      string     `json:"after"`
		Deleted    *bool      `json:"deleted,omitempty"`
		Repo       repo       `json:"repository"`
		HeadCommit headCommit `json:"head_commit"`
	}

	event := pushEvent{Ref: pb.ref, After: pb.after, Deleted: pb.deleted, Repo: repo{SSHUrl: pb.url}, HeadCommit: headCommit{ID: pb.headCommitID}}
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
