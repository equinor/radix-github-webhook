package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/equinor/radix-github-webhook/metrics"
	"github.com/equinor/radix-github-webhook/models"
	"github.com/equinor/radix-github-webhook/radix"
	"github.com/google/go-github/v50/github"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	hubSignatureHeader    = "X-Hub-Signature-256"
	appNameQueryParameter = "appName"
)

var (
	notAGithubEventMessage                      = "Not a Github event"
	unhandledEventTypeMessage                   = func(eventType string) string { return fmt.Sprintf("Unhandled event type %s", eventType) }
	unmatchedRepoMessage                        = "Unable to match repo with any Radix application"
	multipleMatchingReposMessageWithoutAppName  = "Unable to match repo with unique Radix application without appName request parameter"
	unmatchedRepoMessageByAppName               = "Unable to match repo with unique Radix application by appName request parameter"
	unmatchedAppForMultipleMatchingReposMessage = "Unable to match repo with multiple Radix applications by appName request parameter"
	payloadSignatureMismatchMessage             = "Payload signature check failed"
	webhookIncorrectConfiguration               = func(appName string, err error) string {
		return fmt.Sprintf("Webhook is not configured correctly for Radix application %s. Error was: %s", appName, err)
	}
	webhookCorrectConfiguration = func(appName string) string {
		return fmt.Sprintf("Webhook is configured correctly with for Radix application %s", appName)
	}
	refDeletionPushEventUnsupportedMessage = func(refName string) string {
		return fmt.Sprintf("Deletion of %s not supported, aborting", refName)
	}
	createPipelineJobErrorMessage = func(appName string, apiError error) string {
		return fmt.Sprintf("Failed to create pipeline job for Radix application %s. Error was: %s", appName, apiError)
	}
	createPipelineJobSuccessMessage = func(jobName, appName, branch, commitID string) string {
		return fmt.Sprintf("Pipeline job %s created for Radix application %s on branch %s for commit %s", jobName, appName, branch, commitID)
	}
)

// WebhookResponse The response structure
type WebhookResponse struct {
	Ok      bool   `json:"ok"`
	Event   string `json:"event"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

// WebHookHandler Instance
type WebHookHandler struct {
	ServiceAccountBearerToken string
	apiServer                 radix.APIServer
}

// NewWebHookHandler Constructor
func NewWebHookHandler(token string, apiServer radix.APIServer) *WebHookHandler {
	return &WebHookHandler{
		token,
		apiServer,
	}
}

// HandleWebhookEvents Main handler of events
func (wh *WebHookHandler) HandleWebhookEvents() http.Handler {
	return http.HandlerFunc(wh.handleEvent)
}

func (wh *WebHookHandler) handleEvent(w http.ResponseWriter, req *http.Request) {
	// Increase metrics counter
	metrics.IncreaseAllCounter()

	event := req.Header.Get("x-github-event")

	_fail := func(statusCode int, err error) {
		fail(w, event, statusCode, err)
	}

	_succeedWithMessage := func(statusCode int, message string) {
		log.Infof("Success: %s", message)
		succeedWithMessage(w, event, statusCode, message)
	}

	if len(strings.TrimSpace(event)) == 0 {
		metrics.IncreaseNotGithubEventCounter()
		_fail(http.StatusBadRequest, errors.New(notAGithubEventMessage))
		return
	}

	// Need to parse webhook before validation because the secret is taken from the matching repo
	body, err := io.ReadAll(req.Body)
	if err != nil {
		metrics.IncreaseFailedParsingCounter()
		_fail(http.StatusBadRequest, fmt.Errorf("could not parse webhook: err=%s ", err))
		return
	}

	payload, err := github.ParseWebHook(github.WebHookType(req), body)
	if err != nil {
		metrics.IncreaseFailedParsingCounter()
		_fail(http.StatusBadRequest, fmt.Errorf("could not parse webhook: err=%s ", err))
		return
	}

	switch e := payload.(type) {
	case *github.PushEvent:
		branch := getBranch(e)
		commitID := *e.After
		sshURL := e.Repo.GetSSHURL()
		triggeredBy := getPushTriggeredBy(e)

		metrics.IncreasePushGithubEventTypeCounter(sshURL, branch, commitID)

		if isPushEventForRefDeletion(e) {
			_succeedWithMessage(http.StatusAccepted, refDeletionPushEventUnsupportedMessage(*e.Ref))
			return
		}

		applicationSummary, err := wh.getApplication(req, body, sshURL)
		if err != nil {
			metrics.IncreaseFailedCloneURLValidationCounter(sshURL)
			_fail(http.StatusBadRequest, err)
			return
		}

		metrics.IncreasePushGithubEventTypeTriggerPipelineCounter(sshURL, branch, commitID, applicationSummary.Name)
		jobSummary, err := wh.apiServer.TriggerPipeline(wh.ServiceAccountBearerToken, applicationSummary.Name, branch, commitID, triggeredBy)
		if err != nil {
			metrics.IncreasePushGithubEventTypeFailedTriggerPipelineCounter(sshURL, branch, commitID)
			_fail(http.StatusBadRequest, errors.New(createPipelineJobErrorMessage(applicationSummary.Name, err)))
			return
		}

		_succeedWithMessage(http.StatusOK, createPipelineJobSuccessMessage(jobSummary.Name, jobSummary.AppName, jobSummary.Branch, jobSummary.CommitID))

	case *github.PingEvent:
		// sshURL := getSSHUrlFromPingURL(*e.Hook.URL)
		sshURL := e.Repo.GetSSHURL()
		metrics.IncreasePingGithubEventTypeCounter(sshURL)

		applicationSummary, err := wh.getApplication(req, body, sshURL)
		if err != nil {
			metrics.IncreaseFailedCloneURLValidationCounter(sshURL)
			_fail(http.StatusBadRequest, err)
			return
		}

		_succeedWithMessage(http.StatusOK, webhookCorrectConfiguration(applicationSummary.Name))

	default:
		metrics.IncreaseUnsupportedGithubEventTypeCounter()
		_fail(http.StatusBadRequest, errors.New(unhandledEventTypeMessage(github.WebHookType(req))))
		return
	}
}

func (wh *WebHookHandler) getApplication(req *http.Request, body []byte, sshURL string) (*models.ApplicationSummary, error) {
	applicationSummary, err := wh.getApplicationSummary(req, sshURL)
	if err != nil {
		return nil, err
	}
	application, err := wh.apiServer.GetApplication(wh.ServiceAccountBearerToken, applicationSummary.Name)
	if err != nil {
		return nil, err
	}

	err = isValidSecret(req, body, *application.Registration.SharedSecret)
	if err != nil {
		return nil, errors.New(webhookIncorrectConfiguration(application.Registration.Name, err))
	}
	return applicationSummary, nil
}

func (wh *WebHookHandler) getApplicationSummary(req *http.Request, sshURL string) (*models.ApplicationSummary, error) {
	applicationSummaries, err := wh.apiServer.ShowApplications(wh.ServiceAccountBearerToken, sshURL)
	if err != nil {
		return nil, err
	}
	if len(applicationSummaries) == 0 {
		return nil, errors.New(unmatchedRepoMessage)
	}
	appName := req.URL.Query().Get(appNameQueryParameter)
	if len(applicationSummaries) == 1 {
		return getApplicationSummaryForSingleRegisteredApplication(appName, applicationSummaries)
	}
	return getApplicationSummaryForMultipleRegisteredApplications(appName, applicationSummaries)
}

func getApplicationSummaryForSingleRegisteredApplication(appName string, applicationSummaries []*models.ApplicationSummary) (*models.ApplicationSummary, error) {
	if len(appName) == 0 || strings.EqualFold(applicationSummaries[0].Name, appName) {
		return applicationSummaries[0], nil
	}
	return nil, errors.New(unmatchedRepoMessageByAppName)
}

func getApplicationSummaryForMultipleRegisteredApplications(appName string, applicationSummaries []*models.ApplicationSummary) (*models.ApplicationSummary, error) {
	if len(appName) == 0 {
		return nil, errors.New(multipleMatchingReposMessageWithoutAppName)
	}
	for _, applicationSummary := range applicationSummaries {
		if strings.EqualFold(applicationSummary.Name, appName) {
			return applicationSummary, nil
		}
	}
	return nil, errors.New(unmatchedAppForMultipleMatchingReposMessage)
}

func getPushTriggeredBy(pushEvent *github.PushEvent) string {
	sender := pushEvent.GetSender()
	if sender != nil {
		return sender.GetLogin()
	}

	headCommit := pushEvent.GetHeadCommit()
	if headCommit != nil {
		author := headCommit.GetAuthor()
		if author != nil {
			return author.GetLogin()
		}
	}

	pusher := pushEvent.GetPusher()
	if pusher != nil {
		return pusher.GetLogin()
	}
	return ""
}

func getBranch(pushEvent *github.PushEvent) string {
	// Remove refs/heads from ref
	ref := strings.Split(*pushEvent.Ref, "/")
	return strings.Join(ref[2:], "/")
}

func isPushEventForRefDeletion(pushEvent *github.PushEvent) bool {
	// Deleted refers to the Ref in the Push event. See https://docs.github.com/en/developers/webhooks-and-events/webhooks/webhook-events-and-payloads#push
	if pushEvent.Deleted != nil {
		return *pushEvent.Deleted
	}
	return false
}

func isValidSecret(req *http.Request, body []byte, sharedSecret string) error {
	signature := req.Header.Get(hubSignatureHeader)
	if err := validateSignature(signature, sharedSecret, body); err != nil {
		return err
	}

	return nil
}

func succeedWithMessage(w http.ResponseWriter, event string, statusCode int, message string) {
	w.WriteHeader(statusCode)
	render(w, WebhookResponse{
		Ok:      true,
		Event:   event,
		Message: message,
	})
}

func fail(w http.ResponseWriter, event string, statusCode int, err error) {
	log.Printf("%s\n", err)
	w.WriteHeader(statusCode)
	render(w, WebhookResponse{
		Ok:    false,
		Event: event,
		Error: err.Error(),
	})
}

func render(w http.ResponseWriter, v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(data)
}

//	Taken from brigade pkg/webhook/github.go
//
// validateSignature compares the salted digest in the header with our own computing of the body.
func validateSignature(signature, secretKey string, payload []byte) error {
	sum := SHA256HMAC([]byte(secretKey), payload)
	if subtle.ConstantTimeCompare([]byte(sum), []byte(signature)) != 1 {
		log.Printf("Expected signature does not match to received event signature")
		return errors.New(payloadSignatureMismatchMessage)
	}
	return nil
}

// SHA256HMAC computes the GitHub SHA256 HMAC.
func SHA256HMAC(key, message []byte) string {
	// GitHub creates a SHA256 HMAC, where the key is the GitHub secret and the
	// message is the JSON body.
	digest := hmac.New(sha256.New, key)
	digest.Write(message)
	sum := digest.Sum(nil)
	return fmt.Sprintf("sha256=%x", sum)
}
