package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	"github.com/equinor/radix-github-webhook/metrics"
	"github.com/equinor/radix-github-webhook/models"
	"github.com/equinor/radix-github-webhook/radix"
	"github.com/google/go-github/v45/github"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const hubSignatureHeader = "X-Hub-Signature-256"

var pingRepoPattern = regexp.MustCompile(".*github.com/repos/(.*?)")
var pingHooksPattern = regexp.MustCompile("/hooks/[0-9]*")

var (
	notAGithubEventMessage          = "Not a Github event"
	unhandledEventTypeMessage       = func(eventType string) string { return fmt.Sprintf("Unhandled event type %s", eventType) }
	unmatchedRepoMessage            = "Unable to match repo with any Radix application"
	multipleMatchingReposMessage    = "Unable to match repo with unique Radix application"
	payloadSignatureMismatchMessage = "Payload signature check failed"
	webhookIncorrectConfiguration   = func(appName string, err error) string {
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
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		metrics.IncreaseFailedParsingCounter()
		_fail(http.StatusBadRequest, fmt.Errorf("Could not parse webhook: err=%s ", err))
		return
	}

	payload, err := github.ParseWebHook(github.WebHookType(req), body)
	if err != nil {
		metrics.IncreaseFailedParsingCounter()
		_fail(http.StatusBadRequest, fmt.Errorf("Could not parse webhook: err=%s ", err))
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

		applicationSummaries, _, err := wh.validateCloneURL(req, body, sshURL)
		if err != nil {
			metrics.IncreaseFailedCloneURLValidationCounter(sshURL)
			_fail(http.StatusBadRequest, err)
			return
		}

		var message string
		success := true

		for _, applicationSummary := range applicationSummaries {
			jobSummary, err := wh.apiServer.TriggerPipeline(wh.ServiceAccountBearerToken, applicationSummary.Name, branch, commitID, triggeredBy)

			metrics.IncreasePushGithubEventTypeTriggerPipelineCounter(sshURL, branch, commitID, applicationSummary.Name)
			if err != nil {
				message = appendToMessage(message, createPipelineJobErrorMessage(applicationSummary.Name, err))
				success = false
				continue
			}

			success = true
			message = appendToMessage(message, createPipelineJobSuccessMessage(jobSummary.Name, jobSummary.AppName, jobSummary.Branch, jobSummary.CommitID))
		}

		if !success {
			metrics.IncreasePushGithubEventTypeFailedTriggerPipelineCounter(sshURL, branch, commitID)
			_fail(http.StatusBadRequest, errors.New(message))
			return
		}

		_succeedWithMessage(http.StatusOK, message)

	case *github.PingEvent:
		sshURL := getSSHUrlFromPingURL(*e.Hook.URL)
		metrics.IncreasePingGithubEventTypeCounter(sshURL)

		_, message, err := wh.validateCloneURL(req, body, sshURL)

		if err != nil {
			metrics.IncreaseFailedCloneURLValidationCounter(sshURL)
			_fail(http.StatusBadRequest, err)
			return
		}

		_succeedWithMessage(http.StatusOK, message)

	default:
		metrics.IncreaseUnsupportedGithubEventTypeCounter()
		_fail(http.StatusBadRequest, errors.New(unhandledEventTypeMessage(github.WebHookType(req))))
		return
	}
}

func (wh *WebHookHandler) validateCloneURL(req *http.Request, body []byte, sshURL string) ([]*models.ApplicationSummary, string, error) {
	applicationSummaries, err := wh.apiServer.ShowApplications(wh.ServiceAccountBearerToken, sshURL)
	if err != nil {
		return nil, "", err
	}

	if len(applicationSummaries) < 1 {
		return nil, "", errors.New(unmatchedRepoMessage)
	} else if len(applicationSummaries) > 1 {
		return nil, "", errors.New(multipleMatchingReposMessage)
	}

	var message string
	success := true

	for _, applicationSummary := range applicationSummaries {
		application, err := wh.apiServer.GetApplication(wh.ServiceAccountBearerToken, applicationSummary.Name)
		if err != nil {
			return nil, "", err
		}

		err = isValidSecret(req, body, *application.Registration.SharedSecret)
		if err != nil {
			message = appendToMessage(message, webhookIncorrectConfiguration(application.Registration.Name, err))
			success = false
			continue
		}

		message = appendToMessage(message, webhookCorrectConfiguration(application.Registration.Name))
	}

	if !success {
		return nil, "", errors.New(message)
	}

	return applicationSummaries, message, nil
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
	var deleted bool
	if pushEvent.Deleted != nil {
		deleted = *pushEvent.Deleted
	}
	return deleted
}

func isValidSecret(req *http.Request, body []byte, sharedSecret string) error {
	signature := req.Header.Get(hubSignatureHeader)
	if err := validateSignature(signature, sharedSecret, body); err != nil {
		return err
	}

	return nil
}

func appendToMessage(message, messageToAppend string) string {
	if strings.TrimSpace(message) != "" {
		message += ". "
	}

	message += messageToAppend
	return message
}

func getSSHUrlFromPingURL(pingURL string) string {
	fullName := pingRepoPattern.ReplaceAllString(pingURL, "")
	fullName = pingHooksPattern.ReplaceAllString(fullName, "")
	return fmt.Sprintf("git@github.com:%s.git", fullName)
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

//  Taken from brigade pkg/webhook/github.go
//
// validateSignature compares the salted digest in the header with our own computing of the body.
func validateSignature(signature, secretKey string, payload []byte) error {
	sum := SHA256HMAC([]byte(secretKey), payload)
	if subtle.ConstantTimeCompare([]byte(sum), []byte(signature)) != 1 {
		log.Printf("Expected signature %q (sum), got %q (hub-signature)", sum, signature)
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
