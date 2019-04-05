package handler

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/equinor/radix-github-webhook/metrics"
	"github.com/equinor/radix-github-webhook/models"
	"github.com/google/go-github/github"
	"github.com/pkg/errors"
)

const hubSignatureHeader = "X-Hub-Signature"

var pingRepoPattern = regexp.MustCompile(".*github.com/repos/(.*?)")
var pingHooksPattern = regexp.MustCompile("/hooks/[0-9]*")

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
	apiServer                 APIServer
}

// NewWebHookHandler Constructor
func NewWebHookHandler(token string, apiServer APIServer) *WebHookHandler {
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

	_succeedWithMessage := func(message string) {
		log.Infof("Success: %s", message)
		succeedWithMessage(w, event, message)
	}

	if len(strings.TrimSpace(event)) == 0 {
		metrics.IncreaseNotGithubEventCounter()
		_fail(http.StatusBadRequest, fmt.Errorf("Not a github event"))
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

		metrics.IncreasePushGithubEventTypeCounter(sshURL, branch, commitID)

		applicationSummaries, _, err := wh.validateCloneURL(req, body, sshURL)
		if err != nil {
			metrics.IncreaseFailedCloneURLValidationCounter(sshURL)
			_fail(http.StatusBadRequest, err)
			return
		}

		var message string
		success := true

		for _, applicationSummary := range applicationSummaries {
			jobSummary, err := wh.apiServer.TriggerPipeline(wh.ServiceAccountBearerToken, applicationSummary.Name, branch, commitID)
			metrics.IncreasePushGithubEventTypeTriggerPipelineCounter(sshURL, branch, commitID, applicationSummary.Name)
			if err != nil {
				message = appendToMessage(message, fmt.Sprintf("Push failed for the Radix project %s. Error was: %s", applicationSummary.Name, err))
				success = false
				continue
			}

			success = true
			message = appendToMessage(message, getMessageForJob(jobSummary.Name, jobSummary.AppName, jobSummary.Branch, jobSummary.CommitID))
		}

		if !success {
			metrics.IncreasePushGithubEventTypeFailedTriggerPipelineCounter(sshURL, branch, commitID)
			_fail(http.StatusBadRequest, errors.New(message))
			return
		}

		_succeedWithMessage(message)

	case *github.PingEvent:
		sshURL := getSSHUrlFromPingURL(*e.Hook.URL)
		metrics.IncreasePingGithubEventTypeCounter(sshURL)

		_, message, err := wh.validateCloneURL(req, body, sshURL)

		if err != nil {
			metrics.IncreaseFailedCloneURLValidationCounter(sshURL)
			_fail(http.StatusBadRequest, err)
			return
		}

		_succeedWithMessage(message)

	default:
		metrics.IncreaseUnsupportedGithubEventTypeCounter()
		_fail(http.StatusNotFound, fmt.Errorf("Unknown event type %s ", github.WebHookType(req)))
		return
	}
}

func (wh *WebHookHandler) validateCloneURL(req *http.Request, body []byte, sshURL string) ([]*models.ApplicationSummary, string, error) {
	applicationSummaries, err := wh.apiServer.ShowApplications(wh.ServiceAccountBearerToken, sshURL)
	if err != nil {
		return nil, "", err
	}

	if len(applicationSummaries) < 1 {
		return nil, "", errors.New("Unable to match repo with any Radix registration")
	} else if len(applicationSummaries) > 1 {
		return nil, "", errors.New("Unable to match repo with unique Radix registration. Right now we only can handle one registration per repo")
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
			message = appendToMessage(message, fmt.Sprintf("Webhook is not configured correctly for the Radix project %s. Error was: %s", application.Registration.Name, err))
			success = false
			continue
		}

		message = appendToMessage(message, fmt.Sprintf("Webhook is configured correctly with for the Radix project %s", application.Registration.Name))
	}

	if !success {
		return nil, "", errors.New(message)
	}

	return applicationSummaries, message, nil
}

func getMessageForJob(jobName, appName, branch, commitID string) string {
	return fmt.Sprintf("Job %s started for %s on branch %s for commit %s", jobName, appName, branch, commitID)
}

func getBranch(pushEvent *github.PushEvent) string {
	ref := strings.Split(*pushEvent.Ref, "/")
	return ref[len(ref)-1]
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

func succeedWithMessage(w http.ResponseWriter, event, message string) {
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
	sum := SHA1HMAC([]byte(secretKey), payload)
	if subtle.ConstantTimeCompare([]byte(sum), []byte(signature)) != 1 {
		log.Printf("Expected signature %q (sum), got %q (hub-signature)", sum, signature)
		return errors.New("payload signature check failed")
	}
	return nil
}

// SHA1HMAC computes the GitHub SHA1 HMAC.
func SHA1HMAC(salt, message []byte) string {
	// GitHub creates a SHA1 HMAC, where the key is the GitHub secret and the
	// message is the JSON body.
	digest := hmac.New(sha1.New, salt)
	digest.Write(message)
	sum := digest.Sum(nil)
	return fmt.Sprintf("sha1=%x", sum)
}
