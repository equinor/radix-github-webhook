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
	event := req.Header.Get("x-github-event")

	_fail := func(err error) {
		fail(w, event, err)
	}

	_succeedWithMessage := func(message string) {
		log.Infof("Success: %s", message)
		succeedWithMessage(w, event, message)
	}

	if len(strings.TrimSpace(event)) == 0 {
		_fail(fmt.Errorf("Not a github event"))
		return
	}

	// Need to parse webhook before validation because the secret is taken from the matching repo
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		_fail(fmt.Errorf("Could not parse webhook: err=%s ", err))
		return
	}

	payload, err := github.ParseWebHook(github.WebHookType(req), body)
	if err != nil {
		_fail(fmt.Errorf("Could not parse webhook: err=%s ", err))
		return
	}

	switch e := payload.(type) {
	case *github.PushEvent:
		branch := getBranch(e)
		if !strings.EqualFold(branch, "master") {
			log.Warnf("We currently only support push to master. Push on branch %s is ignored", branch)
			return
		}

		rrs, err := wh.apiServer.GetRadixRegistrationsFromRepo(wh.ServiceAccountBearerToken, e.Repo.GetSSHURL())
		if err != nil {
			_fail(err)
			return
		}

		if len(rrs) < 1 {
			_fail(errors.New("Unable to match repo with any Radix registration"))
		} else if len(rrs) > 1 {
			_fail(errors.New("Unable to match repo with unique Radix registration. Right now we only can handle one registration per repo"))
		}

		var message string
		success := true

		for _, rr := range rrs {
			err = isValidSecret(req, body, *rr.SharedSecret)
			if err != nil {
				message = appendToMessage(message, fmt.Sprintf("Webhook is not configured correctly for the Radix project %s. Error was: %s", rr.Name, err))
				success = false
				continue
			}

			responseFromPush, err := wh.apiServer.ProcessPushEvent(wh.ServiceAccountBearerToken, rr.Name, branch)
			if err != nil {
				message = appendToMessage(message, fmt.Sprintf("Push failed for the Radix project %s. Error was: %s", rr.Name, err))
				success = false
				continue
			}

			success = true
			message = appendToMessage(message, responseFromPush)
		}

		if !success {
			_fail(errors.New(message))
			return
		}

		_succeedWithMessage(message)

	case *github.PingEvent:
		sshURL := getSSHUrlFromPingURL(*e.Hook.URL)
		rrs, err := wh.apiServer.GetRadixRegistrationsFromRepo(wh.ServiceAccountBearerToken, sshURL)
		if err != nil {
			_fail(err)
			return
		}

		// If one is successful then consider it to be sucess. But will provide warning in message
		var message string
		success := false

		for _, rr := range rrs {
			err = isValidSecret(req, body, *rr.SharedSecret)
			if err != nil {
				message = appendToMessage(message, fmt.Sprintf("Webhook is not configured correctly for the Radix project %s. Error was: %s", rr.Name, err))
				continue
			}

			success = true
			message = appendToMessage(message, fmt.Sprintf("Webhook is configured correctly with for the Radix project %s", rr.Name))
		}

		if !success {
			_fail(errors.New(message))
			return
		}

		_succeedWithMessage(message)

	case *github.PullRequestEvent:
		rrs, err := wh.apiServer.GetRadixRegistrationsFromRepo(wh.ServiceAccountBearerToken, e.Repo.GetSSHURL())
		if err != nil {
			_fail(err)
			return
		}

		// If one is successful then consider it to be sucess. But will provide warning in message
		var message string
		success := false

		for _, rr := range rrs {
			err = isValidSecret(req, body, *rr.SharedSecret)
			if err != nil {
				message = appendToMessage(message, fmt.Sprintf("Webhook is not configured correctly for the Radix project %s. Error was: %s", rr.Name, err))
				continue
			}

			err := processPullRequestEvent(e, req)
			if err != nil {
				message = appendToMessage(message, fmt.Sprintf("Push failed for the Radix project %s. Error was: %s", rr.Name, err))
				continue
			}

			success = true
			message = appendToMessage(message, fmt.Sprintf("Webhook is configured correctly with for the Radix project %s", rr.Name))
		}

		if !success {
			_fail(errors.New(message))
			return
		}

		_succeedWithMessage(message)

	default:
		_fail(fmt.Errorf("Unknown event type %s ", github.WebHookType(req)))
		return
	}
}

func getBranch(pushEvent *github.PushEvent) string {
	ref := strings.Split(*pushEvent.Ref, "/")
	return ref[len(ref)-1]
}

func processPullRequestEvent(prEvent *github.PullRequestEvent, req *http.Request) error {
	return errors.New("Pull request is not supported at this moment")
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

func succeed(w http.ResponseWriter, event string) {
	render(w, WebhookResponse{
		Ok:    true,
		Event: event,
	})
}

func succeedWithMessage(w http.ResponseWriter, event, message string) {
	render(w, WebhookResponse{
		Ok:      true,
		Event:   event,
		Message: message,
	})
}

func fail(w http.ResponseWriter, event string, err error) {
	log.Printf("%s\n", err)
	w.WriteHeader(500)
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
