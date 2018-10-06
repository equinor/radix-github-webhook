package handler

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/google/go-github/github"
	"github.com/pkg/errors"
	"github.com/statoil/radix-github-webhook/models"
)

const hubSignatureHeader = "X-Hub-Signature"

// TODO: Should we standardize on a port
const apiServerEndPoint = "http://server.radix-api-prod:3002/api"
const getRegistrationsEndPointPattern = apiServerEndPoint + "/v1/platform/registrations?sshRepo=%s"
const startPipelineEndPointPattern = apiServerEndPoint + "/v1/platform/registrations/%s/pipeline/%s"

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
}

// NewWebHookHandler Constructor
func NewWebHookHandler(token string) *WebHookHandler {
	return &WebHookHandler{
		token,
	}
}

// HandleWebhookEvents Main handler of events
func (wh *WebHookHandler) HandleWebhookEvents() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		event := req.Header.Get("x-github-event")

		_fail := func(err error) {
			fail(w, event, err)
		}
		_succeed := func() {
			succeed(w, event)
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
			rr, err := isValidSecret(req, body, wh.ServiceAccountBearerToken, e.Repo.GetSSHURL())
			if err != nil {
				_fail(err)
				return
			}

			message, err := processPushEvent(rr.Name, wh.ServiceAccountBearerToken, e, req)
			if err != nil {
				_fail(err)
				return
			}

			_succeedWithMessage(message)

		case *github.PingEvent:
			sshURL := getSSHUrlFromPingURL(*e.Hook.URL)
			rr, err := isValidSecret(req, body, wh.ServiceAccountBearerToken, sshURL)
			if err != nil {
				_fail(err)
				return
			}

			_succeedWithMessage(fmt.Sprintf("Webhook is set up correctly with the Radix project: %s", rr.Name))

		case *github.PullRequestEvent:
			_, err := isValidSecret(req, body, wh.ServiceAccountBearerToken, e.Repo.GetSSHURL())
			if err != nil {
				_fail(err)
				return
			}

			err = processPullRequestEvent(e, req)
			if err != nil {
				_fail(err)
				return
			}

			_succeed()

		default:
			_fail(fmt.Errorf("Unknown event type %s ", github.WebHookType(req)))
			return
		}
	})
}

func processPushEvent(appName, bearerToken string, pushEvent *github.PushEvent, req *http.Request) (string, error) {
	ref := strings.Split(*pushEvent.Ref, "/")
	pushBranch := ref[len(ref)-1]
	url := fmt.Sprintf(startPipelineEndPointPattern, appName, pushBranch)
	response, err := makeRequest(bearerToken, "POST", url)
	if err != nil {
		return "", err
	}

	return string(response), nil
}

func processPullRequestEvent(prEvent *github.PullRequestEvent, req *http.Request) error {
	return errors.New("Pull request is not supported at this moment")
}

func isValidSecret(req *http.Request, body []byte, bearerToken, sshURL string) (*models.ApplicationRegistration, error) {
	rr, err := getRadixRegistrationFromRepo(bearerToken, sshURL)
	if err != nil {
		return nil, err
	}

	signature := req.Header.Get(hubSignatureHeader)
	if err := validateSignature(signature, *rr.SharedSecret, body); err != nil {
		return nil, err
	}

	return rr, nil
}

func getRadixRegistrationFromRepo(bearerToken, sshURL string) (*models.ApplicationRegistration, error) {
	url := fmt.Sprintf(getRegistrationsEndPointPattern, url.QueryEscape(sshURL))
	response, err := makeRequest(bearerToken, "GET", url)
	if err != nil {
		return nil, err
	}

	rrs, err := unmarshal(response)
	if err != nil {
		return nil, err
	}

	if len(rrs) != 1 {
		return nil, errors.New("Unable to match repo with Radix registration")
	}

	return &rrs[0], nil
}

func makeRequest(bearerToken, method, url string) ([]byte, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, errors.Errorf("Unable create request for starting pipeline: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearerToken))

	log.Infof("%s: %s", method, url)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Errorf("Request failed: %v", err)
	}

	if resp.StatusCode != 200 {
		return nil, errors.Errorf("Request failed with error: %s", resp.Status)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Errorf("Invalid response: %v", err)
	}

	return body, nil
}

func getSSHUrlFromPingURL(pingURL string) string {
	fullName := pingRepoPattern.ReplaceAllString(pingURL, "")
	fullName = pingHooksPattern.ReplaceAllString(fullName, "")
	return fmt.Sprintf("git@github.com:%s.git", fullName)
}

func unmarshal(b []byte) ([]models.ApplicationRegistration, error) {
	var res []models.ApplicationRegistration
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}
	return res, nil
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
