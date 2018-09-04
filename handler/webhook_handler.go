package handler

import (
	"encoding/json"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/google/go-github/github"
	"net/http"
)

type WebhookResponse struct {
	Ok      bool   `json:"ok"`
	Event   string `json:"event"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

func HandleWebhookEvents(secret string, listener WebhookListener) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		event := req.Header.Get("x-github-event")

		_fail := func(err error) {
			fail(w, event, err)
		}
		_succeed := func() {
			succeed(w, event)
		}
		_succeedWithMessage := func(message string) {
			succeedWithMessage(w, event, message)
		}

		body, err := github.ValidatePayload(req, []byte(secret))
		if err != nil {
			_fail(fmt.Errorf("Webhook is not valid: err=%s ", err))
			return
		}

		payload, err := github.ParseWebHook(github.WebHookType(req), body)
		if err != nil {
			_fail(fmt.Errorf("Could not parse webhook: err=%s ", err))
			return
		}

		switch e := payload.(type) {
		case *github.PushEvent:
			err := listener.ProcessPushEvent(e, req)
			if err != nil {
				_fail(err)
			}

			_succeed()

		case *github.PingEvent:
			response, err := listener.ProcessPingEvent(e, req)
			if err != nil {
				_fail(err)
			}

			_succeedWithMessage(response)

		case *github.PullRequestEvent:
			err := listener.ProcessPullRequestEvent(e, req)
			if err != nil {
				_fail(err)
			}

			_succeed()

		default:
			_fail(fmt.Errorf("Unknown event type %s ", github.WebHookType(req)))
			return
		}
	})
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
	logrus.Printf("%s\n", err)
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
