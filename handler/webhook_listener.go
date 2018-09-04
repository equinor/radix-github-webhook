package handler

import (
	"github.com/google/go-github/github"
	"net/http"
)

type WebhookListener interface {
	ProcessPingEvent(pingEvent *github.PingEvent, req *http.Request) (string, error)
	ProcessPushEvent(pushEvent *github.PushEvent, req *http.Request) error
	ProcessPullRequestEvent(prEvent *github.PullRequestEvent, req *http.Request) error
}
