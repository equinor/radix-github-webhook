package radix

import (
	"context"

	"github.com/equinor/radix-github-webhook/models"
)

// APIServer Stub methods in order to mock endpoints
type APIServer interface {
	ShowApplications(ctx context.Context, sshURL string) ([]*models.ApplicationSummary, error)
	GetApplication(ctx context.Context, appName string) (*models.Application, error)
	TriggerPipeline(ctx context.Context, appName, gitRefs, gitRefsType, commitID, triggeredBy string) (*models.JobSummary, error)
}
