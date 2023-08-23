package radix

import "github.com/equinor/radix-github-webhook/models"

// APIServer Stub methods in order to mock endpoints
type APIServer interface {
	ShowApplications(sshURL string) ([]*models.ApplicationSummary, error)
	GetApplication(appName string) (*models.Application, error)
	TriggerPipeline(appName, branch, commitID, triggeredBy string) (*models.JobSummary, error)
}
