package radix

import "github.com/equinor/radix-github-webhook/models"

// APIServer Stub methods in order to mock endpoints
type APIServer interface {
	ShowApplications(bearerToken, sshURL string) ([]*models.ApplicationSummary, error)
	GetApplication(bearerToken, appName string) (*models.Application, error)
	TriggerPipeline(bearerToken, appName, branch, commitID, triggeredBy string) (*models.JobSummary, error)
}
