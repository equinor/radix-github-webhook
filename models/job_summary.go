package models

// JobSummary holds general information about job
type JobSummary struct {
	// Name of the job
	Name string `json:"name"`

	// AppName of the application
	AppName string `json:"appName"`

	// Branch branch to build from
	Branch string `json:"branch"`

	// CommitID the commit ID of the branch to build
	CommitID string `json:"commitID"`
}
