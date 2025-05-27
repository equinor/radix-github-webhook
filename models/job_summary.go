package models

// JobSummary holds general information about job
type JobSummary struct {
	// Name of the job
	Name string `json:"name"`

	// AppName of the application
	AppName string `json:"appName"`

	// Branch to build from
	Branch string `json:"branch"`

	// GitRef Branch or tag to build from
	//
	// example: master
	GitRef string `json:"gitRef,omitempty"`

	// GitRefType When the pipeline job should be built from branch or tag specified in GitRef:
	// - branch
	// - tag
	// - <empty> - either branch or tag
	//
	// example: "branch"
	GitRefType string `json:"gitRefType,omitempty"`

	// CommitID the commit ID of the branch to build
	CommitID string `json:"commitID"`

	// TriggeredBy of the job
	TriggeredBy string `json:"triggeredBy"`
}

// GetGitRefOrDefault returns the GitRef if set, otherwise returns the Branch
func (jobSummary JobSummary) GetGitRefOrDefault() string {
	if jobSummary.GitRef != "" {
		return jobSummary.GitRef
	}
	return jobSummary.Branch
}

// GetGitRefTypeOrDefault returns the GitRefType if set, otherwise returns the Branch
func (jobSummary JobSummary) GetGitRefTypeOrDefault() string {
	if jobSummary.GitRefType != "" {
		return jobSummary.GitRefType
	}
	return "branch"
}
