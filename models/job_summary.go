package models

// JobSummary holds general information about job
type JobSummary struct {
	// Name of the job
	Name string `json:"name"`

	// AppName of the application
	AppName string `json:"appName"`

	// Branch to build from
	Branch string `json:"branch"`

	// GitRefsType When the pipeline job is triggered by a GitHub event via the Radix GitHub webhook FromType can specify
	// which Git references are applicable for this environment:
	// - branch - only events on branches (for refs/heads)
	// - tag - only events on tags (for refs/tags)
	// - <empty> - events on both branches and tags
	GitRefsType string `json:"gitRefsType"`

	// CommitID the commit ID of the branch to build
	CommitID string `json:"commitID"`

	// TriggeredBy of the job
	TriggeredBy string `json:"triggeredBy"`
}
