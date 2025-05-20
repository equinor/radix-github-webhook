package models

// PipelineParameters describe branch to build and its commit ID
type PipelineParameters struct {
	// Branch the branch to build
	//
	// required: true
	// example: master
	Branch string `json:"branch"`

	// CommitID the commit ID of the branch to build
	//
	// required: true
	// example: 4faca8595c5283a9d0f17a623b9255a0d9866a2e
	CommitID string `json:"commitID"`

	// TriggeredBy creator of job
	//
	// required: true
	// example: 4faca8595c5283a9d0f17a623b9255a0d9866a2e
	TriggeredBy string `json:"triggeredBy"`

	// GitRefsType A target of the git event when the pipeline job is triggered by a GitHub event
	// via the Radix GitHUb webhook: branch or tag (for refs/heads) or tag (for refs/tags), otherwise it is empty
	//
	// required: false
	GitRefsType string `json:"gitRefsType,omitempty"`
}
