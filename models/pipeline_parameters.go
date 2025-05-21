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

	// GitRef Branch or tag to build from
	//
	// required: false
	// example: master
	GitRef string `json:"gitRef,omitempty"`

	// GitRefType When the pipeline job should be built from branch or tag specified in GitRef:
	// - branch
	// - tag
	// - <empty> - either branch or tag
	//
	// required false
	// enum: branch,tag,""
	// example: "branch"
	GitRefType string `json:"gitRefType,omitempty"`
}
