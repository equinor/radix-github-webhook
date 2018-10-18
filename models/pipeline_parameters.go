package models

// PipelineParameters describe branch to build
type PipelineParameters struct {
	// Branch the branch to build
	//
	// required: true
	// example: master
	Branch string `json:"branch"`
}
