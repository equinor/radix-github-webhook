package models

// Error Representation of parts of an error struct returned from the API
type Error struct {
	// a message that can be printed out for the user
	Message string `json:"message"`
	// the underlying error that can be e.g., logged for developers to look at
	Err error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}

	return e.Message
}
