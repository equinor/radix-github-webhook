package radix

// ApiError Representation of parts of an error struct returned from the API
type ApiError struct {
	// a message that can be printed out for the user
	Message string `json:"message"`
	Code    int
}

func (e *ApiError) Error() string {
	return e.Message
}
