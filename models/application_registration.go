package models

// ApplicationRegistration ApplicationRegistration describe an application
type ApplicationRegistration struct {
	// Name the unique name of the Radix application
	Name string `json:"name"`

	// SharedSecret the shared secret of the webhook
	SharedSecret *string `json:"sharedSecret"`
}
