package models

// ApplicationRegistration ApplicationRegistration describe an application
type ApplicationRegistration struct {
	// Name the unique name of the Radix application
	Name string `json:"name"`

	// SharedSecret the shared secret of the webhook
	SharedSecret *string `json:"sharedSecret"`
}

// ApplicationRegistrationBuilder Handles construction of application registration
type ApplicationRegistrationBuilder interface {
	WithName(string) ApplicationRegistrationBuilder
	WithSharedSecret(string) ApplicationRegistrationBuilder
	BuildApplicationRegistration() *ApplicationRegistration
}

type applicationRegistrationBuilder struct {
	name         string
	sharedSecret string
}

// NewApplicationRegistrationBuilder Constructor
func NewApplicationRegistrationBuilder() ApplicationRegistrationBuilder {
	return &applicationRegistrationBuilder{}
}

func (ar *applicationRegistrationBuilder) WithName(name string) ApplicationRegistrationBuilder {
	ar.name = name
	return ar
}

func (ar *applicationRegistrationBuilder) WithSharedSecret(sharedSecret string) ApplicationRegistrationBuilder {
	ar.sharedSecret = sharedSecret
	return ar
}

// BuildApplicationRegistration Builds object from builder data
func (ar *applicationRegistrationBuilder) BuildApplicationRegistration() *ApplicationRegistration {
	return &ApplicationRegistration{
		Name:         ar.name,
		SharedSecret: &ar.sharedSecret,
	}
}
