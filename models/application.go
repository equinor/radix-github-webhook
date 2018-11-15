package models

// Application details of an application
type Application struct {
	// Registration registration details
	Registration ApplicationRegistration `json:"registration"`
}

// ApplicationRegistration ApplicationRegistration describe an application
type ApplicationRegistration struct {
	// Name the unique name of the Radix application
	Name string `json:"name"`

	// SharedSecret the shared secret of the webhook
	SharedSecret *string `json:"sharedSecret"`
}

// ApplicationBuilder Handles construction of application detail
type ApplicationBuilder interface {
	WithName(string) ApplicationBuilder
	WithSharedSecret(string) ApplicationBuilder
	Build() *Application
}

type applicationBuilder struct {
	name         string
	sharedSecret string
}

// NewApplicationBuilder Constructor
func NewApplicationBuilder() ApplicationBuilder {
	return &applicationBuilder{}
}

func (ab *applicationBuilder) WithName(name string) ApplicationBuilder {
	ab.name = name
	return ab
}

func (ab *applicationBuilder) WithSharedSecret(sharedSecret string) ApplicationBuilder {
	ab.sharedSecret = sharedSecret
	return ab
}

// Build Builds object from builder data
func (ab *applicationBuilder) Build() *Application {
	return &Application{
		Registration: ApplicationRegistration{
			Name:         ab.name,
			SharedSecret: &ab.sharedSecret,
		}}
}
