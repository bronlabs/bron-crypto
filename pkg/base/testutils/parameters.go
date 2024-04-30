package testutils

import (
	"io"
	"reflect"
	"testing"

	"pgregory.net/rapid"
)

// RunHappyFunct is a function type that runs a certain set of steps over a scenario
// (fixed across tests) with the provided parameters (vary across tests) and a
// random number generator.
type RunHappyFunct[ScenarioT any, P any, PublicParamT PublicParams[P],
] func(t *testing.T, scenario *ScenarioT, pp PublicParamT, rng io.Reader)

// RunUnhappyFunct is a function type that runs a certain set of steps over a scenario
// (fixed across tests) with the provided public parameters (vary across tests),
// unhappy path parameters (vary across tests) and a random number generator.
type RunUnhappyFunct[ScenarioT any, P any, U any,
	PublicParamT PublicParams[P], UnhappyParamT UnhappyParams[U],
] func(t *testing.T, scenario *ScenarioT, pp PublicParamT, up UnhappyParamT, rng io.Reader)

type Params interface {
	// String returns a string representation of the parameters.
	String() string
	// AreValid returns true if the parameters are valid, used to expect parameter errors.
	AreValid() bool
	// CanBeInvalid returns wether the parameters can be invalid, used to expect parameter errors.
	CanBeInvalid() bool
}

// PublicParams is an interface for the public testing parameters.
type PublicParams[P any] interface {
	Params
	// Seed returns the seed for the test's random number generator.
	Seed() []byte
	// Generator returns a `rapid` generator to generate random valid parameters.
	GeneratorPublicParams() *rapid.Generator[PublicParams[P]]
}

// UnhappyParams is an interface for the parametrization of unhappy paths.
type UnhappyParams[P any] interface {
	Params
	// Name returns the name of the unhappy path.
	Name() string
	// Generator returns a `rapid` generator to generate random valid parameters.
	GeneratorUnhappyParams() *rapid.Generator[UnhappyParams[P]]
}

func GetPublicParamsGenerator[P any, ParamT PublicParams[P]]() *rapid.Generator[PublicParams[P]] {
	return reflect.New(reflect.TypeFor[ParamT]()).Interface().(ParamT).GeneratorPublicParams()
}

func GetUnhappyParamsGenerator[P any, ParamT UnhappyParams[P]]() *rapid.Generator[UnhappyParams[P]] {
	return reflect.New(reflect.TypeFor[ParamT]()).Interface().(ParamT).GeneratorUnhappyParams()
}
