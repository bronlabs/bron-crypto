package isn

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/errs-go/errs"
)

// NewFiniteGroupElementSampler creates a new Sampler for secrets and shares based on the random sampling function of a finite group. It returns an error if the provided group is nil.
func NewFiniteGroupElementSampler[E algebra.GroupElement[E]](g algebra.FiniteGroup[E]) (*Sampler[E], error) {
	if g == nil {
		return nil, ErrIsNil.WithMessage("group is nil")
	}
	return &Sampler[E]{
		secrets: g.Random,
		shares:  g.Random,
	}, nil
}

// Sampler provides functions to sample secrets and shares for ISN schemes. It abstracts the randomness source and allows for flexible sampling strategies.
type Sampler[E algebra.GroupElement[E]] struct {
	secrets func(io.Reader) (E, error)
	shares  func(io.Reader) (E, error)
}

func (s *Sampler[E]) Secret(prng io.Reader) (E, error) {
	return s.secrets(prng)
}

func (s *Sampler[E]) Share(prng io.Reader) (E, error) {
	return s.shares(prng)
}

// NewSecret creates a new secret from a group element.
func NewSecret[E algebra.GroupElement[E]](v E) *Secret[E] {
	return &Secret[E]{v: v}
}

// Secret represents a shared secret value in an ISN scheme. The secret
// is an element of a finite group and can be split into shares using
// either the DNF or CNF dealing algorithm.
type Secret[E algebra.GroupElement[E]] struct {
	v E
}

// Value returns the underlying group element of the secret.
func (s *Secret[E]) Value() E {
	return s.v
}

// Equal tests whether two secrets have equal values.
func (s *Secret[E]) Equal(other *Secret[E]) bool {
	if s == nil && other == nil {
		return s == other
	}
	return s.v.Equal(other.v)
}

// Clone creates a deep copy of the secret.
func (s *Secret[E]) Clone() *Secret[E] {
	return &Secret[E]{
		v: s.v.Clone(),
	}
}

var (
	ErrIsNil        = errs.New("is nil")
	ErrMembership   = errs.New("membership error")
	ErrFailed       = errs.New("failed")
	ErrUnauthorized = errs.New("unauthorised")
)
