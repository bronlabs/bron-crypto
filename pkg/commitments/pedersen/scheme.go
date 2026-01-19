package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
)

// Scheme wires together the Pedersen CRS with its committer and verifier.
type Scheme[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	key *Key[E, S]
}

// NewScheme validates and constructs a Pedersen commitment scheme from the provided key.
func NewScheme[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](key *Key[E, S]) (*Scheme[E, S], error) {
	if key == nil {
		return nil, ErrInvalidArgument.WithMessage("key cannot be nil")
	}

	s := &Scheme[E, S]{
		key: key,
	}
	return s, nil
}

// Name returns the identifier of the Pedersen commitment scheme.
func (*Scheme[_, _]) Name() commitments.Name {
	return Name
}

// Committer returns a committer configured with the scheme key.
func (s *Scheme[E, S]) Committer() *Committer[E, S] {
	return &Committer[E, S]{
		key: s.key,
	}
}

// Verifier returns a verifier compatible with commitments produced by this scheme.
func (s *Scheme[E, S]) Verifier() *Verifier[E, S] {
	committingParty := &Committer[E, S]{
		key: s.key,
	}
	generic := commitments.NewGenericVerifier(committingParty, func(c1, c2 *Commitment[E, S]) bool {
		return c1.Equal(c2)
	})
	v := &Verifier[E, S]{
		GenericVerifier: *generic,
	}
	return v
}

// Key exposes the scheme CRS.
func (s *Scheme[E, S]) Key() *Key[E, S] {
	return s.key
}

// Group returns the prime group used by the scheme.
func (s *Scheme[E, S]) Group() algebra.PrimeGroup[E, S] {
	return s.key.Group()
}
