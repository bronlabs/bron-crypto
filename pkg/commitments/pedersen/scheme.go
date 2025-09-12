package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
)

type Scheme[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	key *Key[E, S]
}

func NewScheme[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](key *Key[E, S]) (*Scheme[E, S], error) {
	if key == nil {
		return nil, errs.NewIsNil("key cannot be nil")
	}

	s := &Scheme[E, S]{
		key: key,
	}
	return s, nil
}

func (s *Scheme[_, _]) Name() commitments.Name {
	return Name
}

// TODO: add committer to CRTP so it doesn't return interface
func (s *Scheme[E, S]) Committer() commitments.Committer[*Witness[S], *Message[S], *Commitment[E, S]] {
	return &Committer[E, S]{
		key: s.key,
	}
}

// TODO: add verifier to CRTP so it doesn't return interface
func (s *Scheme[E, S]) Verifier() commitments.Verifier[*Witness[S], *Message[S], *Commitment[E, S]] {
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
