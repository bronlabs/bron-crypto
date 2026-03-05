package isn

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
)

// Name is the human-readable name for ISN secret sharing.
const Name sharing.Name = "ISN secret sharing scheme"

func clauses(ac *accessstructures.CNF) []bitset.ImmutableBitSet[sharing.ID] {
	clausesCount := 0
	for range ac.MaximalUnqualifiedSetsIter() {
		clausesCount++
	}

	clauses := make([]bitset.ImmutableBitSet[sharing.ID], 0, clausesCount)
	for set := range ac.MaximalUnqualifiedSetsIter() {
		clauses = append(clauses, bitset.NewImmutableBitSet(set.List()...))
	}
	return clauses
}

// sampler provides functions to sample secrets and shares for ISN schemes. It abstracts the randomness source and allows for flexible sampling strategies.
type sampler[E algebra.GroupElement[E]] struct {
	secrets func(io.Reader) (E, error)
	shares  func(io.Reader) (E, error)
}

// newFiniteGroupElementSampler creates a new sampler for secrets and shares based on the random sampling function of a finite group. It returns an error if the provided group is nil.
func newFiniteGroupElementSampler[E algebra.GroupElement[E]](g algebra.FiniteGroup[E]) (*sampler[E], error) {
	if g == nil {
		return nil, sharing.ErrIsNil.WithMessage("group is nil")
	}
	return &sampler[E]{
		secrets: g.Random,
		shares:  g.Random,
	}, nil
}

func (s *sampler[E]) Secret(prng io.Reader) (E, error) {
	return s.secrets(prng)
}

func (s *sampler[E]) Share(prng io.Reader) (E, error) {
	return s.shares(prng)
}
