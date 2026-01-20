package przs

import (
	"io"
	"math/rand/v2"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

// Sampler deterministically derives zero-sharing scalars from pairwise seeds.
type Sampler[FE algebra.PrimeFieldElement[FE]] struct {
	field       algebra.PrimeField[FE]
	mySharingID sharing.ID
	seededPrngs ds.Map[sharing.ID, io.Reader]
}

// NewSampler builds a sampler from per-party seeds agreed during setup.
func NewSampler[FE algebra.PrimeFieldElement[FE]](sharingID sharing.ID, quorum network.Quorum, seeds Seeds, field algebra.PrimeField[FE]) (*Sampler[FE], error) {
	prngs := hashmap.NewComparable[sharing.ID, io.Reader]()
	for id := range quorum.Iter() {
		if id == sharingID {
			continue
		}
		seed, ok := seeds.Get(id)
		if !ok {
			return nil, ErrInvalidArgument.WithMessage("missing seed for %d", id)
		}

		prng := rand.NewChaCha8(seed)
		prngs.Put(id, prng)
	}
	p := &Sampler[FE]{
		field:       field,
		mySharingID: sharingID,
		seededPrngs: prngs.Freeze(),
	}

	return p, nil
}

// Sample draws a zero-share using pairwise PRNGs; the sum across parties is zero.
func (s *Sampler[FE]) Sample() (FE, error) {
	var nilFE FE
	share := s.field.Zero()

	for id, prng := range s.seededPrngs.Iter() {
		sample, err := s.field.Random(prng)
		if err != nil {
			return nilFE, errs2.Wrap(err).WithMessage("could not sample scalar")
		}

		if id < s.mySharingID {
			share = share.Add(sample)
		} else {
			share = share.Add(sample.Neg())
		}
	}

	if share.IsZero() {
		return nilFE, ErrFailed.WithMessage("could not sample a zero share")
	}
	return share, nil
}
