package przs

import (
	"io"
	"math/rand/v2"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type Sampler[FE algebra.PrimeFieldElement[FE]] struct {
	field       algebra.PrimeField[FE]
	mySharingId sharing.ID
	seededPrngs ds.Map[sharing.ID, io.Reader]
}

func NewSampler[FE algebra.PrimeFieldElement[FE]](sharingId sharing.ID, quorum network.Quorum, seeds Seeds, field algebra.PrimeField[FE]) (*Sampler[FE], error) {
	prngs := hashmap.NewComparable[sharing.ID, io.Reader]()
	for id := range quorum.Iter() {
		if id == sharingId {
			continue
		}
		seed, ok := seeds.Get(id)
		if !ok {
			return nil, errs.NewValidation("missing seed for %d", id)
		}

		prng := rand.NewChaCha8(seed)
		prngs.Put(id, prng)
	}
	p := &Sampler[FE]{
		field:       field,
		mySharingId: sharingId,
		seededPrngs: prngs.Freeze(),
	}

	return p, nil
}

func (s *Sampler[FE]) Sample() (FE, error) {
	var nilFE FE
	share := s.field.Zero()

	for id, prng := range s.seededPrngs.Iter() {
		sample, err := s.field.Random(prng)
		if err != nil {
			return nilFE, errs.WrapRandomSample(err, "could not sample scalar")
		}

		if id < s.mySharingId {
			share = share.Add(sample)
		} else {
			share = share.Add(sample.Neg())
		}
	}

	if share.IsZero() {
		return nilFE, errs.NewFailed("could not sample a zero share")
	}
	return share, nil
}
