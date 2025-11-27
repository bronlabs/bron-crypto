package binrep3

import (
	"io"
	"maps"
	"slices"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

// TODO: This does not implement the sharing interface (yet?), as there's currently
// TODO: no way to represent direct product GF(2) x GF(2) x ... x GF(2)

type Scheme struct {
	accessStructure *shamir.AccessStructure
}

func NewScheme(partySet ds.Set[sharing.ID]) (*Scheme, error) {
	var errs []error
	if partySet == nil {
		errs = append(errs, ErrInvalidArgument.WithMessage("party set is nil"))
	}
	if partySet.Size() != 3 {
		errs = append(errs, ErrInvalidArgument.WithMessage("party set must have exactly 3 members"))
	}
	if len(errs) > 0 {
		return nil, errs2.Join(errs...)
	}

	accessStructure, err := shamir.NewAccessStructure(2, partySet)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not create access structure")
	}
	s := &Scheme{
		accessStructure: accessStructure,
	}
	return s, nil
}

func (s *Scheme) Name() sharing.Name {
	return Name
}

func (s *Scheme) Deal(secret uint64, prng io.Reader) (*DealerOutput, error) {
	var err error
	var secrets [3]uint64
	secrets[0], err = mathutils.RandomUint64(prng)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not generate random secret")
	}
	secrets[1], err = mathutils.RandomUint64(prng)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not generate random secret")
	}
	secrets[2] = secrets[0] ^ secrets[1] ^ secret

	ids := s.accessStructure.Shareholders().List()
	slices.Sort(ids)
	shares := make(map[sharing.ID]*Share)
	shares[ids[0]] = &Share{
		id: ids[0],
		p:  secrets[2],
		n:  secrets[1],
	}
	shares[ids[1]] = &Share{
		id: ids[1],
		p:  secrets[0],
		n:  secrets[2],
	}
	shares[ids[2]] = &Share{
		id: ids[2],
		p:  secrets[1],
		n:  secrets[0],
	}

	do := &DealerOutput{
		shares: shares,
	}
	return do, nil
}

func (s *Scheme) DealRandom(prng io.Reader) (*DealerOutput, uint64, error) {
	secret, err := mathutils.RandomUint64(prng)
	if err != nil {
		return nil, 0, errs2.Wrap(err).WithMessage("could not generate random secret")
	}
	do, err := s.Deal(secret, prng)
	if err != nil {
		return nil, 0, errs2.Wrap(err).WithMessage("could not deal shares")
	}
	return do, secret, nil
}

func (s *Scheme) Reconstruct(shares ...*Share) (uint64, error) {
	if len(shares) < 2 || len(shares) > 3 {
		return 0, ErrInvalidArgument.WithMessage("invalid number of shares")
	}

	sharesMap := make(map[sharing.ID]*Share)
	for _, share := range shares {
		sharesMap[share.id] = share
	}

	ids := s.accessStructure.Shareholders().List()
	secrets := make(map[sharing.ID]uint64)
	for i, id := range ids {
		share, ok := sharesMap[id]
		if !ok {
			continue
		}
		prevId := ids[(i+2)%3]
		nextId := ids[(i+1)%3]

		prevSecret := share.p
		nextSecret := share.n
		if secret, ok := secrets[prevId]; ok {
			if secret != prevSecret {
				return 0, ErrInvalidShare.WithMessage("inconsistent shares")
			}
		} else {
			secrets[prevId] = prevSecret
		}
		if secret, ok := secrets[nextId]; ok {
			if secret != nextSecret {
				return 0, ErrInvalidShare.WithMessage("inconsistent shares")
			}
		} else {
			secrets[nextId] = nextSecret
		}
	}
	if len(secrets) != 3 {
		return 0, ErrInvalidShare.WithMessage("inconsistent shares")
	}

	secret := iterutils.Reduce(maps.Values(secrets), 0, func(acc, v uint64) uint64 { return acc ^ v })
	return secret, nil
}

func (s *Scheme) AccessStructure() *shamir.AccessStructure {
	return s.accessStructure
}
