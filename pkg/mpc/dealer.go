package mpc

import (
	"encoding/binary"
	"io"
	"maps"
	"slices"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/base/utils/itertools"
)

type Dealer struct {
}

func NewDealer() *Dealer {
	return &Dealer{}
}

func (*Dealer) Share(secret uint64, prng io.Reader) map[types.SharingID]*BinaryShare {
	const Alice types.SharingID = 1
	const Bob types.SharingID = 2
	const Charlie types.SharingID = 3

	aliceSubShare := randomUint64(prng)
	bobSubShare := randomUint64(prng)
	charlieSubShare := secret ^ aliceSubShare ^ bobSubShare

	return map[types.SharingID]*BinaryShare{
		Alice: {
			SubShares: map[SharingIdSet]uint64{
				NewSharingIdSetOf(Bob):     bobSubShare,
				NewSharingIdSetOf(Charlie): charlieSubShare,
			},
		},
		Bob: {
			SubShares: map[SharingIdSet]uint64{
				NewSharingIdSetOf(Alice):   aliceSubShare,
				NewSharingIdSetOf(Charlie): charlieSubShare,
			},
		},
		Charlie: {
			SubShares: map[SharingIdSet]uint64{
				NewSharingIdSetOf(Alice): aliceSubShare,
				NewSharingIdSetOf(Bob):   bobSubShare,
			},
		},
	}
}

func (*Dealer) Open(shares ...*BinaryShare) (uint64, error) {
	subShares := make(map[SharingIdSet]uint64)
	for _, share := range shares {
		for sharingIdSet, subShareValue := range share.SubShares {
			if _, ok := subShares[sharingIdSet]; !ok {
				subShares[sharingIdSet] = subShareValue
			} else if subShares[sharingIdSet] != subShareValue {
				return 0, errs.NewFailed("consistency check fail")
			}
		}
	}

	secret := itertools.Fold(func(acc, x uint64) uint64 { return acc ^ x }, 0, slices.Collect(maps.Values(subShares))...)
	return secret, nil
}

func randomUint64(prng io.Reader) uint64 {
	var uint64Bytes [8]byte
	_, err := io.ReadFull(prng, uint64Bytes[:])
	if err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint64(uint64Bytes[:])
}
