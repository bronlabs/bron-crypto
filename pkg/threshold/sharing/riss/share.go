package riss

import (
	"maps"
	"math/big"
	"math/bits"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type IntShare struct {
	SubShares map[SharingIdSet]*big.Int
}

func (s *IntShare) SharingId() types.SharingID {
	union := SharingIdSet(0)
	for sharingIdSet := range s.SubShares {
		union |= sharingIdSet
	}

	return types.SharingID(bits.TrailingZeros64(^uint64(union)) + 1)
}

func (s *IntShare) ThresholdAccessStructure() (t, n uint) {
	t = uint(slices.Collect(maps.Keys(s.SubShares))[0].Size() + 1)

	union := SharingIdSet(0)
	for sharingIdSet := range s.SubShares {
		union |= sharingIdSet
	}
	n = uint(bits.OnesCount64(uint64(union)) + 1)

	return t, n
}

func (s *IntShare) Clone() *IntShare {
	result := make(map[SharingIdSet]*big.Int)
	for sharingIdSet, subShareValue := range s.SubShares {
		result[sharingIdSet] = new(big.Int).Set(subShareValue)
	}

	return &IntShare{SubShares: result}
}

func (s *IntShare) Add(rhs *IntShare) *IntShare {
	result := make(map[SharingIdSet]*big.Int)
	for sharingIdSet, subShareValue := range s.SubShares {
		result[sharingIdSet] = new(big.Int).Add(subShareValue, rhs.SubShares[sharingIdSet])
	}

	return &IntShare{SubShares: result}
}

func (s *IntShare) AddValue(rhs *big.Int) *IntShare {
	smallestSharingIdSet := s.smallestSharingIdSet()
	result := make(map[SharingIdSet]*big.Int)
	for sharingIdSet, subShareValue := range s.SubShares {
		if sharingIdSet == smallestSharingIdSet {
			result[sharingIdSet] = new(big.Int).Add(subShareValue, rhs)
		} else {
			result[sharingIdSet] = new(big.Int).Set(subShareValue)
		}
	}

	return &IntShare{SubShares: result}
}

func (s *IntShare) Sub(rhs *IntShare) *IntShare {
	result := make(map[SharingIdSet]*big.Int)
	for sharingIdSet, subShareValue := range s.SubShares {
		result[sharingIdSet] = new(big.Int).Sub(subShareValue, rhs.SubShares[sharingIdSet])
	}

	return &IntShare{SubShares: result}
}

func (s *IntShare) SubValue(rhs *big.Int) *IntShare {
	smallestSharingIdSet := s.smallestSharingIdSet()
	result := make(map[SharingIdSet]*big.Int)
	for sharingIdSet, subShareValue := range s.SubShares {
		if sharingIdSet == smallestSharingIdSet {
			result[sharingIdSet] = new(big.Int).Sub(subShareValue, rhs)
		} else {
			result[sharingIdSet] = new(big.Int).Set(subShareValue)
		}
	}

	return &IntShare{SubShares: result}
}

func (s *IntShare) MulValue(rhs *big.Int) *IntShare {
	result := make(map[SharingIdSet]*big.Int)
	for sharingIdSet, subShareValue := range s.SubShares {
		result[sharingIdSet] = new(big.Int).Mul(subShareValue, rhs)
	}

	return &IntShare{SubShares: result}
}

func (s *IntShare) Neg() *IntShare {
	result := make(map[SharingIdSet]*big.Int)
	for sharingIdSet, subShareValue := range s.SubShares {
		result[sharingIdSet] = new(big.Int).Neg(subShareValue)
	}

	return &IntShare{SubShares: result}
}

func (s *IntShare) Mod(modulus *big.Int) *IntShare {
	result := make(map[SharingIdSet]*big.Int)
	for sharingIdSet, subShareValue := range s.SubShares {
		result[sharingIdSet] = new(big.Int).Mod(subShareValue, modulus)
	}

	return &IntShare{SubShares: result}
}

func (s *IntShare) smallestSharingIdSet() SharingIdSet {
	sharingIdSize := slices.Collect(maps.Keys(s.SubShares))[0].Size()
	smallest := (uint64(1) << sharingIdSize) - 1
	return SharingIdSet(smallest)
}
