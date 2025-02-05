package mpc

import (
	"math/bits"

	"github.com/bronlabs/krypton-primitives/pkg/base/types"
)

type BinaryShare struct {
	SubShares map[SharingIdSet]uint64
}

func (s *BinaryShare) SharingId() types.SharingID {
	union := SharingIdSet(0)
	for sharingIdSet := range s.SubShares {
		union |= sharingIdSet
	}

	return types.SharingID(bits.TrailingZeros64(^uint64(union)) + 1)
}

func (s *BinaryShare) Clone() *BinaryShare {
	result := make(map[SharingIdSet]uint64)
	for sharingIdSet, subShareValue := range s.SubShares {
		result[sharingIdSet] = subShareValue
	}

	return &BinaryShare{SubShares: result}
}

func (s *BinaryShare) Xor(rhs *BinaryShare) *BinaryShare {
	result := make(map[SharingIdSet]uint64)
	for sharingIdSet, subShareValue := range s.SubShares {
		result[sharingIdSet] = subShareValue ^ rhs.SubShares[sharingIdSet]
	}

	return &BinaryShare{SubShares: result}
}

func (s *BinaryShare) Shr(shift int) *BinaryShare {
	result := make(map[SharingIdSet]uint64)
	for sharingIdSet, subShareValue := range s.SubShares {
		result[sharingIdSet] = subShareValue >> shift
	}

	return &BinaryShare{SubShares: result}
}

func (s *BinaryShare) Shl(shift int) *BinaryShare {
	result := make(map[SharingIdSet]uint64)
	for sharingIdSet, subShareValue := range s.SubShares {
		result[sharingIdSet] = subShareValue << shift
	}

	return &BinaryShare{SubShares: result}
}

func (s *BinaryShare) Ror(shift int) *BinaryShare {
	result := make(map[SharingIdSet]uint64)
	for sharingIdSet, subShareValue := range s.SubShares {
		result[sharingIdSet] = bits.RotateLeft64(subShareValue, -shift)
	}

	return &BinaryShare{SubShares: result}
}

func (s *BinaryShare) Rol(shift int) *BinaryShare {
	result := make(map[SharingIdSet]uint64)
	for sharingIdSet, subShareValue := range s.SubShares {
		result[sharingIdSet] = bits.RotateLeft64(subShareValue, shift)
	}

	return &BinaryShare{SubShares: result}
}

func (s *BinaryShare) XorPlain(rhs uint64) *BinaryShare {
	smallestSharingIdSet := s.smallestSharingIdSet()
	result := make(map[SharingIdSet]uint64)
	for sharingIdSet, subShareValue := range s.SubShares {
		if sharingIdSet == smallestSharingIdSet {
			result[sharingIdSet] = subShareValue ^ rhs
		} else {
			result[sharingIdSet] = subShareValue
		}
	}

	return &BinaryShare{SubShares: result}
}

func (s *BinaryShare) AndPlain(rhs uint64) *BinaryShare {
	result := make(map[SharingIdSet]uint64)
	for sharingIdSet, subShareValue := range s.SubShares {
		result[sharingIdSet] = subShareValue & rhs
	}

	return &BinaryShare{SubShares: result}
}

func (s *BinaryShare) Not() *BinaryShare {
	smallestSharingIdSet := s.smallestSharingIdSet()
	result := make(map[SharingIdSet]uint64)
	for sharingIdSet, subShareValue := range s.SubShares {
		if sharingIdSet == smallestSharingIdSet {
			result[sharingIdSet] = subShareValue ^ 0xffffffffffffffff
		} else {
			result[sharingIdSet] = subShareValue
		}
	}

	return &BinaryShare{SubShares: result}
}

func (*BinaryShare) smallestSharingIdSet() SharingIdSet {
	return 1
}
