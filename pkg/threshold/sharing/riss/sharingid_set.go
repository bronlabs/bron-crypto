package riss

import (
	"math/bits"

	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type SharingIdSet uint64

func NewSharingIdSetOf(sharingIds ...types.SharingID) SharingIdSet {
	set := SharingIdSet(0)
	for _, sharingId := range sharingIds {
		set |= 1 << (sharingId - 1)
	}

	return set
}

func (s SharingIdSet) Has(sharingId types.SharingID) bool {
	return (s & (1 << (sharingId - 1))) != 0
}

func (s SharingIdSet) Size() int {
	return bits.OnesCount64(uint64(s))
}
