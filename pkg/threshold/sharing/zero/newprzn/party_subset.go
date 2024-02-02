package newprzn

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"gonum.org/v1/gonum/stat/combin"
)

type PartySubSet struct {
	n              int
	keyToSharingid map[types.IdentityHash]int
	subSet         map[int]integration.IdentityKey
}

func (s *PartySubSet) Contains(id integration.IdentityKey) bool {
	sharingId := s.keyToSharingid[id.Hash()]
	idx := sharingId - 1
	if _, ok := s.subSet[idx]; ok {
		return true
	} else {
		return false
	}
}

func (s *PartySubSet) GetMap() map[int]integration.IdentityKey {
	return s.subSet
}

func (s *PartySubSet) Label() int {
	label := 0
	for k := range s.subSet {
		label += 1 << k
	}
	return label
}

func NewSubSets(allParties *hashset.HashSet[integration.IdentityKey], size int) []*PartySubSet {
	idToKey, keyToId, _ := integration.DeriveSharingIds(allParties.List()[0], allParties)
	subsets := make([]*PartySubSet, 0)
	combinations := combin.Combinations(allParties.Len(), size)
	for _, combination := range combinations {
		subset := &PartySubSet{
			n:              allParties.Len(),
			keyToSharingid: keyToId,
			subSet:         make(map[int]integration.IdentityKey),
		}
		for _, idx := range combination {
			subset.subSet[idx] = idToKey[idx+1]
		}
		subsets = append(subsets, subset)
	}
	return subsets
}
