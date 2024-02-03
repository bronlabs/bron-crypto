package prss

import (
	"gonum.org/v1/gonum/stat/combin"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
)

type SubSet struct {
	n       int
	keyToId map[types.IdentityHash]int
	subSet  map[int]integration.IdentityKey
}

func NewSubSets(allParties *hashset.HashSet[integration.IdentityKey], size int) []*SubSet {
	idToKey, keyToId, _ := integration.DeriveSharingIds(allParties.List()[0], allParties)

	subSets := make([]*SubSet, 0)
	combinations := combin.Combinations(allParties.Len(), size)
	for _, combination := range combinations {
		subSet := make(map[int]integration.IdentityKey)
		for _, index := range combination {
			sharingId := index + 1
			subSet[sharingId] = idToKey[sharingId]
		}
		subSets = append(subSets, &SubSet{
			n:       allParties.Len(),
			keyToId: keyToId,
			subSet:  subSet,
		})
	}

	return subSets
}

func (s *SubSet) Contains(id integration.IdentityKey) bool {
	sharingId := s.keyToId[id.Hash()]
	if _, ok := s.subSet[sharingId]; ok {
		return true
	} else {
		return false
	}
}

func (s *SubSet) Label() int {
	label := 0
	for k := range s.subSet {
		label += 1 << (k - 1)
	}
	return label
}
