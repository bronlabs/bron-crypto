package riss

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/combinatorics"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"slices"
	"sort"
)

var (
	_ sort.Interface = (bySharingIdUsage)(nil)
)

type sharingIdUsage struct {
	id types.SharingID
	c  uint64
}

type bySharingIdUsage []sharingIdUsage

func (b bySharingIdUsage) Len() int {
	return len(b)
}

func (b bySharingIdUsage) Less(i, j int) bool {
	return b[i].c < b[j].c
}

func (b bySharingIdUsage) Swap(i, j int) {
	tmp := b[i]
	b[i] = b[j]
	b[j] = tmp
}

func BuildRhoMapping(sortedMaxUnqualifiedSets []SharingIdSet, total uint) (map[SharingIdSet]map[SharingIdSet]types.SharingID, error) {
	mapping := make(map[SharingIdSet]map[SharingIdSet]types.SharingID)
	for _, set := range sortedMaxUnqualifiedSets {
		mapping[set] = make(map[SharingIdSet]types.SharingID)
	}

	utilization := make([]sharingIdUsage, total)
	for i := types.SharingID(1); i <= types.SharingID(total); i++ {
		utilization[i-1] = sharingIdUsage{id: i, c: 0}
	}

	for l := len(sortedMaxUnqualifiedSets) - 1; l >= 0; l-- {
	next:
		for r := 0; r < len(sortedMaxUnqualifiedSets); r++ {
			for i := 0; i < len(utilization); i++ {
				if !sortedMaxUnqualifiedSets[l].Has(utilization[i].id) && !sortedMaxUnqualifiedSets[r].Has(utilization[i].id) {
					mapping[sortedMaxUnqualifiedSets[l]][sortedMaxUnqualifiedSets[r]] = utilization[i].id
					utilization[i].c = utilization[i].c + 1
					sort.Stable(bySharingIdUsage(utilization))
					continue next
				}
			}
			return nil, errs.NewFailed("unable to build rho mapping")
		}
	}

	return mapping, nil
}

type unqualifiedSetUsage struct {
	set SharingIdSet
	c   uint64
}

type byUnqualifiedSetUsage []unqualifiedSetUsage

func (s byUnqualifiedSetUsage) Len() int {
	return len(s)
}

func (s byUnqualifiedSetUsage) Less(i, j int) bool {
	return s[i].c < s[j].c
}

func (s byUnqualifiedSetUsage) Swap(i, j int) {
	tmp := s[i]
	s[i] = s[j]
	s[j] = tmp
}

func BuildChiMapping(unqualifiedSets []SharingIdSet, total uint) (map[types.SharingID]SharingIdSet, error) {
	mapping := make(map[types.SharingID]SharingIdSet)
	utilization := make([]SharingIdSet, total)
	copy(utilization, unqualifiedSets)

next:
	for id := types.SharingID(total); id > 0; id-- {
		for i := 0; i < len(unqualifiedSets); i++ {
			if !utilization[i].Has(id) {
				mapping[id] = utilization[i]
				slices.Delete(utilization, i, i+1)
				continue next
			}
		}
		return nil, errs.NewFailed("unable to build chi mapping")
	}

	return mapping, nil
}

//type SharingIdSetPair struct {
//	L SharingIdSet
//	R SharingIdSet
//}

func BuildSortedMaxUnqualifiedSets(threshold, total uint) ([]SharingIdSet, error) {
	sharingIds := make([]types.SharingID, total)
	for i := range total {
		sharingIds[i] = types.SharingID(i + 1)
	}

	rawMaxUnqualifiedSets, err := combinatorics.Combinations(sharingIds, threshold-1)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute combinations")
	}
	maxUnqualifiedSets := make([]SharingIdSet, len(rawMaxUnqualifiedSets))
	for i, rawMaxUnqualifiedSet := range rawMaxUnqualifiedSets {
		maxUnqualifiedSets[i] = NewSharingIdSetOf(rawMaxUnqualifiedSet...)
	}
	slices.Sort(maxUnqualifiedSets)

	return maxUnqualifiedSets, nil
}

//// BuildExpTable builds "exponentiation table" - not perfectly balanced but good enough.
//func BuildExpTable(threshold, total uint) (map[types.SharingID][]SharingIdSet, error) {
//	maxUnqualifiedSets, err := BuildSortedMaxUnqualifiedSets(threshold, total)
//	if err != nil {
//		return nil, errs.WrapFailed(err, "cannot build max unqualified sets")
//	}
//
//	expTableRaw := make([][]SharingIdSet, total)
//	for _, unqualifiedSet := range maxUnqualifiedSets {
//		minIdx := -1
//		for i := int(total) - 1; i >= 0; i-- {
//			sharingId := types.SharingID(i + 1)
//			if !unqualifiedSet.Has(sharingId) {
//				if minIdx == -1 || len(expTableRaw[i]) < len(expTableRaw[minIdx]) {
//					minIdx = i
//				}
//			}
//		}
//		expTableRaw[minIdx] = append(expTableRaw[minIdx], unqualifiedSet)
//	}
//
//	expTable := make(map[types.SharingID][]SharingIdSet)
//	for i, entry := range expTableRaw {
//		sharingId := types.SharingID(i + 1)
//		expTable[sharingId] = entry
//	}
//
//	return expTable, nil
//}
//
//// BuildMulTable builds "multiplication table" - not perfectly balanced but good enough.
//func BuildMulTable(threshold, total uint) (map[types.SharingID][]*SharingIdSetPair, error) {
//	maxUnqualifiedSets, err := BuildSortedMaxUnqualifiedSets(threshold, total)
//	if err != nil {
//		return nil, errs.WrapFailed(err, "cannot build max unqualified sets")
//	}
//
//	mulTableRaw := make([][]*SharingIdSetPair, total)
//	for _, LSet := range maxUnqualifiedSets {
//		for _, RSet := range maxUnqualifiedSets {
//			minIdx := -1
//			for i := int(total) - 1; i >= 0; i-- {
//				sharingId := types.SharingID(i + 1)
//				if !LSet.Has(sharingId) && !RSet.Has(sharingId) {
//					if minIdx == -1 || len(mulTableRaw[i]) < len(mulTableRaw[minIdx]) {
//						minIdx = i
//					}
//				}
//			}
//			mulTableRaw[minIdx] = append(mulTableRaw[minIdx], &SharingIdSetPair{
//				L: LSet,
//				R: RSet,
//			})
//		}
//	}
//
//	mulTable := make(map[types.SharingID][]*SharingIdSetPair)
//	for i, entry := range mulTableRaw {
//		sharingId := types.SharingID(i + 1)
//		mulTable[sharingId] = entry
//	}
//
//	return mulTable, nil
//}
