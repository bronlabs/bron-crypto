package replicated

import (
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/combinatorics"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type SharingIdSetPair struct {
	L SharingIdSet
	R SharingIdSet
}

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

// BuildExpTable builds "exponentiation table" - not perfectly balanced but good enough.
func BuildExpTable(threshold, total uint) (map[types.SharingID][]SharingIdSet, error) {
	maxUnqualifiedSets, err := BuildSortedMaxUnqualifiedSets(threshold, total)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot build max unqualified sets")
	}

	expTableRaw := make([][]SharingIdSet, total)
	for _, unqualifiedSet := range maxUnqualifiedSets {
		minIdx := -1
		for i := int(total) - 1; i >= 0; i-- {
			sharingId := types.SharingID(i + 1)
			if !unqualifiedSet.Has(sharingId) {
				if minIdx == -1 || len(expTableRaw[i]) < len(expTableRaw[minIdx]) {
					minIdx = i
				}
			}
		}
		expTableRaw[minIdx] = append(expTableRaw[minIdx], unqualifiedSet)
	}

	expTable := make(map[types.SharingID][]SharingIdSet)
	for i, entry := range expTableRaw {
		sharingId := types.SharingID(i + 1)
		expTable[sharingId] = entry
	}

	return expTable, nil
}

// BuildMulTable builds "multiplication table" - not perfectly balanced but good enough.
func BuildMulTable(threshold, total uint) (map[types.SharingID][]*SharingIdSetPair, error) {
	maxUnqualifiedSets, err := BuildSortedMaxUnqualifiedSets(threshold, total)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot build max unqualified sets")
	}

	mulTableRaw := make([][]*SharingIdSetPair, total)
	for _, LSet := range maxUnqualifiedSets {
		for _, RSet := range maxUnqualifiedSets {
			minIdx := -1
			for i := int(total) - 1; i >= 0; i-- {
				sharingId := types.SharingID(i + 1)
				if !LSet.Has(sharingId) && !RSet.Has(sharingId) {
					if minIdx == -1 || len(mulTableRaw[i]) < len(mulTableRaw[minIdx]) {
						minIdx = i
					}
				}
			}
			mulTableRaw[minIdx] = append(mulTableRaw[minIdx], &SharingIdSetPair{
				L: LSet,
				R: RSet,
			})
		}
	}

	mulTable := make(map[types.SharingID][]*SharingIdSetPair)
	for i, entry := range mulTableRaw {
		sharingId := types.SharingID(i + 1)
		mulTable[sharingId] = entry
	}

	return mulTable, nil
}
