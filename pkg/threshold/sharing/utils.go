package sharing

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

// NewOrdinalShareholderSet creates a set of shareholder IDs {1, 2, ..., count}.
// This is a convenience function for creating standard shareholder sets where
// IDs are sequential integers starting from 1.
func NewOrdinalShareholderSet(count uint) ds.Set[ID] {
	out := hashset.NewComparable[ID]()
	for i := range count {
		out.Add(ID(i + 1))
	}
	return out.Freeze()
}

// CollectIDs extracts the shareholder IDs from a slice of shares.
// Returns an error if any share is nil.
func CollectIDs[S Share[S]](shares ...S) ([]ID, error) {
	ids, err := sliceutils.MapOrError(shares, func(s S) (ID, error) {
		if utils.IsNil(s) {
			return 0, errs.NewIsNil("share cannot be nil")
		}
		return s.ID(), nil
	})
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to collect share IDs")
	}
	return ids, nil
}
