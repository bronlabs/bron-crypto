package sharing

import (
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/errs-go/errs"
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
			return 0, ErrIsNil.WithMessage("share cannot be nil")
		}
		return s.ID(), nil
	})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to collect share IDs")
	}
	return ids, nil
}

// DealerFuncsAreEqual checks if two dealer functions are equal by comparing their representations.
// It assumes that the representations yield coefficients in a consistent order.
func DealerFuncsAreEqual[
	DF DealerFunc[S, SV, AC],
	S LinearShare[S, SV],
	SV algebra.GroupElement[SV],
	AC accessstructures.Monotone,
](df1, df2 DF) bool {
	df1Pull, df1Stop := iter.Pull(df1.Repr())
	defer df1Stop()
	df2Pull, df2Stop := iter.Pull(df2.Repr())
	defer df2Stop()

	for {
		df1Val, df1Ok := df1Pull()
		df2Val, df2Ok := df2Pull()
		if !df1Ok && !df2Ok {
			return true
		}
		if df1Ok != df2Ok {
			return false
		}
		if !df1Val.Equal(df2Val) {
			return false
		}
	}
}
