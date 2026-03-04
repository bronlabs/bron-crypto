package feldman

import (
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
)

// NewScheme constructs a meta Feldman VSS scheme that wraps an arbitrary LSSS.
//
// Parameters:
//   - basePoint: the group generator used to lift scalar values into the group
//   - lsss: the underlying linear secret sharing scheme
//   - liftDealerFunc: converts the underlying dealer function into a lifted dealer function
//   - liftShare: lifts a share value into the group using the base point
func NewScheme[
	S sharing.LinearShare[S, SV, SC], SV any, SC any,
	W interface {
		sharing.Secret[W]
		base.Transparent[WV]
	}, WV algebra.GroupElement[WV],
	DO sharing.DealerOutput[S],
	AC accessstructures.Monotone,
	DF any,
	LFTDF interface {
		ShareOf(id sharing.ID) LFTS
		Accepts(AC) bool
	},
	LFTS interface {
		sharing.Share[LFTS]
		Repr() iter.Seq[LFTEREPR]
	},
	LFTEREPR base.Equatable[LFTEREPR],
](
	basePoint LFTEREPR,
	lsss sharing.LSSS[S, SV, W, WV, DO, SC, AC, DF],
	liftDealerFunc func(DF, LFTEREPR) (LFTDF, error),
	liftShare func(SV, LFTEREPR) (LFTEREPR, error),
) *Scheme[S, SV, SC, W, WV, DO, AC, DF, LFTDF, LFTS, LFTEREPR] {
	return &Scheme[S, SV, SC, W, WV, DO, AC, DF, LFTDF, LFTS, LFTEREPR]{
		basePoint:      basePoint,
		lsss:           lsss,
		liftDealerFunc: liftDealerFunc,
		liftShare:      liftShare,
	}
}
