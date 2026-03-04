package pedersen

import (
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/errs-go/errs"
)

// NewScheme constructs a meta Pedersen VSS scheme that wraps an arbitrary LSSS.
//
// Parameters:
//   - key: the Pedersen commitment key (g, h)
//   - lsss: the underlying linear secret sharing scheme
//   - liftDealerFunc: converts the underlying dealer function into a lifted dealer function
func NewScheme[
	US sharing.LinearShare[US, USV, USSC], USV algebra.PrimeFieldElement[USV], USSC any,
	W interface {
		sharing.Secret[W]
		base.Transparent[WV]
	}, WV algebra.GroupElement[WV],
	UDO sharing.DealerOutput[US],
	AC accessstructures.Monotone,
	ULDF any,
	LFTUDF interface {
		algebra.Operand[LFTUDF]
		ShareOf(id sharing.ID) LFTUS
		Repr() iter.Seq[LFTUSV]
		Accepts(AC) bool
	},
	LFTUS interface {
		sharing.Share[LFTUS]
		Repr() iter.Seq[LFTUSV]
	},
	LFTUSV algebra.PrimeGroupElement[LFTUSV, USV],
](
	key *pedcom.Key[LFTUSV, USV],
	lsss sharing.LSSS[US, USV, W, WV, UDO, USSC, AC, ULDF],
	liftDealerFunc func(ULDF, LFTUSV) (LFTUDF, error),
) (*Scheme[US, USV, USSC, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV], error) {
	if key == nil {
		return nil, errs.New("key cannot be nil")
	}
	commitmentScheme, err := pedcom.NewScheme(key)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create commitment scheme")
	}
	return &Scheme[US, USV, USSC, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV]{
		key:              key,
		lsss:             lsss,
		commitmentScheme: commitmentScheme,
		liftDealerFunc:   liftDealerFunc,
	}, nil
}
