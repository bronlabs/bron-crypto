package meta

import (
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/isn"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/shamir"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/pedersen"
	"github.com/bronlabs/errs-go/errs"
)

// NewFeldmanScheme creates a Feldman VSS scheme wrapping the given LSSS.
// The lifting functions are resolved automatically based on the underlying scheme.
func NewFeldmanScheme[
	S sharing.LinearShare[S, SV], SV algebra.PrimeFieldElement[SV],
	W interface {
		sharing.Secret[W]
		base.Transparent[WV]
	}, WV algebra.GroupElement[WV],
	DO sharing.DealerOutput[S],
	AC accessstructures.Monotone,
	DF sharing.DealerFunc[S, SV, AC],
	LFTDF sharing.DealerFunc[LFTS, LFTSV, AC],
	LFTS interface {
		sharing.Share[LFTS]
		Repr() iter.Seq[LFTSV]
	},
	LFTSV algebra.PrimeGroupElement[LFTSV, SV],
](
	basePoint LFTSV,
	lsss sharing.LSSS[S, SV, W, WV, DO, AC, DF],
) (*feldman.Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV], error) {
	if utils.IsNil(basePoint) {
		return nil, sharing.ErrIsNil.WithMessage("base point cannot be nil")
	}
	if lsss == nil {
		return nil, sharing.ErrIsNil.WithMessage("LSSS cannot be nil")
	}

	liftDealerFunc, err := resolveLiftDealerFunc[DF, LFTDF, SV, LFTSV](lsss.Name())
	if err != nil {
		return nil, err
	}

	liftShare, err := resolveLiftShare[S, LFTS, SV, LFTSV](lsss.Name())
	if err != nil {
		return nil, err
	}

	return feldman.NewScheme(
		basePoint, lsss, liftDealerFunc, liftShare,
	), nil
}

// NewPedersenScheme creates a Pedersen VSS scheme wrapping the given LSSS.
// The lifting functions are resolved automatically based on the underlying scheme.
func NewPedersenScheme[
	US sharing.LinearShare[US, USV], USV algebra.PrimeFieldElement[USV],
	W interface {
		sharing.Secret[W]
		base.Transparent[WV]
	}, WV algebra.GroupElement[WV],
	UDO sharing.DealerOutput[US],
	AC accessstructures.Monotone,
	ULDF sharing.DealerFunc[US, USV, AC],
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
	lsss sharing.LSSS[US, USV, W, WV, UDO, AC, ULDF],
) (*pedersen.Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV], error) {
	if key == nil {
		return nil, sharing.ErrIsNil.WithMessage("key cannot be nil")
	}
	if lsss == nil {
		return nil, sharing.ErrIsNil.WithMessage("LSSS cannot be nil")
	}

	liftDealerFunc, err := resolveLiftDealerFunc[ULDF, LFTUDF, USV, LFTUSV](lsss.Name())
	if err != nil {
		return nil, err
	}

	return pedersen.NewScheme(
		key, lsss, liftDealerFunc,
	)
}

// resolveLiftDealerFunc returns the appropriate liftDealerFunc for the given scheme name.
// It uses runtime type assertions to bridge the scheme-specific concrete types to the
// generic function signature expected by the meta schemes.
func resolveLiftDealerFunc[
	DF, LFTDF any,
	SV algebra.PrimeFieldElement[SV],
	LFTSV algebra.PrimeGroupElement[LFTSV, SV],
](name sharing.Name) (func(DF, LFTSV) (LFTDF, error), error) {
	switch name {
	case shamir.Name:
		liftDF, ok := any(shamir.LiftDealerFunc[LFTSV, SV]).(func(DF, LFTSV) (LFTDF, error))
		if !ok {
			return nil, errs.New("type mismatch: Shamir scheme requires matching DealerFunc and LiftedDealerFunc type parameters")
		}
		return liftDF, nil
	case isn.Name:
		liftDF, ok := any(isn.LiftDealerFunc[LFTSV, SV]).(func(DF, LFTSV) (LFTDF, error))
		if !ok {
			return nil, errs.New("type mismatch: ISN scheme requires matching DealerFunc and LiftedDealerFunc type parameters")
		}
		return liftDF, nil
	default:
		return nil, errs.New("unsupported underlying scheme: %s", name)
	}
}

// resolveLiftShare returns the appropriate liftShare for the given scheme name.
func resolveLiftShare[
	S, LFTS any,
	SV algebra.PrimeFieldElement[SV],
	LFTSV algebra.PrimeGroupElement[LFTSV, SV],
](name sharing.Name) (func(S, LFTSV) (LFTS, error), error) {
	switch name {
	case shamir.Name:
		liftS, ok := any(shamir.LiftShare[LFTSV, SV]).(func(S, LFTSV) (LFTS, error))
		if !ok {
			return nil, errs.New("type mismatch: Shamir scheme requires matching Share and LiftedShare type parameters")
		}
		return liftS, nil
	case isn.Name:
		liftS, ok := any(isn.LiftShare[LFTSV, SV]).(func(S, LFTSV) (LFTS, error))
		if !ok {
			return nil, errs.New("type mismatch: ISN scheme requires matching Share and LiftedShare type parameters")
		}
		return liftS, nil
	default:
		return nil, errs.New("unsupported underlying scheme: %s", name)
	}
}
