package pedersen

import (
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/errs-go/errs"
)

type DealerFunc[
	S sharing.Share[S], SV algebra.GroupElement[SV], AC accessstructures.Monotone,
	UDF sharing.DealerFunc[UDF, S, SV, AC],
] struct {
	shares   UDF
	blinding UDF
}

func (f *DealerFunc[S, EREPR, AC, UDF]) Shares() UDF {
	return f.shares
}

func (f *DealerFunc[S, EREPR, AC, UDF]) Blinding() UDF {
	return f.blinding
}

func (f *DealerFunc[S, EREPR, AC, UDF]) ShareOf(id sharing.ID) S {
	return f.shares.ShareOf(id)
}

func (f *DealerFunc[S, EREPR, AC, UDF]) Repr() iter.Seq[EREPR] {
	return f.shares.Repr()
}

func (f *DealerFunc[S, EREPR, AC, UDF]) BlindingRepr() iter.Seq[EREPR] {
	return f.blinding.Repr()
}

func (f *DealerFunc[S, EREPR, AC, UDF]) Accepts(ac AC) bool {
	return f.shares.Accepts(ac)
}

func (f *DealerFunc[S, EREPR, AC, UDF]) Op(other *DealerFunc[S, EREPR, AC, UDF]) *DealerFunc[S, EREPR, AC, UDF] {
	return &DealerFunc[S, EREPR, AC, UDF]{
		shares:   f.shares.Op(other.shares),
		blinding: f.blinding.Op(other.blinding),
	}
}

type LinearDealerFunc[
	S sharing.LinearShare[S, SV],
	SV algebra.PrimeFieldElement[SV],
	LFTS sharing.LinearShare[LFTS, LFTSV],
	LFTSV algebra.PrimeGroupElement[LFTSV, SV],
	AC accessstructures.Monotone,
	ULDF sharing.LinearDealerFunc[ULDF, LFTUDF, S, SV, LFTS, LFTSV, AC], LFTUDF sharing.DealerFunc[LFTUDF, LFTS, LFTSV, AC],
] struct {
	shares   ULDF
	blinding ULDF
}

func (f *LinearDealerFunc[S, SV, LFTS, LFTSV, AC, ULDF, LFTUDF]) Shares() ULDF {
	return f.shares
}

func (f *LinearDealerFunc[S, SV, LFTS, LFTSV, AC, ULDF, LFTUDF]) Blinding() ULDF {
	return f.blinding
}

func (f *LinearDealerFunc[S, SV, LFTS, LFTSV, AC, ULDF, LFTUDF]) ShareOf(id sharing.ID) S {
	return f.shares.ShareOf(id)
}

func (f *LinearDealerFunc[S, SV, LFTS, LFTSV, AC, ULDF, LFTUDF]) Repr() iter.Seq[SV] {
	return f.shares.Repr()
}

func (f *LinearDealerFunc[S, SV, LFTS, LFTSV, AC, ULDF, LFTUDF]) BlindingRepr() iter.Seq[SV] {
	return f.blinding.Repr()
}

func (f *LinearDealerFunc[S, SV, LFTS, LFTSV, AC, ULDF, LFTUDF]) Accepts(ac AC) bool {
	return f.shares.Accepts(ac)
}

func (f *LinearDealerFunc[S, SV, LFTS, LFTSV, AC, ULDF, LFTUDF]) LiftWithDifferentBasePoints(b1, b2 LFTSV) (*DealerFunc[LFTS, LFTSV, AC, LFTUDF], error) {
	liftedShares, err := f.shares.Lift(b1)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to lift shares")
	}
	liftedBlinding, err := f.blinding.Lift(b2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to lift blinding shares")
	}
	return &DealerFunc[LFTS, LFTSV, AC, LFTUDF]{
		shares:   liftedShares,
		blinding: liftedBlinding,
	}, nil
}

func (f *LinearDealerFunc[S, SV, LFTS, LFTSV, AC, ULDF, LFTUDF]) Lift(basePoint LFTSV) (*DealerFunc[LFTS, LFTSV, AC, LFTUDF], error) {
	return f.LiftWithDifferentBasePoints(basePoint, basePoint)
}

func (f *LinearDealerFunc[S, SV, LFTS, LFTSV, AC, ULDF, LFTUDF]) Op(other *LinearDealerFunc[S, SV, LFTS, LFTSV, AC, ULDF, LFTUDF]) *LinearDealerFunc[S, SV, LFTS, LFTSV, AC, ULDF, LFTUDF] {
	return &LinearDealerFunc[S, SV, LFTS, LFTSV, AC, ULDF, LFTUDF]{
		shares:   f.shares.Op(other.shares),
		blinding: f.blinding.Op(other.blinding),
	}
}
