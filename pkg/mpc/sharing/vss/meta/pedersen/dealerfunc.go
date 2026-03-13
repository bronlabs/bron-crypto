package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
	"github.com/bronlabs/errs-go/errs"
)

func NewDealerFunc[FE algebra.PrimeFieldElement[FE]](g, h *kw.DealerFunc[FE]) (*DealerFunc[FE], error) {
	if g == nil {
		return nil, sharing.ErrIsNil.WithMessage("g dealer func is nil")
	}
	if h == nil {
		return nil, sharing.ErrIsNil.WithMessage("h dealer func is nil")
	}
	return &DealerFunc[FE]{
		g: g,
		h: h,
	}, nil
}

type DealerFunc[FE algebra.PrimeFieldElement[FE]] struct {
	g *kw.DealerFunc[FE]
	h *kw.DealerFunc[FE]
}

func (df *DealerFunc[FE]) ShareOf(id sharing.ID) (*Share[FE], error) {
	secretShare, err := df.g.ShareOf(id)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not get secret share from g dealer func")
	}
	blindingShare, err := df.h.ShareOf(id)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not get blinding share from h dealer func")
	}
	return NewShare(id, secretShare, blindingShare, nil)
}

func (df *DealerFunc[FE]) Secret() *kw.Secret[FE] {
	return df.g.Secret()
}

func (df *DealerFunc[FE]) G() *kw.DealerFunc[FE] {
	return df.g
}

func (df *DealerFunc[FE]) H() *kw.DealerFunc[FE] {
	return df.h
}

func LiftDealerFunc[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](df *DealerFunc[FE], key *pedcom.Key[E, FE]) (*LiftedDealerFunc[E, FE], error) {
	if df == nil {
		return nil, sharing.ErrIsNil.WithMessage("dealer func is nil")
	}
	if key == nil {
		return nil, sharing.ErrIsNil.WithMessage("pedersen commitment key is nil")
	}
	g, err := kw.LiftDealerFunc(df.g, key.G())
	if err != nil {
		return nil, err
	}
	h, err := kw.LiftDealerFunc(df.h, key.H())
	if err != nil {
		return nil, err
	}
	out, err := kw.NewLiftedDealerFunc(g.VerificationVector().Op(h.VerificationVector()), g.MSP())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create lifted kw dealer func for Pedersen VSS")
	}
	return &LiftedDealerFunc[E, FE]{
		gh: out,
	}, nil
}

func NewLiftedDealerFunc[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](verificationVector *VerificationVector[E, FE], mspMatrix *msp.MSP[FE]) (*LiftedDealerFunc[E, FE], error) {
	out, err := kw.NewLiftedDealerFunc(verificationVector, mspMatrix)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create lifted kw dealer func for Pedersen VSS")
	}
	return &LiftedDealerFunc[E, FE]{
		gh: out,
	}, nil
}

type LiftedDealerFunc[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	gh *kw.LiftedDealerFunc[E, FE]
}

func (df *LiftedDealerFunc[E, FE]) ShareOf(id sharing.ID) (*LiftedShare[E, FE], error) {
	kwShare, err := df.gh.ShareOf(id)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not get lifted share from lifted kw dealer func")
	}
	v, err := sliceutils.MapOrError(kwShare.Value(), func(elem E) (*pedcom.Commitment[E, FE], error) { return pedcom.NewCommitment(elem) })
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create Pedersen commitment from lifted lambda element")
	}
	return &LiftedShare[E, FE]{
		id: id,
		v:  v,
	}, nil
}

func (df *LiftedDealerFunc[E, FE]) VerificationVector() *VerificationVector[E, FE] {
	return df.gh.VerificationVector()
}
