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

// NewDealerFunc creates a Pedersen dealer function from the secret (g) and
// blinding (h) KW dealer functions. Both must share the same MSP.
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

// DealerFunc holds the dealer's secret state after dealing: the secret random
// column r_g (with r_g[0] = secret) and the blinding random column r_h (with
// r_h[0] = blinding secret), along with the corresponding share vectors
// λ_g = M · r_g and λ_h = M · r_h. It must not be published.
type DealerFunc[FE algebra.PrimeFieldElement[FE]] struct {
	g *kw.DealerFunc[FE]
	h *kw.DealerFunc[FE]
}

// ShareOf computes the Pedersen share for the given shareholder by evaluating
// both the secret and blinding dealer functions at the shareholder's ID.
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

// Secret returns the dealt secret (r_g[0]).
func (df *DealerFunc[FE]) Secret() *kw.Secret[FE] {
	return df.g.Secret()
}

// G returns the secret (g) component of the dealer function.
func (df *DealerFunc[FE]) G() *kw.DealerFunc[FE] {
	return df.g
}

// H returns the blinding (h) component of the dealer function.
func (df *DealerFunc[FE]) H() *kw.DealerFunc[FE] {
	return df.h
}

// LiftDealerFunc lifts a scalar dealer function into the group by computing
// V = [r_g]G + [r_h]H, i.e. the component-wise Pedersen commitment of the
// secret and blinding random columns using the respective generators from the
// commitment key.
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

// NewLiftedDealerFunc creates a lifted dealer function from a public
// verification vector and the MSP. This is used during verification to
// compute the expected lifted shares via the left module action M_i · V.
func NewLiftedDealerFunc[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](verificationVector *VerificationVector[E, FE], mspMatrix *msp.MSP[FE]) (*LiftedDealerFunc[E, FE], error) {
	out, err := kw.NewLiftedDealerFunc(verificationVector, mspMatrix)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create lifted kw dealer func for Pedersen VSS")
	}
	return &LiftedDealerFunc[E, FE]{
		gh: out,
	}, nil
}

// LiftedDealerFunc is the group-element counterpart of DealerFunc. It holds
// the verification vector V = [r_g]G + [r_h]H and the MSP, enabling
// computation of lifted shares M_i · V for any shareholder i.
type LiftedDealerFunc[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	gh *kw.LiftedDealerFunc[E, FE]
}

// ShareOf computes the expected lifted share for the given shareholder via the
// left module action M_i · V. The result is a vector of Pedersen commitments,
// one per MSP row owned by the shareholder.
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

// VerificationVector returns the public verification vector V = [r_g]G + [r_h]H.
func (df *LiftedDealerFunc[E, FE]) VerificationVector() *VerificationVector[E, FE] {
	return df.gh.VerificationVector()
}
