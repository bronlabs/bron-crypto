package feldman

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
	"github.com/bronlabs/errs-go/errs"
)

type (
	// DealerFunc holds the dealer's secret state after dealing: the random
	// column vector r and the share vector λ = M · r. It is a type alias
	// for the underlying KW dealer function.
	DealerFunc[FE algebra.PrimeFieldElement[FE]] = kw.DealerFunc[FE]
)

// LiftDealerFunc lifts a scalar-domain DealerFunc into a prime-order group by
// computing [r_i] * basePoint for each entry of both the random column r and
// the share vector lambda. The resulting LiftedDealerFunc contains the
// verification vector ([r_0]G, ..., [r_{d-1}]G) and the lifted share vector
// ([lambda_0]G, ..., [lambda_{n-1}]G). This is the trusted-dealer path: the
// caller has access to the scalar r.
func LiftDealerFunc[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](df *DealerFunc[FE], basePoint E) (*LiftedDealerFunc[E, FE], error) {
	if df == nil {
		return nil, sharing.ErrIsNil.WithMessage("DealerFunc cannot be nil")
	}
	if utils.IsNil(basePoint) {
		return nil, sharing.ErrIsNil.WithMessage("basePoint cannot be nil")
	}
	liftedRandomColumn, err := mat.Lift(df.RandomColumn(), basePoint)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to lift random column")
	}
	liftedLambda, err := mat.Lift(df.Lambda(), basePoint)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to lift lambda matrix")
	}
	return &LiftedDealerFunc[E, FE]{
		verificationVector: &VerificationVector[E, FE]{value: liftedRandomColumn},
		mspMatrix:          df.MSP(),
		liftedLambda:       liftedLambda,
	}, nil
}

// NewLiftedDealerFunc constructs a LiftedDealerFunc from a public verification
// vector and an MSP, without knowledge of the scalar random column r. The
// lifted share vector is computed as the left module action M * V, where M is
// the MSP matrix and V is the verification vector (column of group elements).
// This is the verifier path used in Feldman VSS: given only the public
// verification vector, any party can derive the expected lifted share for a
// shareholder and compare it against the manually lifted scalar share.
func NewLiftedDealerFunc[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](verificationVector *VerificationVector[E, FE], mspMatrix *msp.MSP[FE]) (*LiftedDealerFunc[E, FE], error) {
	if verificationVector == nil {
		return nil, sharing.ErrIsNil.WithMessage("verificationVector cannot be nil")
	}
	if mspMatrix == nil {
		return nil, sharing.ErrIsNil.WithMessage("MSP cannot be nil")
	}
	if !verificationVector.value.IsColumnVector() {
		return nil, sharing.ErrValue.WithMessage("verificationVector must be a column vector")
	}
	// Dimension enforcement in LeftAction implicitly prevents the Dahlgren attack
	// (https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/)
	// by rejecting verification vectors whose length does not match the MSP
	// column count.
	liftedLambda, err := mat.LeftAction(mspMatrix.Matrix(), verificationVector.value)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute lifted lambda = M * lifted random column")
	}
	return &LiftedDealerFunc[E, FE]{
		verificationVector: verificationVector,
		mspMatrix:          mspMatrix,
		liftedLambda:       liftedLambda,
	}, nil
}

// LiftedDealerFunc is the group-element counterpart of DealerFunc. It holds
// the verification vector V = ([r_0]G, ..., [r_{d-1}]G), the MSP, and the
// lifted share vector [lambda]G = M * V (computed via the left module action).
// A verifier who knows only V and the MSP can derive expected lifted shares
// without access to the scalar r.
type LiftedDealerFunc[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	verificationVector *VerificationVector[E, FE]
	mspMatrix          *msp.MSP[FE]
	liftedLambda       *mat.ModuleValuedMatrix[E, FE]
}

// LiftedSecret returns the group element [secret]G, computed as the left
// module action of the MSP target vector on the verification vector:
// target * V = sum_i target[i] * V[i]. For the standard target e_0 this
// reduces to V[0] = [r_0]G.
func (d *LiftedDealerFunc[E, FE]) LiftedSecret() *LiftedSecret[E, FE] {
	liftedSecretMat, err := mat.LeftAction(d.mspMatrix.TargetVector(), d.verificationVector.value)
	if err != nil {
		panic(errs.Wrap(err).WithMessage("failed to compute lifted secret = target * lifted_r"))
	}
	v, err := liftedSecretMat.Get(0, 0)
	if err != nil {
		panic(errs.Wrap(err).WithMessage("failed to get lifted secret from target * lifted_r result"))
	}
	return NewLiftedSecret(v)
}

// ShareOf returns the lifted share for the given shareholder. It extracts
// the rows of the lifted share vector [lambda]G that belong to the
// shareholder (sorted by ascending MSP row index). In Feldman VSS, this
// value is compared against the manually lifted scalar share [lambda_i]G
// to verify correctness.
func (d *LiftedDealerFunc[E, FE]) ShareOf(id sharing.ID) (*LiftedShare[E, FE], error) {
	rowsi, exists := d.mspMatrix.HoldersToRows().Get(id)
	if !exists {
		return nil, sharing.ErrMembership.WithMessage("shareholder %d is not in the MSP holders mapping", id)
	}
	sortedRows := slices.Sorted(slices.Values(rowsi.List()))
	lambdaI, err := d.liftedLambda.SubMatrixGivenRows(sortedRows...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to extract lambda_i for shareholder %d", id)
	}
	return &LiftedShare[E, FE]{
		id: id,
		v:  slices.Collect(lambdaI.Iter()),
	}, nil
}

// MSP returns the monotone span programme associated with this dealing.
func (d *LiftedDealerFunc[E, FE]) MSP() *msp.MSP[FE] {
	return d.mspMatrix
}

// VerificationVector returns the verification vector V = ([r_0]G, ..., [r_{d-1}]G),
// the lifted random column used during dealing. This is the public commitment
// published in Feldman VSS.
func (d *LiftedDealerFunc[E, FE]) VerificationVector() *VerificationVector[E, FE] {
	return d.verificationVector
}

// Lambda returns the full lifted share vector [lambda]G = M * V. Each entry
// is the group element [lambda_i]G for MSP row i.
func (d *LiftedDealerFunc[E, FE]) Lambda() *mat.ModuleValuedMatrix[E, FE] {
	return d.liftedLambda
}
