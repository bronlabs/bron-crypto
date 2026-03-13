package kw

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
	"github.com/bronlabs/errs-go/errs"
)

// NewDealerFunc constructs a dealer function from a random column vector r and
// an MSP. It computes the share vector lambda = M * r, where M is the MSP
// matrix. The random column must have dimension D x 1, where D is the number
// of columns in M. The secret is implicitly defined as target * r, where
// target is the MSP's target (row) vector.
func NewDealerFunc[FE algebra.PrimeFieldElement[FE]](randomColumn *mat.ColumnVector[FE], msp *msp.MSP[FE]) (*DealerFunc[FE], error) {
	if msp == nil {
		return nil, sharing.ErrIsNil.WithMessage("MSP cannot be nil")
	}
	if randomColumn == nil {
		return nil, sharing.ErrIsNil.WithMessage("randomColumn cannot be nil")
	}
	if !randomColumn.IsColumnVector() {
		return nil, sharing.ErrValue.WithMessage("randomColumn must be a column vector")
	}
	rows, _ := randomColumn.Dimensions()
	if rows < 2 {
		return nil, sharing.ErrValue.WithMessage("randomColumn must have at least 2 rows")
	}
	lambda, err := msp.Matrix().TryMul(randomColumn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute lambda = M * r")
	}
	return &DealerFunc[FE]{
		randomColumn: randomColumn,
		msp:          msp,
		lambda:       lambda,
	}, nil
}

// DealerFunc holds the dealer's internal state after dealing: the random
// column r, the MSP, and the share vector lambda = M * r. It exposes the
// secret (target * r) and individual shares (rows of lambda grouped by
// shareholder). This type is the scalar-domain counterpart of
// LiftedDealerFunc.
type DealerFunc[FE algebra.PrimeFieldElement[FE]] struct {
	randomColumn *mat.ColumnVector[FE]
	msp          *msp.MSP[FE]
	lambda       *mat.ColumnVector[FE]
}

// Secret returns the shared secret, computed as target * r where target is
// the MSP's target (row) vector and r is the random column. For the standard
// target vector e_0 = (1, 0, ..., 0) this equals r[0].
func (d *DealerFunc[FE]) Secret() *Secret[FE] {
	secretMat, err := d.msp.TargetVector().TryMul(d.randomColumn)
	if err != nil {
		panic(errs.Wrap(err).WithMessage("failed to compute secret = target * r"))
	}
	v, err := secretMat.Get(0, 0)
	if err != nil {
		panic(errs.Wrap(err).WithMessage("failed to get secret from target * r result"))
	}
	return NewSecret(v)
}

// ShareOf returns the share for the given shareholder. It extracts the rows
// of lambda = M * r that belong to the shareholder (sorted by ascending MSP
// row index) and packages them into a Share.
func (d *DealerFunc[FE]) ShareOf(id sharing.ID) (*Share[FE], error) {
	rowsi, exists := d.msp.HoldersToRows().Get(id)
	if !exists {
		return nil, sharing.ErrMembership.WithMessage("shareholder %d is not in the MSP holders mapping", id)
	}
	sortedRows := slices.Sorted(slices.Values(rowsi.List()))
	lambdaI, err := d.lambda.SubMatrixGivenRows(sortedRows...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to extract lambda_i for shareholder %d", id)
	}
	return &Share[FE]{
		id: id,
		v:  slices.Collect(lambdaI.Iter()),
	}, nil
}

// RandomColumn returns the random column vector r used during dealing.
func (d *DealerFunc[FE]) RandomColumn() *mat.ColumnVector[FE] {
	return d.randomColumn
}

// MSP returns the monotone span programme associated with this dealing.
func (d *DealerFunc[FE]) MSP() *msp.MSP[FE] {
	return d.msp
}

// Lambda returns the full share vector lambda = M * r. Each entry lambda[i]
// is the share component corresponding to MSP row i.
func (d *DealerFunc[FE]) Lambda() *mat.ColumnVector[FE] {
	return d.lambda
}

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
		verificationVector: liftedRandomColumn,
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
//
// Dimension enforcement in LeftAction implicitly prevents the Dahlgren attack
// (https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/)
// by rejecting verification vectors whose length does not match the MSP
// column count.
func NewLiftedDealerFunc[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](verificationVector *mat.ModuleValuedColumnVector[E, FE], mspMatrix *msp.MSP[FE]) (*LiftedDealerFunc[E, FE], error) {
	if verificationVector == nil {
		return nil, sharing.ErrIsNil.WithMessage("verificationVector cannot be nil")
	}
	if mspMatrix == nil {
		return nil, sharing.ErrIsNil.WithMessage("MSP cannot be nil")
	}
	liftedLambda, err := mat.LeftAction(mspMatrix.Matrix(), verificationVector)
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
	verificationVector *mat.ModuleValuedColumnVector[E, FE]
	mspMatrix          *msp.MSP[FE]
	liftedLambda       *mat.ModuleValuedColumnVector[E, FE]
}

// LiftedSecret returns the group element [secret]G, computed as the left
// module action of the MSP target vector on the verification vector:
// target * V = sum_i target[i] * V[i]. For the standard target e_0 this
// reduces to V[0] = [r_0]G.
func (d *LiftedDealerFunc[E, FE]) LiftedSecret() *LiftedSecret[E, FE] {
	liftedSecretMat, err := mat.LeftAction(d.mspMatrix.TargetVector(), d.verificationVector)
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
func (d *LiftedDealerFunc[E, FE]) VerificationVector() *mat.ModuleValuedColumnVector[E, FE] {
	return d.verificationVector
}

// Lambda returns the full lifted share vector [lambda]G = M * V. Each entry
// is the group element [lambda_i]G for MSP row i.
func (d *LiftedDealerFunc[E, FE]) Lambda() *mat.ModuleValuedColumnVector[E, FE] {
	return d.liftedLambda
}
