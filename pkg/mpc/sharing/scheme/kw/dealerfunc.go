package kw

import (
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
)

// NewDealerFunc constructs a dealer function from a random column vector r and
// an MSP. It computes the share vector lambda = M * r, where M is the MSP
// matrix. The random column must have dimension D x 1, where D is the number
// of columns in M. The secret is implicitly defined as target * r, where
// target is the MSP's target (row) vector.
func NewDealerFunc[FE algebra.PrimeFieldElement[FE]](randomColumn *mat.Matrix[FE], mspMatrix *msp.MSP[FE]) (*DealerFunc[FE], error) {
	if mspMatrix == nil {
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
	lambda, err := mspMatrix.Matrix().TryMul(randomColumn)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute lambda = M * r")
	}
	return &DealerFunc[FE]{
		randomColumn: randomColumn,
		msp:          mspMatrix,
		lambdaColumn: lambda,
	}, nil
}

// DealerFunc holds the dealer's internal state after dealing: the random
// column r, the MSP, and the share vector lambda = M * r. It exposes the
// secret (target * r) and individual shares (rows of lambda grouped by
// shareholder). This type is the scalar-domain counterpart of
// LiftedDealerFunc.
type DealerFunc[FE algebra.PrimeFieldElement[FE]] struct {
	randomColumn *mat.Matrix[FE]
	msp          *msp.MSP[FE]
	lambdaColumn *mat.Matrix[FE]
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
	lambdaI, err := d.lambdaColumn.SubMatrixGivenRows(sortedRows...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to extract lambda_i for shareholder %d", id)
	}
	return &Share[FE]{
		id: id,
		v:  slices.Collect(lambdaI.Iter()),
	}, nil
}

// RandomColumn returns the random column vector r used during dealing.
func (d *DealerFunc[FE]) RandomColumn() *mat.Matrix[FE] {
	return d.randomColumn
}

// MSP returns the monotone span programme associated with this dealing.
func (d *DealerFunc[FE]) MSP() *msp.MSP[FE] {
	return d.msp
}

// Lambda returns the full share vector lambda = M * r. Each entry lambda[i]
// is the share component corresponding to MSP row i.
func (d *DealerFunc[FE]) Lambda() *mat.Matrix[FE] {
	return d.lambdaColumn
}
