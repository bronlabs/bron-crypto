package feldman

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
)

// NewVerificationVector constructs a VerificationVector from a module-valued
// column matrix. If mspMatrix is non-nil the column length is validated against
// the MSP column count D; pass nil to skip that check (e.g. during
// deserialisation when the MSP is not yet available).
func NewVerificationVector[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](value *mat.ModuleValuedMatrix[E, FE], mspMatrix *msp.MSP[FE]) (*VerificationVector[E, FE], error) {
	if value == nil {
		return nil, sharing.ErrIsNil.WithMessage("verification vector value is nil")
	}
	if !value.IsColumnVector() {
		return nil, sharing.ErrValue.WithMessage("verification vector must be a column vector")
	}
	rows, _ := value.Dimensions()
	if mspMatrix != nil && rows != int(mspMatrix.D()) {
		return nil, sharing.ErrValue.WithMessage("verification vector length must match MSP column count")
	}
	return &VerificationVector[E, FE]{value: value}, nil
}

// VerificationVector is the public commitment V = [r]G published in Feldman
// VSS. It wraps a module-valued column matrix whose entries are the
// group-element lifts of the random column: V_j = [r_j]G for j = 0, …, D−1.
type VerificationVector[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	value *mat.ModuleValuedMatrix[E, FE]
}

type verificationVectorDTO[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	V *mat.ModuleValuedMatrix[E, FE] `cbor:"verification_vector"`
}

// Value returns the underlying module-valued column matrix.
func (v *VerificationVector[E, FE]) Value() *mat.ModuleValuedMatrix[E, FE] {
	return v.value
}

// Op performs component-wise group addition of two verification vectors, i.e. the group operation on the underlying module-valued matrices.
func (v *VerificationVector[E, FE]) Op(other *VerificationVector[E, FE]) (*VerificationVector[E, FE], error) {
	if v == nil || other == nil {
		return nil, sharing.ErrIsNil.WithMessage("verification vector is nil")
	}
	otherRows, otherColumns := other.value.Dimensions()
	thisRows, thisColumns := v.value.Dimensions()
	if otherColumns != thisColumns {
		return nil, sharing.ErrValue.WithMessage("verification vectors must have the same number of columns to be added")
	}
	if otherRows != thisRows {
		return nil, sharing.ErrValue.WithMessage("verification vectors must have the same number of rows to be added")
	}
	return &VerificationVector[E, FE]{
		value: v.value.Op(other.value),
	}, nil
}

// Equal reports whether two verification vectors have identical entries.
func (v *VerificationVector[E, FE]) Equal(other *VerificationVector[E, FE]) bool {
	if v == nil || other == nil {
		return v == other
	}
	return v.value.Equal(other.value)
}

// HashCode returns a hash derived from the verification vector entries.
func (v *VerificationVector[E, FE]) HashCode() base.HashCode {
	if v == nil {
		return base.HashCode(0)
	}
	return v.value.HashCode()
}

// MarshalCBOR serialises the verification vector to CBOR.
func (v *VerificationVector[E, FE]) MarshalCBOR() ([]byte, error) {
	dto := verificationVectorDTO[E, FE]{
		V: v.value,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal verification vector")
	}
	return data, nil
}

// UnmarshalCBOR deserialises a verification vector from CBOR, validating the
// result.
func (v *VerificationVector[E, FE]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*verificationVectorDTO[E, FE]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal verification vector")
	}
	vv, err := NewVerificationVector(dto.V, nil)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create verification vector from deserialized value")
	}
	v.value = vv.value
	return nil
}
