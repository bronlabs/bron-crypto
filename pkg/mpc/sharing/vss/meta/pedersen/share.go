package pedersen

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/errs-go/errs"
)

type Share[US sharing.LinearShare[US, USV], USV algebra.PrimeFieldElement[USV]] struct {
	secret   US
	blinding US
}

type shareDTO[US sharing.LinearShare[US, USV], USV algebra.PrimeFieldElement[USV]] struct {
	ID       sharing.ID `cbor:"sharingID"`
	Secret   US         `cbor:"secret"`
	Blinding US         `cbor:"blinding"`
}

// NewShare creates a new meta Pedersen share wrapping an underlying share with
// Pedersen commitment components (messages and witnesses).
func NewShare[US sharing.LinearShare[US, USV], USV algebra.PrimeFieldElement[USV]](
	secret, blinding US,
) (*Share[US, USV], error) {
	if utils.IsNil(secret) {
		return nil, sharing.ErrIsNil.WithMessage("secret cannot be nil")
	}
	if utils.IsNil(blinding) {
		return nil, sharing.ErrIsNil.WithMessage("blinding cannot be nil")
	}
	if secret.ID() != blinding.ID() {
		return nil, sharing.ErrValue.WithMessage("secret and blinding must have the same ID")
	}
	if len(slices.Collect(secret.Repr())) != len(slices.Collect(blinding.Repr())) {
		return nil, sharing.ErrValue.WithMessage("secret and blinding must have the same number of components")
	}
	return &Share[US, USV]{
		secret:   secret,
		blinding: blinding,
	}, nil
}

// ID returns the shareholder identifier, delegated from the underlying share.
func (s *Share[US, USV]) ID() sharing.ID {
	return s.secret.ID()
}

// Blinding returns the blinding components of this share.
func (s *Share[US, USV]) Blinding() US {
	return s.blinding
}

// Secret returns the secret components as Pedersen messages.
func (s *Share[US, USV]) Secret() US {
	return s.secret
}

// Op returns a new share with component-wise sums of secret and blinding.
// The underlying share is preserved from the receiver.
func (s *Share[US, USV]) Op(other *Share[US, USV]) *Share[US, USV] {
	if s.ID() != other.ID() {
		panic("cannot add shares with different IDs")
	}
	return &Share[US, USV]{
		secret:   s.secret.Op(other.secret),
		blinding: s.blinding.Op(other.blinding),
	}
}

// Add returns a new share that is the component-wise sum of two shares.
func (s *Share[US, USV]) Add(other *Share[US, USV]) *Share[US, USV] {
	return s.Op(other)
}

// ScalarOp multiplies both secret and blinding components by a scalar.
// The underlying share is preserved from the receiver.
func (s *Share[US, USV]) ScalarOp(scalar USV) *Share[US, USV] {
	return &Share[US, USV]{
		secret:   s.secret.ScalarOp(scalar),
		blinding: s.blinding.ScalarOp(scalar),
	}
}

// ScalarMul returns a new share with both components multiplied by a scalar.
func (s *Share[US, USV]) ScalarMul(scalar USV) *Share[US, USV] {
	return s.ScalarOp(scalar)
}

// HashCode returns a hash code for this share.
func (s *Share[US, USV]) HashCode() base.HashCode {
	return base.HashCode(s.ID()).Combine(s.secret.HashCode(), s.blinding.HashCode())
}

// Equal returns true if two shares have the same ID, secret, and blinding components.
func (s *Share[US, USV]) Equal(other *Share[US, USV]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.ID() == other.ID() && s.secret.Equal(other.secret) && s.blinding.Equal(other.blinding)
}

// MarshalCBOR serialises the share. Note: the underlying share is not serialised;
// only the ID, secret, and blinding components are stored.
func (s *Share[US, USV]) MarshalCBOR() ([]byte, error) {
	dto := shareDTO[US, USV]{
		ID:       s.ID(),
		Secret:   s.secret,
		Blinding: s.blinding,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal Pedersen Share")
	}
	return data, nil
}

func (s *Share[US, USV]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[shareDTO[US, USV]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal Pedersen Share")
	}
	share, err := NewShare(dto.Secret, dto.Blinding)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid data for Pedersen Share")
	}
	*s = *share
	return nil
}
