package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/errs-go/errs"
)

type Share[SV algebra.PrimeFieldElement[SV]] struct {
	id       sharing.ID
	secret   []*pedcom.Message[SV]
	blinding []*pedcom.Witness[SV]
}

type shareDTO[SV algebra.PrimeFieldElement[SV]] struct {
	ID       sharing.ID            `cbor:"sharingID"`
	Secret_  []*pedcom.Message[SV] `cbor:"secret"`
	Blinding []*pedcom.Witness[SV] `cbor:"blinding"`
}

// NewShare creates a new Pedersen share with the given ID, secret, and blinding value.
// If an access structure is provided, validates that the ID is a valid shareholder.
func NewShare[SV algebra.PrimeFieldElement[SV]](id sharing.ID, secret []*pedcom.Message[SV], blinding []*pedcom.Witness[SV], ac *accessstructures.Threshold) (*Share[SV], error) {
	if secret == nil {
		return nil, sharing.ErrIsNil.WithMessage("secret cannot be nil")
	}
	if blinding == nil {
		return nil, sharing.ErrIsNil.WithMessage("blinding cannot be nil")
	}
	if len(secret) != len(blinding) {
		return nil, sharing.ErrFailed.WithMessage("secret and blinding must have the same length")
	}
	if ac != nil && !ac.Shareholders().Contains(id) {
		return nil, sharing.ErrMembership.WithMessage("share ID %d is not a valid shareholder", id)
	}
	return &Share[SV]{
		id:       id,
		secret:   secret,
		blinding: blinding,
	}, nil
}

// ID returns the shareholder identifier for this share.
func (s *Share[SV]) ID() sharing.ID {
	return s.id
}

// Blinding returns the blinding component r(i) of this share.
func (s *Share[SV]) Blinding() []*pedcom.Witness[SV] {
	if s == nil {
		return nil
	}
	return s.blinding
}

// Secret returns the secret component as a Pedersen message.
func (s *Share[SV]) Secret() []*pedcom.Message[SV] {
	if s == nil {
		return nil
	}
	return s.secret
}

// Op is an alias for Add, implementing the group element interface.
func (s *Share[SV]) Op(other *Share[SV]) *Share[SV] {
	if s.id != other.id {
		panic("cannot add shares with different IDs")
	}
	if len(s.secret) != len(other.secret) || len(s.blinding) != len(other.blinding) {
		panic("cannot add shares with different secret/blinding lengths")
	}
	outSecret := make([]*pedcom.Message[SV], len(s.secret))
	outBlinding := make([]*pedcom.Witness[SV], len(s.blinding))
	for i := range s.secret {
		outSecret[i] = s.secret[i].Op(other.secret[i])
		outBlinding[i] = s.blinding[i].Op(other.blinding[i])
	}
	return &Share[SV]{
		id:       s.id,
		secret:   outSecret,
		blinding: outBlinding,
	}
}

// Add returns a new share that is the component-wise sum of two shares.
// Both the secret and blinding components are added separately.
func (s *Share[SV]) Add(other *Share[SV]) *Share[SV] {
	return s.Op(other)
}

// ScalarOp is an alias for ScalarMul.
// Panics if scalar is zero since Pedersen requires non-zero blinding factors.
func (s *Share[SV]) ScalarOp(scalar SV) *Share[SV] {
	w2, err := pedcom.NewWitness(scalar)
	if err != nil {
		panic(sharing.ErrFailed.WithMessage("could not create witness from scalar: %v", err))
	}
	m2 := pedcom.NewMessage(scalar)
	outSecret := make([]*pedcom.Message[SV], len(s.secret))
	outBlinding := make([]*pedcom.Witness[SV], len(s.blinding))
	for i := range s.secret {
		outSecret[i] = s.secret[i].Mul(m2)
		outBlinding[i] = s.blinding[i].Mul(w2)
	}
	return &Share[SV]{
		id:       s.id,
		secret:   outSecret,
		blinding: outBlinding,
	}
}

// ScalarMul returns a new share with both components multiplied by a scalar.
func (s *Share[SV]) ScalarMul(scalar SV) *Share[SV] {
	return s.ScalarOp(scalar)
}

// HashCode returns a hash code for this share, for use in hash-based collections.
func (s *Share[SV]) HashCode() base.HashCode {
	out := base.HashCode(s.id)
	for _, m := range s.secret {
		out = out.Combine(m.HashCode())
	}
	for _, w := range s.blinding {
		out = out.Combine(w.HashCode())
	}
	return out
}

// Equal returns true if two shares have the same secret and blinding components.
func (s *Share[SV]) Equal(other *Share[SV]) bool {
	if s == nil || other == nil {
		return s == other
	}
	if s.id != other.id {
		return false
	}
	if len(s.secret) != len(other.secret) || len(s.blinding) != len(other.blinding) {
		return false
	}
	for i := range s.secret {
		if !s.secret[i].Equal(other.secret[i]) {
			return false
		}
	}
	for i := range s.blinding {
		if !s.blinding[i].Equal(other.blinding[i]) {
			return false
		}
	}
	return true
}

// Bytes returns the canonical byte representation of this share.
func (s *Share[SV]) Bytes() []byte {
	panic("implement me")
}

// ToAdditive converts this Pedersen share to an additive share by multiplying
// the secret component by the appropriate Lagrange coefficient. The blinding
// component is discarded. The resulting additive shares can be summed to
// reconstruct the secret.
func (s *Share[SV]) ToAdditive(qualifiedSet *accessstructures.Unanimity) (*additive.Share[SV], error) {
	panic("implement me")
}

// MarshalCBOR serialises the share.
func (s *Share[SV]) MarshalCBOR() ([]byte, error) {
	dto := shareDTO[SV]{
		ID:       s.id,
		Secret_:  s.secret,
		Blinding: s.blinding,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal Pedersen Share")
	}
	return data, nil
}

// UnmarshalCBOR deserializes the share.
func (s *Share[SV]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*shareDTO[SV]](data)
	if err != nil {
		return err
	}

	s2, err := NewShare(dto.ID, dto.Secret_, dto.Blinding, nil)
	if err != nil {
		return err
	}
	*s = *s2
	return nil
}
