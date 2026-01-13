package pedersen

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

// Share represents a Pedersen VSS share consisting of a secret component f(i)
// and a blinding component r(i), where f and r are the dealing polynomials.
type Share[S algebra.PrimeFieldElement[S]] struct {
	id       sharing.ID
	secret   *pedcom.Message[S]
	blinding *pedcom.Witness[S]
}

type shareDTO[S algebra.PrimeFieldElement[S]] struct {
	ID       sharing.ID         `cbor:"sharingId"`
	Secret_  *pedcom.Message[S] `cbor:"secret"`
	Blinding *pedcom.Witness[S] `cbor:"blinding"`
}

// NewShare creates a new Pedersen share with the given ID, secret, and blinding value.
// If an access structure is provided, validates that the ID is a valid shareholder.
func NewShare[S algebra.PrimeFieldElement[S]](id sharing.ID, secret *pedcom.Message[S], blinding *pedcom.Witness[S], ac *sharing.ThresholdAccessStructure) (*Share[S], error) {
	if secret == nil {
		return nil, ErrIsNil.WithMessage("secret cannot be nil")
	}
	if blinding == nil {
		return nil, ErrIsNil.WithMessage("blinding cannot be nil")
	}
	if ac != nil && !ac.Shareholders().Contains(id) {
		return nil, ErrMembership.WithMessage("share ID %d is not a valid shareholder", id)
	}
	return &Share[S]{
		id:       id,
		secret:   secret,
		blinding: blinding,
	}, nil
}

// ID returns the shareholder identifier for this share.
func (s *Share[S]) ID() sharing.ID {
	return s.id
}

// Value returns the secret component f(i) of this share.
func (s *Share[S]) Value() S {
	return s.secret.Value()
}

// Blinding returns the blinding component r(i) of this share.
func (s *Share[S]) Blinding() *pedcom.Witness[S] {
	if s == nil {
		return nil
	}
	return s.blinding
}

// Secret returns the secret component as a Pedersen message.
func (s *Share[S]) Secret() *pedcom.Message[S] {
	if s == nil {
		return nil
	}
	return s.secret
}

// Op is an alias for Add, implementing the group element interface.
func (s *Share[S]) Op(other *Share[S]) *Share[S] {
	if s.id != other.id {
		panic("cannot add shares with different IDs")
	}
	return &Share[S]{
		id:       s.id,
		secret:   s.secret.Op(other.secret),
		blinding: s.blinding.Op(other.blinding),
	}
}

// Add returns a new share that is the component-wise sum of two shares.
// Both the secret and blinding components are added separately.
func (s *Share[S]) Add(other *Share[S]) *Share[S] {
	return s.Op(other)
}

// ScalarOp is an alias for ScalarMul.
// Panics if scalar is zero since Pedersen requires non-zero blinding factors.
func (s *Share[S]) ScalarOp(scalar S) *Share[S] {
	// Special case: multiplying by zero is not supported in Pedersen VSS
	// because it would require a zero blinding factor, which is not allowed
	if scalar.IsZero() {
		panic(ErrIsZero.WithMessage("cannot multiply Pedersen share by zero - zero blinding factors are not allowed"))
	}

	w2, err := pedcom.NewWitness(scalar)
	if err != nil {
		panic(ErrFailed.WithMessage("could not create witness from scalar: %v", err))
	}
	m2 := pedcom.NewMessage(scalar)
	return &Share[S]{
		id:       s.id,
		secret:   s.secret.Mul(m2),
		blinding: s.blinding.Mul(w2),
	}
}

// ScalarMul returns a new share with both components multiplied by a scalar.
func (s *Share[S]) ScalarMul(scalar S) *Share[S] {
	return s.ScalarOp(scalar)
}

// HashCode returns a hash code for this share, for use in hash-based collections.
func (s *Share[S]) HashCode() base.HashCode {
	return s.secret.HashCode() ^ s.blinding.HashCode()
}

// Equal returns true if two shares have the same secret and blinding components.
func (s *Share[S]) Equal(other *Share[S]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.id == other.id && s.secret.Equal(other.secret) && s.blinding.Equal(other.blinding)
}

// Bytes returns the canonical byte representation of this share.
func (s *Share[S]) Bytes() []byte {
	return slices.Concat(
		s.secret.Value().Bytes(),
		s.blinding.Value().Bytes(),
	)
}

// ToAdditive converts this Pedersen share to an additive share by multiplying
// the secret component by the appropriate Lagrange coefficient. The blinding
// component is discarded. The resulting additive shares can be summed to
// reconstruct the secret.
func (s *Share[S]) ToAdditive(qualifiedSet *sharing.MinimalQualifiedAccessStructure) (*additive.Share[S], error) {
	ss, err := shamir.NewShare(s.id, s.secret.Value(), nil)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not create shamir share from share")
	}
	additiveShare, err := ss.ToAdditive(qualifiedSet)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to convert Pedersen share to additive")
	}
	return additiveShare, nil
}

func (s *Share[S]) MarshalCBOR() ([]byte, error) {
	dto := shareDTO[S]{
		ID:       s.id,
		Secret_:  s.secret,
		Blinding: s.blinding,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to marshal Pedersen Share")
	}
	return data, nil
}

func (s *Share[S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*shareDTO[S]](data)
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
