package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/errs-go/errs"
)

type Share[US sharing.Share[US], USV algebra.PrimeFieldElement[USV]] struct {
	underlying US
	secret     []*pedcom.Message[USV]
	blinding   []*pedcom.Witness[USV]
}

type shareDTO[USV algebra.PrimeFieldElement[USV]] struct {
	ID       sharing.ID            `cbor:"sharingID"`
	Secret_  []*pedcom.Message[USV] `cbor:"secret"`
	Blinding []*pedcom.Witness[USV] `cbor:"blinding"`
}

// NewShare creates a new meta Pedersen share wrapping an underlying share with
// Pedersen commitment components (messages and witnesses).
func NewShare[US sharing.Share[US], USV algebra.PrimeFieldElement[USV]](
	underlying US,
	secret []*pedcom.Message[USV],
	blinding []*pedcom.Witness[USV],
) (*Share[US, USV], error) {
	if secret == nil {
		return nil, sharing.ErrIsNil.WithMessage("secret cannot be nil")
	}
	if blinding == nil {
		return nil, sharing.ErrIsNil.WithMessage("blinding cannot be nil")
	}
	if len(secret) != len(blinding) {
		return nil, sharing.ErrFailed.WithMessage("secret and blinding must have the same length")
	}
	return &Share[US, USV]{
		underlying: underlying,
		secret:     secret,
		blinding:   blinding,
	}, nil
}

// ID returns the shareholder identifier, delegated from the underlying share.
func (s *Share[US, USV]) ID() sharing.ID {
	return s.underlying.ID()
}

// Underlying returns the underlying share stored in this meta Pedersen share.
func (s *Share[US, USV]) Underlying() US {
	return s.underlying
}

// Blinding returns the blinding components of this share.
func (s *Share[US, USV]) Blinding() []*pedcom.Witness[USV] {
	if s == nil {
		return nil
	}
	return s.blinding
}

// Secret returns the secret components as Pedersen messages.
func (s *Share[US, USV]) Secret() []*pedcom.Message[USV] {
	if s == nil {
		return nil
	}
	return s.secret
}

// Op returns a new share with component-wise sums of secret and blinding.
// The underlying share is preserved from the receiver.
func (s *Share[US, USV]) Op(other *Share[US, USV]) *Share[US, USV] {
	if s.ID() != other.ID() {
		panic("cannot add shares with different IDs")
	}
	if len(s.secret) != len(other.secret) || len(s.blinding) != len(other.blinding) {
		panic("cannot add shares with different secret/blinding lengths")
	}
	outSecret := make([]*pedcom.Message[USV], len(s.secret))
	outBlinding := make([]*pedcom.Witness[USV], len(s.blinding))
	for i := range s.secret {
		outSecret[i] = s.secret[i].Op(other.secret[i])
		outBlinding[i] = s.blinding[i].Op(other.blinding[i])
	}
	return &Share[US, USV]{
		underlying: s.underlying,
		secret:     outSecret,
		blinding:   outBlinding,
	}
}

// Add returns a new share that is the component-wise sum of two shares.
func (s *Share[US, USV]) Add(other *Share[US, USV]) *Share[US, USV] {
	return s.Op(other)
}

// ScalarOp multiplies both secret and blinding components by a scalar.
// The underlying share is preserved from the receiver.
func (s *Share[US, USV]) ScalarOp(scalar USV) *Share[US, USV] {
	w2, err := pedcom.NewWitness(scalar)
	if err != nil {
		panic(sharing.ErrFailed.WithMessage("could not create witness from scalar: %v", err))
	}
	m2 := pedcom.NewMessage(scalar)
	outSecret := make([]*pedcom.Message[USV], len(s.secret))
	outBlinding := make([]*pedcom.Witness[USV], len(s.blinding))
	for i := range s.secret {
		outSecret[i] = s.secret[i].Mul(m2)
		outBlinding[i] = s.blinding[i].Mul(w2)
	}
	return &Share[US, USV]{
		underlying: s.underlying,
		secret:     outSecret,
		blinding:   outBlinding,
	}
}

// ScalarMul returns a new share with both components multiplied by a scalar.
func (s *Share[US, USV]) ScalarMul(scalar USV) *Share[US, USV] {
	return s.ScalarOp(scalar)
}

// HashCode returns a hash code for this share.
func (s *Share[US, USV]) HashCode() base.HashCode {
	out := base.HashCode(s.ID())
	for _, m := range s.secret {
		out = out.Combine(m.HashCode())
	}
	for _, w := range s.blinding {
		out = out.Combine(w.HashCode())
	}
	return out
}

// Equal returns true if two shares have the same ID, secret, and blinding components.
func (s *Share[US, USV]) Equal(other *Share[US, USV]) bool {
	if s == nil || other == nil {
		return s == other
	}
	if s.ID() != other.ID() {
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
func (s *Share[US, USV]) Bytes() []byte {
	panic("implement me")
}

// MarshalCBOR serialises the share. Note: the underlying share is not serialised;
// only the ID, secret, and blinding components are stored.
func (s *Share[US, USV]) MarshalCBOR() ([]byte, error) {
	dto := shareDTO[USV]{
		ID:       s.ID(),
		Secret_:  s.secret,
		Blinding: s.blinding,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal Pedersen Share")
	}
	return data, nil
}
