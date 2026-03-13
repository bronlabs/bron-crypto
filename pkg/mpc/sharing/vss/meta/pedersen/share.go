package pedersen

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
)

// Share represents a Pedersen VSS share consisting of a secret component f(i)
// and a blinding component r(i), where f and r are the dealing polynomials.
type Share[S algebra.PrimeFieldElement[S]] struct {
	id       sharing.ID
	secret   []*pedcom.Message[S]
	blinding []*pedcom.Witness[S]
}

type shareDTO[S algebra.PrimeFieldElement[S]] struct {
	ID       sharing.ID           `cbor:"sharingID"`
	Secret   []*pedcom.Message[S] `cbor:"secret"`
	Blinding []*pedcom.Witness[S] `cbor:"blinding"`
}

// NewShare creates a new Pedersen share with the given ID, secret, and blinding value.
// If an access structure is provided, validates that the ID is a valid shareholder.
func NewShare[S algebra.PrimeFieldElement[S]](id sharing.ID, secret, blinding *kw.Share[S], ac accessstructures.Linear) (*Share[S], error) {
	if secret == nil {
		return nil, sharing.ErrIsNil.WithMessage("secret cannot be nil")
	}
	if blinding == nil {
		return nil, sharing.ErrIsNil.WithMessage("blinding cannot be nil")
	}
	if len(secret.Value()) != len(blinding.Value()) {
		return nil, sharing.ErrFailed.WithMessage("secret and blinding must have the same length")
	}
	if ac != nil && !ac.Shareholders().Contains(id) {
		return nil, sharing.ErrUnauthorized.WithMessage("share ID %d is not a valid shareholder", id)
	}
	messages := sliceutils.Map(secret.Value(), func(secretValue S) *pedcom.Message[S] { return pedcom.NewMessage(secretValue) })
	witnesses, err := sliceutils.MapOrError(blinding.Value(), func(blindingValue S) (*pedcom.Witness[S], error) {
		return pedcom.NewWitness(blindingValue)
	})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create Pedersen witnesses")
	}

	return &Share[S]{
		id:       id,
		secret:   messages,
		blinding: witnesses,
	}, nil
}

// ID returns the shareholder identifier for this share.
func (s *Share[S]) ID() sharing.ID {
	return s.id
}

// Value returns the secret component f(i) of this share.
func (s *Share[S]) Value() []S {
	return sliceutils.Map(s.secret, func(m *pedcom.Message[S]) S { return m.Value() })
}

// Blinding returns the blinding component r(i) of this share.
func (s *Share[S]) Blinding() []*pedcom.Witness[S] {
	if s == nil {
		return nil
	}
	return s.blinding
}

// Secret returns the secret component as a Pedersen message.
func (s *Share[S]) Secret() []*pedcom.Message[S] {
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
	if len(s.secret) != len(other.secret) || len(s.blinding) != len(other.blinding) {
		panic("cannot add shares with different lengths of secret or blinding components")
	}
	secretsOut := make([]*pedcom.Message[S], len(s.secret))
	blindingsOut := make([]*pedcom.Witness[S], len(s.blinding))
	for i, si := range s.secret {
		secretsOut[i] = si.Op(other.secret[i])
		blindingsOut[i] = s.blinding[i].Op(other.blinding[i])
	}
	return &Share[S]{
		id:       s.id,
		secret:   secretsOut,
		blinding: blindingsOut,
	}
}

// Add returns a new share that is the component-wise sum of two shares.
// Both the secret and blinding components are added separately.
func (s *Share[S]) Add(other *Share[S]) *Share[S] {
	return s.Op(other)
}

// ScalarOp is an alias for ScalarMul.
// Panics if scalar is zero since Pedersen requires non-zero blinding factors.
func (s *Share[S]) ScalarOp(sc algebra.Numeric) *Share[S] {
	primeField := algebra.StructureMustBeAs[algebra.PrimeField[S]](s.secret[0].Value().Structure())
	scalar, err := primeField.FromBytesBE(sc.BytesBE())
	if err != nil {
		panic(err)
	}
	w2, err := pedcom.NewWitness(scalar)
	if err != nil {
		panic(sharing.ErrFailed.WithMessage("could not create witness from scalar: %v", err))
	}
	m2 := pedcom.NewMessage(scalar)
	return &Share[S]{
		id:       s.id,
		secret:   sliceutils.Map(s.secret, func(m *pedcom.Message[S]) *pedcom.Message[S] { return m.Mul(m2) }),
		blinding: sliceutils.Map(s.blinding, func(w *pedcom.Witness[S]) *pedcom.Witness[S] { return w.Mul(w2) }),
	}
}

// ScalarMul returns a new share with both components multiplied by a scalar.
func (s *Share[S]) ScalarMul(scalar algebra.Numeric) *Share[S] {
	return s.ScalarOp(scalar)
}

// HashCode returns a hash code for this share, for use in hash-based collections.
func (s *Share[S]) HashCode() base.HashCode {
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
func (s *Share[S]) Equal(other *Share[S]) bool {
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
		if !s.secret[i].Equal(other.secret[i]) || !s.blinding[i].Equal(other.blinding[i]) {
			return false
		}
	}
	return true
}

// MarshalCBOR serialises the share.
func (s *Share[S]) MarshalCBOR() ([]byte, error) {
	dto := shareDTO[S]{
		ID:       s.id,
		Secret:   s.secret,
		Blinding: s.blinding,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal Pedersen Share")
	}
	return data, nil
}

// UnmarshalCBOR deserializes the share.
func (s *Share[S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*shareDTO[S]](data)
	if err != nil {
		return err
	}
	if len(dto.Secret) != len(dto.Blinding) {
		return sharing.ErrFailed.WithMessage("secret and blinding must have the same length")
	}
	s.id = dto.ID
	s.secret = dto.Secret
	s.blinding = dto.Blinding
	return nil
}

func NewLiftedShare[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](id sharing.ID, v []*pedcom.Commitment[E, FE]) (*LiftedShare[E, FE], error) {
	if v == nil {
		return nil, sharing.ErrIsNil.WithMessage("commitments cannot be nil")
	}
	if id == 0 {
		return nil, sharing.ErrIsNil.WithMessage("share ID cannot be zero")
	}
	return &LiftedShare[E, FE]{
		id: id,
		v:  v,
	}, nil
}

func LiftShare[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](share *Share[FE], key *pedcom.Key[E, FE]) (*LiftedShare[E, FE], error) {
	if share == nil {
		return nil, sharing.ErrIsNil.WithMessage("share cannot be nil")
	}
	if key == nil {
		return nil, sharing.ErrIsNil.WithMessage("pedersen commitment key cannot be nil")
	}
	comScheme, err := pedcom.NewScheme(key)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create Pedersen commitment scheme for lifting share")
	}
	committer, err := comScheme.Committer()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create Pedersen committer for lifting share")
	}
	v := make([]*pedcom.Commitment[E, FE], len(share.secret))
	for i := range share.secret {
		v[i], err = committer.CommitWithWitness(share.secret[i], share.blinding[i])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create Pedersen commitment for share")
		}
	}
	return NewLiftedShare(share.ID(), v)
}

type LiftedShare[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	id sharing.ID
	v  []*pedcom.Commitment[E, FE]
}

type liftedShareDTO[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	ID sharing.ID                  `cbor:"sharingID"`
	V  []*pedcom.Commitment[E, FE] `cbor:"value"`
}

func (s *LiftedShare[E, FE]) ID() sharing.ID {
	return s.id
}

func (s *LiftedShare[E, FE]) Value() []*pedcom.Commitment[E, FE] {
	return s.v
}

func (s *LiftedShare[E, FE]) Equal(other *LiftedShare[E, FE]) bool {
	if s == nil || other == nil {
		return s == other
	}
	if s.id != other.id {
		return false
	}
	if len(s.v) != len(other.v) {
		return false
	}
	for i := range s.v {
		if !s.v[i].Equal(other.v[i]) {
			return false
		}
	}
	return true
}

func (s *LiftedShare[E, FE]) MarshalCBOR() ([]byte, error) {
	dto := liftedShareDTO[E, FE]{
		ID: s.id,
		V:  s.v,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal Pedersen LiftedShare")
	}
	return data, nil
}

func (s *LiftedShare[E, FE]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*liftedShareDTO[E, FE]](data)
	if err != nil {
		return err
	}

	s2, err := NewLiftedShare(dto.ID, dto.V)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create LiftedShare from unmarshaled data")
	}

	*s = *s2
	return nil
}
