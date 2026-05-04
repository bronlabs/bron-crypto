package intcom

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/commitments/internal"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/errs"
	"golang.org/x/sync/errgroup"
)

func SampleCommitmentKey(keyLen uint, prng io.Reader) (*CommitmentKey, error) {
	_, s, t, _, err := SamplePedersenParameters(keyLen, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to sample Pedersen parameters")
	}
	out, err := newCommitmentKey(s, t)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create Pedersen commitment key")
	}
	return out, nil
}

func ExtractCommitmentKey[A znstar.ArithmeticRSA](transcript ts.Transcript, label string, group *znstar.RSAGroup[A]) (*CommitmentKey, error) {
	if transcript == nil {
		return nil, ErrInvalidArgument.WithMessage("transcript cannot be nil")
	}
	if label == "" {
		return nil, ErrInvalidArgument.WithMessage("label cannot be empty")
	}
	if group == nil {
		return nil, ErrInvalidArgument.WithMessage("group cannot be nil")
	}
	var s, t *znstar.RSAGroupElement[A]
	eg := errgroup.Group{}
	eg.Go(func() error {
		for {
			counter := 0
			sSqrt, err := ts.Extract(transcript, fmt.Sprintf("s_%s_%d", label, counter), group)
			if err != nil {
				return errs.Wrap(err).WithMessage("failed to extract sSqrt for pedersen key")
			}
			s = sSqrt.Mul(sSqrt)
			if s.Value().Decrement().Nat().Coprime(group.Modulus().Nat()) {
				break
			}
			counter++
		}
		return nil
	})
	eg.Go(func() error {
		for {
			counter := 0
			tSqrt, err := ts.Extract(transcript, fmt.Sprintf("t_%s_%d", label, counter), group)
			if err != nil {
				return errs.Wrap(err).WithMessage("failed to extract tSqrt for pedersen key")
			}
			t = tSqrt.Mul(tSqrt)
			if t.Value().Decrement().Nat().Coprime(group.Modulus().Nat()) {
				break
			}
			counter++
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to extract generators for pedersen key")
	}

	out, err := newCommitmentKey(s.ForgetOrder(), t.ForgetOrder())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Pedersen commitment key")
	}
	return out, nil
}

func newCommitmentKey(s, t *znstar.RSAGroupElementUnknownOrder) (*CommitmentKey, error) {
	if s == nil || t == nil {
		return nil, ErrInvalidArgument.WithMessage("generators cannot be nil")
	}
	if s.Structure().Name() != t.Structure().Name() {
		return nil, ErrInvalidArgument.WithMessage("s and t must belong to the same group")
	}
	if s.Equal(t) {
		return nil, ErrInvalidArgument.WithMessage("s and t cannot be equal")
	}
	if s.IsOne() || t.IsOne() {
		return nil, ErrInvalidArgument.WithMessage("s or t cannot be the identity element")
	}
	// TorsionFree checks the jacobi symbol. This is necessary but not sufficient.
	// We can't check if they are in QR(N̂) due to not having the order.
	if !s.IsTorsionFree() || !t.IsTorsionFree() {
		return nil, ErrInvalidArgument.WithMessage("s and t must be torsion-free")
	}

	group := s.Group()

	witnessUpper := group.Modulus().Lsh(base.StatisticalSecurityBits).Lift()
	witnessLower := witnessUpper.Neg()

	return &CommitmentKey{
		s: s,
		t: t,

		witnessUpper: witnessUpper,
		witnessLower: witnessLower,
	}, nil
}

type CommitmentKey struct {
	s, t *znstar.RSAGroupElementUnknownOrder

	witnessUpper *num.Int
	witnessLower *num.Int
}

type commitmentKeyDTO struct {
	S            *znstar.RSAGroupElementUnknownOrder `cbor:"s"`
	T            *znstar.RSAGroupElementUnknownOrder `cbor:"t"`
	MessageSlack int                                 `cbor:"slack"`
}

func (k *CommitmentKey) SampleWitness(prng io.Reader) (*Witness, error) {
	if prng == nil {
		return nil, ErrIsNil.WithMessage("prng cannot be nil")
	}
	wv, err := num.Z().Random(k.witnessLower, k.witnessUpper, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to sample witness value")
	}
	witness, err := NewWitness(wv)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create witness from sampled value")
	}
	return witness, nil
}

func (k *CommitmentKey) WitnessIsFreshlySampled(witness *Witness) bool {
	return witness != nil &&
		k.witnessLower.IsLessThanOrEqual(witness.Value()) &&
		base.Compare(witness.Value(), k.witnessUpper).IsLessThan()
}

func (k *CommitmentKey) CommitWithWitness(message *Message, witness *Witness) (*Commitment, error) {
	if message == nil || witness == nil {
		return nil, ErrIsNil.WithMessage("message and witness cannot be nil")
	}
	out, err := NewCommitment(k.s.ExpI(message.Value()).Mul(k.t.ExpI(witness.Value())).ForgetOrder())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create commitment from message and witness")
	}
	return out, nil
}

func (k *CommitmentKey) Open(commitment *Commitment, message *Message, witness *Witness) error {
	if err := internal.GenericOpen(k, commitment, message, witness); err != nil {
		return errs.Wrap(err).WithMessage("failed to open commitment")
	}
	return nil
}

func (k *CommitmentKey) WitnessOp(first, second *Witness, rest ...*Witness) (*Witness, error) {
	out, err := internal.Op(NewWitness, first, second, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine witnesses")
	}
	return out, nil
}

func (k *CommitmentKey) WitnessOpInv(w *Witness) (*Witness, error) {
	if w == nil {
		return nil, ErrIsNil.WithMessage("witness cannot be nil")
	}
	out, err := NewWitness(w.Value().Neg())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new witness")
	}
	return out, nil
}

func (k *CommitmentKey) WitnessScalarOp(w *Witness, scalar *num.Int) (*Witness, error) {
	if w == nil {
		return nil, ErrIsNil.WithMessage("witness cannot be nil")
	}
	if scalar == nil {
		return nil, ErrIsNil.WithMessage("scalar cannot be nil")
	}
	out, err := NewWitness(w.Value().Mul(scalar))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new witness")
	}
	return out, nil
}

func (k *CommitmentKey) MessageOp(first, second *Message, rest ...*Message) (*Message, error) {
	out, err := internal.Op(NewMessage, first, second, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine messages")
	}
	return out, nil
}

func (k *CommitmentKey) MessageOpInv(m *Message) (*Message, error) {
	if m == nil {
		return nil, ErrIsNil.WithMessage("message cannot be nil")
	}
	out, err := NewMessage(m.Value().Neg())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new message")
	}
	return out, nil
}

func (k *CommitmentKey) MessageScalarOp(m *Message, scalar *num.Int) (*Message, error) {
	if m == nil {
		return nil, ErrIsNil.WithMessage("message cannot be nil")
	}
	if scalar == nil {
		return nil, ErrIsNil.WithMessage("scalar cannot be nil")
	}
	out, err := NewMessage(m.Value().Mul(scalar))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new message")
	}
	return out, nil
}

func (k *CommitmentKey) CommitmentOp(first, second *Commitment, rest ...*Commitment) (*Commitment, error) {
	out, err := internal.Op(NewCommitment, first, second, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine commitments")
	}
	return out, nil
}

func (k *CommitmentKey) CommitmentOpInv(c *Commitment) (*Commitment, error) {
	if c == nil {
		return nil, ErrIsNil.WithMessage("commitment cannot be nil")
	}
	out, err := NewCommitment(c.Value().Inv())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment")
	}
	return out, nil
}

func (k *CommitmentKey) CommitmentScalarOp(c *Commitment, scalar *num.Int) (*Commitment, error) {
	if c == nil {
		return nil, ErrIsNil.WithMessage("commitment cannot be nil")
	}
	if scalar == nil {
		return nil, ErrIsNil.WithMessage("scalar cannot be nil")
	}
	out, err := NewCommitment(c.Value().ExpI(scalar))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment")
	}
	return out, nil
}

func (k *CommitmentKey) ReRandomise(c *Commitment, witnessShift *Witness) (*Commitment, error) {
	if c == nil {
		return nil, ErrIsNil.WithMessage("commitment cannot be nil")
	}
	if witnessShift == nil {
		return nil, ErrIsNil.WithMessage("witness shift cannot be nil")
	}
	out, err := NewCommitment(c.Value().Mul(k.t.ExpI(witnessShift.Value())))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment")
	}
	return out, nil
}

func (k *CommitmentKey) Shift(c *Commitment, message *Message) (*Commitment, error) {
	if c == nil {
		return nil, ErrIsNil.WithMessage("commitment cannot be nil")
	}
	if message == nil {
		return nil, ErrIsNil.WithMessage("message cannot be nil")
	}
	out, err := NewCommitment(c.Value().Mul(k.s.ExpI(message.Value())))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment")
	}
	return out, nil
}

func (k *CommitmentKey) MessageGroup() *num.Integers {
	return num.Z()
}

func (k *CommitmentKey) WitnessGroup() *num.Integers {
	return num.Z()
}

func (k *CommitmentKey) CommitmentGroup() *znstar.RSAGroupUnknownOrder {
	return k.s.Group()
}

func (k *CommitmentKey) S() *znstar.RSAGroupElementUnknownOrder {
	return k.s
}

func (k *CommitmentKey) T() *znstar.RSAGroupElementUnknownOrder {
	return k.t
}

func (k *CommitmentKey) Group() *znstar.RSAGroupUnknownOrder {
	return k.s.Group()
}

func (k *CommitmentKey) Equal(other *CommitmentKey) bool {
	if k == nil || other == nil {
		return k == other
	}
	return k.s.Equal(other.s) &&
		k.t.Equal(other.t) &&
		k.s.IsUnknownOrder() == other.s.IsUnknownOrder()
}

func (k *CommitmentKey) HashCode() base.HashCode {
	return k.s.HashCode().Combine(k.t.HashCode())
}

func (k *CommitmentKey) Clone() *CommitmentKey {
	return &CommitmentKey{
		s:            k.s.Clone(),
		t:            k.t.Clone(),
		witnessUpper: k.witnessUpper.Clone(),
		witnessLower: k.witnessLower.Clone(),
	}
}

func (k *CommitmentKey) MarshalCBOR() ([]byte, error) {
	dto := &commitmentKeyDTO{
		S: k.s,
		T: k.t,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal commitment key to CBOR")
	}
	return out, nil
}

func (k *CommitmentKey) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[commitmentKeyDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal commitment key from CBOR")
	}
	kk, err := newCommitmentKey(dto.S, dto.T)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment key parameters")
	}
	*k = *kk
	return nil
}
