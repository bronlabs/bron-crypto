package boundedintcom

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/commitments/internal"
	"github.com/bronlabs/errs-go/errs"
)

type KeyTrait[A znstar.ArithmeticRSA] struct {
	s, t *znstar.RSAGroupElement[A]

	messageSlack int
	nBits        int
	witnessUpper *num.Int
	witnessLower *num.Int
}

func (k *KeyTrait[A]) SampleWitness(prng io.Reader) (*Witness, error) {
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

func (k *KeyTrait[A]) WitnessInRange(witness *Witness) bool {
	return witness != nil &&
		k.witnessLower.IsLessThanOrEqual(witness.Value()) &&
		base.Compare(witness.Value(), k.witnessUpper).IsLessThan()
}

func (k *KeyTrait[A]) MessageInRange(message *Message) bool {
	return message != nil &&
		message.Value().Abs().TrueLen()+k.messageSlack < k.nBits
}

func (k *KeyTrait[A]) CommitWithWitness(message *Message, witness *Witness) (*Commitment, error) {
	if message == nil || witness == nil {
		return nil, ErrIsNil.WithMessage("message and witness cannot be nil")
	}
	if !k.WitnessInRange(witness) {
		return nil, ErrInvalidArgument.WithMessage("witness value out of range")
	}
	if !k.MessageInRange(message) {
		return nil, ErrInvalidArgument.WithMessage("message value out of range")
	}
	out, err := NewCommitment(k.s.ExpI(witness.Value()).Mul(k.t.ExpI(message.Value())).ForgetOrder())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create commitment from message and witness")
	}
	return out, nil
}

func (k *KeyTrait[A]) Open(commitment *Commitment, message *Message, witness *Witness) error {
	if err := internal.GenericOpen(k, commitment, message, witness); err != nil {
		return errs.Wrap(err).WithMessage("failed to open commitment")
	}
	return nil
}

func (k *KeyTrait[A]) WitnessOp(first, second *Witness, rest ...*Witness) (*Witness, error) {
	out, err := internal.Op(NewWitness, first, second, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine witnesses")
	}
	return out, nil
}

func (k *KeyTrait[A]) WitnessOpInv(w *Witness) (*Witness, error) {
	if w == nil {
		return nil, ErrIsNil.WithMessage("witness cannot be nil")
	}
	out, err := NewWitness(w.Value().Neg())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new witness")
	}
	return out, nil
}

func (k *KeyTrait[A]) WitnessScalarOp(w *Witness, scalar *num.Int) (*Witness, error) {
	if w == nil || scalar == nil {
		return nil, ErrIsNil.WithMessage("witness and scalar cannot be nil")
	}
	out, err := NewWitness(w.Value().ScalarOp(scalar))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new witness")
	}
	return out, nil
}

func (k *KeyTrait[A]) MessageOp(first, second *Message, rest ...*Message) (*Message, error) {
	out, err := internal.Op(NewMessage, first, second, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine messages")
	}
	return out, nil
}

func (k *KeyTrait[A]) MessageOpInv(m *Message) (*Message, error) {
	if m == nil {
		return nil, ErrIsNil.WithMessage("message cannot be nil")
	}
	out, err := NewMessage(m.Value().Neg())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new message")
	}
	return out, nil
}

func (k *KeyTrait[A]) MessageScalarOp(m *Message, scalar *num.Int) (*Message, error) {
	if m == nil || scalar == nil {
		return nil, ErrIsNil.WithMessage("message and scalar cannot be nil")
	}
	out, err := NewMessage(m.Value().ScalarOp(scalar))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new message")
	}
	return out, nil
}

func (k *KeyTrait[A]) commitmentOpValues(first, second *znstar.RSAGroupElement[A], rest ...*znstar.RSAGroupElement[A]) (*znstar.RSAGroupElement[A], error) {
	out, err := internal.OpValues(first, second, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine commitment values")
	}
	return out, nil
}

func (k *KeyTrait[A]) commitmentOpInv(c *znstar.RSAGroupElement[A]) (*znstar.RSAGroupElement[A], error) {
	if c == nil {
		return nil, ErrIsNil.WithMessage("commitment cannot be nil")
	}
	return c.OpInv(), nil
}

func (k *KeyTrait[A]) commitmentScalarOp(c *znstar.RSAGroupElement[A], scalar *num.Int) (*znstar.RSAGroupElement[A], error) {
	if c == nil || scalar == nil {
		return nil, ErrIsNil.WithMessage("commitment and scalar cannot be nil")
	}
	return c.ExpI(scalar), nil
}

func (k *KeyTrait[A]) S() *znstar.RSAGroupElement[A] {
	return k.s
}

func (k *KeyTrait[A]) T() *znstar.RSAGroupElement[A] {
	return k.t
}

func (k *KeyTrait[A]) MessageSlack() int {
	return k.messageSlack
}

func (k *KeyTrait[A]) Group() *znstar.RSAGroup[A] {
	return k.s.Group()
}

func (k *KeyTrait[A]) Equal(other *KeyTrait[A]) bool {
	if k == nil || other == nil {
		return k == other
	}
	return k.s.Equal(other.s) &&
		k.t.Equal(other.t) &&
		k.s.IsUnknownOrder() == other.s.IsUnknownOrder() &&
		k.messageSlack == other.messageSlack
}

func (k *KeyTrait[A]) HashCode() base.HashCode {
	return k.s.HashCode().Combine(k.t.HashCode())
}
