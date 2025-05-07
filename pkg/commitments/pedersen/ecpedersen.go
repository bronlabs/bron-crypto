package pedersen_comm

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
)

type Commitment[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] struct {
	C P
}

func NewCommitment[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](c P) *Commitment[P, F, S] {
	return &Commitment[P, F, S]{C: c}
}

type Message[S fields.PrimeFieldElement[S]] struct {
	M S
}

func NewMessage[S fields.PrimeFieldElement[S]](m S) *Message[S] {
	return &Message[S]{M: m}
}

type Witness[S fields.PrimeFieldElement[S]] struct {
	W S
}

func NewWitness[S fields.PrimeFieldElement[S]](w S) *Witness[S] {
	return &Witness[S]{W: w}
}

type CommittingKey[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] struct {
	G P
	H P
}

func NewCommittingKey[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](g, h P) *CommittingKey[P, F, S] {
	return &CommittingKey[P, F, S]{G: g, H: h}
}

func (ck *CommittingKey[P, F, S]) RandomWitness(prng io.Reader) (witness *Witness[S], err error) {
	curve, err := curves.GetCurve(ck.H)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get curve")
	}

	r, err := curve.ScalarField().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot sample witness")
	}

	return NewWitness(r), nil
}

func (ck *CommittingKey[P, F, S]) CommitWithWitness(message *Message[S], witness *Witness[S]) (commitment *Commitment[P, F, S], err error) {
	gm := ck.G.ScalarMul(message.M)
	hr := ck.H.ScalarMul(witness.W)
	c := gm.Op(hr)

	return NewCommitment(c), nil
}

func (ck *CommittingKey[P, F, S]) Commit(message *Message[S], prng io.Reader) (commitment *Commitment[P, F, S], witness *Witness[S], err error) {
	r, err := ck.RandomWitness(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample witness")
	}

	c, err := ck.CommitWithWitness(message, r)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot compute commitment")
	}

	return c, r, nil
}

func (ck *CommittingKey[P, F, S]) Verify(commitment *Commitment[P, F, S], message *Message[S], witness *Witness[S]) (err error) {
	c, err := ck.CommitWithWitness(message, witness)
	if err != nil {
		return errs.WrapFailed(err, "cannot compute commitment")
	}
	if !c.C.Equal(commitment.C) {
		return errs.NewVerification("invalid commitment")
	}

	return nil
}

func (*CommittingKey[P, F, S]) MessageAdd(lhs, rhs *Message[S]) (message *Message[S], err error) {
	return NewMessage(lhs.M.Add(rhs.M)), nil
}

func (*CommittingKey[P, F, S]) MessageSub(lhs, rhs *Message[S]) (message *Message[S], err error) {
	return NewMessage(lhs.M.Sub(rhs.M)), nil
}

func (*CommittingKey[P, F, S]) MessageNeg(x *Message[S]) (message *Message[S], err error) {
	return NewMessage(x.M.Neg()), nil
}

func (*CommittingKey[P, F, S]) MessageMul(lhs *Message[S], rhs S) (message *Message[S], err error) {
	return NewMessage(lhs.M.Mul(rhs)), nil
}

func (*CommittingKey[P, F, S]) CommitmentAdd(lhs, rhs *Commitment[P, F, S]) (commitment *Commitment[P, F, S], err error) {
	return NewCommitment(lhs.C.Op(rhs.C)), nil
}

func (ck *CommittingKey[P, F, S]) CommitmentAddMessage(lhs *Commitment[P, F, S], rhs *Message[S]) (commitment *Commitment[P, F, S], err error) {
	gm := ck.G.ScalarMul(rhs.M)
	c := lhs.C.Op(gm)

	return NewCommitment(c), nil
}

func (*CommittingKey[P, F, S]) CommitmentSub(lhs, rhs *Commitment[P, F, S]) (commitment *Commitment[P, F, S], err error) {
	return NewCommitment(lhs.C.Op(rhs.C.OpInv())), nil
}

func (ck *CommittingKey[P, F, S]) CommitmentSubMessage(lhs *Commitment[P, F, S], rhs *Message[S]) (commitment *Commitment[P, F, S], err error) {
	gm := ck.G.ScalarMul(rhs.M)
	c := lhs.C.Op(gm.OpInv())

	return NewCommitment(c), nil
}

func (*CommittingKey[P, F, S]) CommitmentNeg(x *Commitment[P, F, S]) (commitment *Commitment[P, F, S], err error) {
	return NewCommitment(x.C.OpInv()), nil
}

func (*CommittingKey[P, F, S]) CommitmentMul(lhs *Commitment[P, F, S], rhs S) (commitment *Commitment[P, F, S], err error) {
	return NewCommitment(lhs.C.ScalarMul(rhs)), nil
}

func (*CommittingKey[P, F, S]) WitnessEqual(lhs, rhs *Witness[S]) bool {
	return lhs.W.Equal(rhs.W)
}

func (*CommittingKey[P, F, S]) WitnessAdd(lhs, rhs *Witness[S]) (witness *Witness[S], err error) {
	return NewWitness(lhs.W.Add(rhs.W)), nil
}

func (*CommittingKey[P, F, S]) WitnessSub(lhs, rhs *Witness[S]) (witness *Witness[S], err error) {
	return NewWitness(lhs.W.Sub(rhs.W)), nil
}

func (*CommittingKey[P, F, S]) WitnessNeg(x *Witness[S]) (witness *Witness[S], err error) {
	return NewWitness(x.W.Neg()), nil
}

func (*CommittingKey[P, F, S]) WitnessMul(lhs *Witness[S], rhs S) (witness *Witness[S], err error) {
	return NewWitness(lhs.W.Mul(rhs)), nil
}
