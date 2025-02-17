package pedersen_comm

import (
	"encoding/gob"
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/commitments"
)

var (
	_ commitments.Commitment                                                     = Commitment(nil)
	_ commitments.Message                                                        = Message(nil)
	_ commitments.Witness                                                        = Witness(nil)
	_ commitments.Scalar                                                         = Scalar(nil)
	_ commitments.HomomorphicCommittingKey[Commitment, Message, Witness, Scalar] = (*CommittingKey)(nil)
)

type (
	Commitment curves.Point
	Message    curves.Scalar
	Witness    curves.Scalar
	Scalar     curves.Scalar
)

type Opening = commitments.Opening[Message, Witness]

func NewOpening(message, witness curves.Scalar) *Opening {
	return commitments.NewOpening[Message, Witness](message, witness)
}

type CommittingKey struct {
	g curves.Point
	h curves.Point
}

func NewCommittingKey(g, h curves.Point) *CommittingKey {
	return &CommittingKey{g: g, h: h}
}

func (ck *CommittingKey) RandomWitness(prng io.Reader) (witness Witness, err error) {
	r, err := ck.h.Curve().ScalarField().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot sample witness")
	}

	return r, nil
}

func (ck *CommittingKey) CommitWithWitness(message Message, witness Witness) (commitment Commitment, err error) {
	gm := ck.g.ScalarMul(message)
	hr := ck.h.ScalarMul(witness)
	c := gm.Add(hr)

	return c, nil
}

func (ck *CommittingKey) Commit(message Message, prng io.Reader) (commitment Commitment, witness Witness, err error) {
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

func (ck *CommittingKey) Verify(commitment Commitment, message Message, witness Witness) (err error) {
	c, err := ck.CommitWithWitness(message, witness)
	if err != nil {
		return errs.WrapFailed(err, "cannot compute commitment")
	}
	if !c.Equal(commitment) {
		return errs.NewVerification("invalid commitment")
	}

	return nil
}

func (*CommittingKey) MessageAdd(lhs, rhs Message) (message Message, err error) {
	return lhs.Add(rhs), nil
}

func (*CommittingKey) MessageSub(lhs, rhs Message) (message Message, err error) {
	return lhs.Sub(rhs), nil
}

func (*CommittingKey) MessageNeg(x Message) (message Message, err error) {
	return x.Neg(), nil
}

func (*CommittingKey) MessageMul(lhs Message, rhs Scalar) (message Message, err error) {
	return lhs.Mul(rhs), nil
}

func (*CommittingKey) CommitmentAdd(lhs, rhs Commitment) (commitment Commitment, err error) {
	return lhs.Add(rhs), nil
}

func (ck *CommittingKey) CommitmentAddMessage(lhs Commitment, rhs Message) (commitment Commitment, err error) {
	gm := ck.g.ScalarMul(rhs)
	c := lhs.Add(gm)

	return c, nil
}

func (*CommittingKey) CommitmentSub(lhs, rhs Commitment) (commitment Commitment, err error) {
	return lhs.Sub(rhs), nil
}

func (ck *CommittingKey) CommitmentSubMessage(lhs Commitment, rhs Message) (commitment Commitment, err error) {
	gm := ck.g.ScalarMul(rhs)
	c := lhs.Sub(gm)

	return c, nil
}

func (*CommittingKey) CommitmentNeg(x Commitment) (commitment Commitment, err error) {
	return x.Neg(), nil
}

func (*CommittingKey) CommitmentMul(lhs Commitment, rhs Scalar) (commitment Commitment, err error) {
	return lhs.ScalarMul(rhs), nil
}

func (*CommittingKey) WitnessEqual(lhs, rhs Witness) bool {
	return lhs.Equal(rhs)
}

func (*CommittingKey) WitnessAdd(lhs, rhs Witness) (witness Witness, err error) {
	return lhs.Add(rhs), nil
}

func (*CommittingKey) WitnessSub(lhs, rhs Witness) (witness Witness, err error) {
	return lhs.Sub(rhs), nil
}

func (*CommittingKey) WitnessNeg(x Witness) (witness Witness, err error) {
	return x.Neg(), nil
}

func (*CommittingKey) WitnessMul(lhs Witness, rhs Scalar) (witness Witness, err error) {
	return lhs.Mul(rhs), nil
}

//nolint:gochecknoinits // register for gob
func init() {
	gob.Register(new(commitments.Opening[Message, Witness]))
}
