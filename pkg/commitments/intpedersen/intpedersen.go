package intpedersen_comm

import (
	"encoding/gob"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/commitments"
)

const (
	// ParamC challenge space.
	ParamC = base.ComputationalSecurity

	// ParamL masking overhead.
	ParamL = base.ComputationalSecurity

	// ParamS randomness space.
	ParamS = 2 * base.ComputationalSecurity
)

var (
	_ commitments.Message                                                            = (*Message)(nil)
	_ commitments.Witness                                                            = (*Witness)(nil)
	_ commitments.Commitment                                                         = (*Commitment)(nil)
	_ commitments.Scalar                                                             = (*Scalar)(nil)
	_ commitments.HomomorphicCommittingKey[*Commitment, *Message, *Witness, *Scalar] = (*CommittingKey)(nil)
)

type Message = saferith.Int
type Witness = saferith.Int
type Commitment = saferith.Nat
type Scalar = saferith.Int

type CommittingKey struct {
	G *saferith.Nat
	H *saferith.Nat
	P *saferith.Modulus
}

func NewCommittingKey(g, h *saferith.Nat, p *saferith.Modulus) *CommittingKey {
	return &CommittingKey{
		G: g,
		H: h,
		P: p,
	}
}

func (*CommittingKey) RandomWitness(prng io.Reader) (witness *Witness, err error) {
	var rBytes [ParamS/8 + 1]byte
	_, err = io.ReadFull(prng, rBytes[1:])
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot sample witness bytes")
	}

	r := new(saferith.Int)
	err = r.UnmarshalBinary(rBytes[:])
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot sample witness")
	}

	return r, nil
}

func (ck *CommittingKey) CommitWithWitness(message *Message, witness *Witness) (commitment *Commitment, err error) {
	gToX := new(saferith.Nat).ExpI(ck.G, message, ck.P)
	hToR := new(saferith.Nat).ExpI(ck.H, witness, ck.P)
	c := new(saferith.Nat).ModMul(gToX, hToR, ck.P)

	return c, nil
}

func (ck *CommittingKey) Commit(message *Message, prng io.Reader) (commitment *Commitment, witness *Witness, err error) {
	r, err := ck.RandomWitness(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample witness")
	}

	c, err := ck.CommitWithWitness(message, r)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot commit to message")
	}

	return c, r, nil
}

func (ck *CommittingKey) Verify(commitment *Commitment, message *Message, witness *Witness) (err error) {
	c, err := ck.CommitWithWitness(message, witness)
	if err != nil {
		return errs.WrapFailed(err, "invalid compute commitment")
	}
	if c.Eq(commitment) == 1 && message.Abs().AnnouncedLen() < (ck.P.BitLen()-2-ParamC) {
		return nil
	}

	return errs.NewVerification("verification failed")
}

func (*CommittingKey) MessageAdd(lhs, rhs *Message) (message *Message, err error) {
	return new(saferith.Int).Add(lhs, rhs, -1), nil
}

func (*CommittingKey) MessageSub(lhs, rhs *Message) (message *Message, err error) {
	return new(saferith.Int).Add(lhs, rhs.Clone().Neg(1), -1), nil
}

func (*CommittingKey) MessageNeg(x *Message) (message *Message, err error) {
	return x.Clone().Neg(1), nil
}

func (*CommittingKey) MessageMul(lhs *Message, rhs *Scalar) (message *Message, err error) {
	return new(saferith.Int).Mul(lhs, rhs, -1), nil
}

func (ck *CommittingKey) CommitmentAdd(lhs, rhs *Commitment) (commitment *Commitment, err error) {
	return new(saferith.Nat).ModMul(lhs, rhs, ck.P), nil
}

func (ck *CommittingKey) CommitmentAddMessage(lhs *Commitment, rhs *Message) (commitment *Commitment, err error) {
	gToM := new(saferith.Nat).ExpI(ck.G, rhs, ck.P)
	return new(saferith.Nat).ModMul(lhs, gToM, ck.P), nil
}

func (ck *CommittingKey) CommitmentSub(lhs, rhs *Commitment) (commitment *Commitment, err error) {
	rhsInv := new(saferith.Nat).ModInverse(rhs, ck.P)
	return new(saferith.Nat).ModMul(lhs, rhsInv, ck.P), nil
}

func (ck *CommittingKey) CommitmentSubMessage(lhs *Commitment, rhs *Message) (commitment *Commitment, err error) {
	gToM := new(saferith.Nat).ExpI(ck.G, rhs.Clone().Neg(1), ck.P)
	return new(saferith.Nat).ModMul(lhs, gToM, ck.P), nil
}

func (ck *CommittingKey) CommitmentNeg(x *Commitment) (commitment *Commitment, err error) {
	return new(saferith.Nat).ModInverse(x, ck.P), nil
}

func (ck *CommittingKey) CommitmentMul(lhs *Commitment, rhs *Scalar) (commitment *Commitment, err error) {
	return new(saferith.Nat).ExpI(lhs, rhs, ck.P), nil
}

func (*CommittingKey) WitnessAdd(lhs, rhs *Witness) (witness *Witness, err error) {
	return new(saferith.Int).Add(lhs, rhs, -1), nil
}

func (*CommittingKey) WitnessSub(lhs, rhs *Witness) (witness *Witness, err error) {
	return new(saferith.Int).Add(lhs, rhs.Clone().Neg(1), -1), nil
}

func (*CommittingKey) WitnessNeg(x *Witness) (witness *Witness, err error) {
	return x.Clone().Neg(1), nil
}

func (*CommittingKey) WitnessMul(lhs *Witness, rhs *Scalar) (witness *Witness, err error) {
	return new(saferith.Int).Mul(lhs, rhs, -1), nil
}

//nolint:gochecknoinits // register for gob
func init() {
	gob.Register(new(commitments.Opening[*Message, *Witness]))
}
