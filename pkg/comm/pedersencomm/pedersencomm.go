package pedersencomm

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/cronokirby/saferith"
)

const Name comm.Name = "PEDERSEN_COMMITMENT"

type Message curves.Scalar

var _ comm.Message = Message(nil)

type Witness curves.Scalar

var _ Witness = Witness(nil)

var (
	// hardcoded seed used to derive generators along with the session-id
	somethingUpMySleeve = []byte("COPPER_KRYPTON_JF_SOMETHING_UP_MY_SLEEVE-")
)

type Opening struct {
	Message_ Message
	Witness  Witness
}

var _ comm.Opening[Message] = (*Opening)(nil)

func (o Opening) Message() Message {
	return o.Message_
}

type CommitterHomomorphic struct {
	prng      io.Reader
	sessionId []byte
}

var _ comm.CommitterHomomorphic[Message, Commitment, Opening] = (*CommitterHomomorphic)(nil)

type VerifierHomomorphic struct {
	sessionId []byte
}

var _ comm.VerifierHomomorphic[Message, Commitment, Opening] = (*VerifierHomomorphic)(nil)

type Commitment struct {
	Commitment curves.Point
}

var _ comm.Commitment = (*Commitment)(nil)

// not UC-secure without session-id
func NewCommitterHomomorphic(prng io.Reader, sessionId []byte) (*CommitterHomomorphic, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	return &CommitterHomomorphic{prng, sessionId}, nil
}

func NewVerifierHomomorphic(sessionId []byte) (*VerifierHomomorphic, error) {
	return &VerifierHomomorphic{sessionId}, nil
}

func (c *CommitterHomomorphic) Commit(message Message) (*Commitment, *Opening, error) {
	curve := message.ScalarField().Curve()
	witness, err := message.ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, err
	}
	// Generate the 1st operand of the commitment
	mG := curve.Generator().ScalarMul(message)
	// Generate a random point from the sessionId and NothingUpMySleeve
	HMessage, err := hashing.HashChain(base.RandomOracleHashFunction, c.sessionId, somethingUpMySleeve)
	if err != nil {
		return nil, nil, errs.WrapHashing(err, "could not produce dlog of H")
	}
	H, err := curve.Hash(HMessage)
	if err != nil {
		return nil, nil, errs.WrapHashing(err, "failed to hash to curve for H")
	}
	// Generate the 2nd operand of the commitment
	rH := H.ScalarMul(witness)
	commitment := rH.Add(mG)
	return &Commitment{commitment}, &Opening{message, witness}, nil
}

func (c *CommitterHomomorphic) CombineCommitments(x *Commitment, ys ...*Commitment) (*Commitment, error) {
	if len(ys) == 0 {
		return x, nil
	}
	acc := x
	for _, y := range ys {
		acc.Commitment = acc.Commitment.Add(y.Commitment)
	}
	return acc, nil
}

func (c *CommitterHomomorphic) ScaleCommitment(x *Commitment, n *saferith.Nat) (*Commitment, error) {
	curve := x.Commitment.Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	return &Commitment{x.Commitment.ScalarMul(scale)}, nil
}

func (c *CommitterHomomorphic) CombineOpenings(x *Opening, ys ...*Opening) (*Opening, error) {
	if len(ys) == 0 {
		return x, nil
	}
	acc := x
	for _, y := range ys {
		acc.Message_ = acc.Message_.Add(y.Message_)
		acc.Witness = acc.Witness.Add(y.Witness)
	}
	return acc, nil
}

func (c *CommitterHomomorphic) ScaleOpening(x *Opening, n *saferith.Nat) (*Opening, error) {
	curve := x.Witness.ScalarField().Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	return &Opening{x.Message().Mul(scale), x.Witness.Mul(scale)}, nil
}

func (c *Commitment) Validate() error {
	if c.Commitment == nil {
		return errs.NewIsNil("commitment is nil")
	}
	// TODO: uncomment when 'IsInPrimeSubGroup' is implemented
	// if !c.Commitment.IsInPrimeSubGroup() {
	// 	return errs.NewArgument("commitment is not part of the prime order subgroup")
	// }
	return nil
}

func (o *Opening) Validate() error {
	if o.Message_ == nil {
		return errs.NewIsNil("message is nil")
	}
	if o.Witness == nil {
		return errs.NewIsNil("witness is nil")
	}
	return nil
}

func (v *VerifierHomomorphic) Verify(commitment *Commitment, opening *Opening) error {
	if commitment.Validate() != nil {
		return errs.NewArgument("unvalid commitment")
	}
	if opening.Validate() != nil {
		return errs.NewArgument("unvalid opening")
	}
	curve := opening.Message_.ScalarField().Curve()
	// Reconstructs the 1st operand
	mG := curve.Generator().ScalarMul(opening.Message_)
	// Reconstructs the 2nd operand
	HMessage, err := hashing.HashChain(base.RandomOracleHashFunction, v.sessionId, somethingUpMySleeve)
	if err != nil {
		return errs.WrapHashing(err, "could not produce dlog of H")
	}
	H, err := curve.Hash(HMessage)
	if err != nil {
		return errs.WrapHashing(err, "failed to hash to curve for H")
	}
	rH := H.ScalarMul(opening.Witness)
	// Reconstructs the corresponding commitment
	localCommitment := rH.Add(mG)
	if !commitment.Commitment.Equal(localCommitment) {
		return errs.NewVerification("verification failed")
	}
	return nil
}

func (c *VerifierHomomorphic) CombineCommitments(x *Commitment, ys ...*Commitment) (*Commitment, error) {
	if len(ys) == 0 {
		return x, nil
	}
	acc := x
	for _, y := range ys {
		acc.Commitment = acc.Commitment.Add(y.Commitment)
	}
	return acc, nil
}

func (c *VerifierHomomorphic) ScaleCommitment(x *Commitment, n *saferith.Nat) (*Commitment, error) {
	curve := x.Commitment.Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	return &Commitment{x.Commitment.ScalarMul(scale)}, nil
}

func (c *VerifierHomomorphic) CombineOpenings(x *Opening, ys ...*Opening) (*Opening, error) {
	if len(ys) == 0 {
		return x, nil
	}
	acc := x
	for _, y := range ys {
		acc.Message_ = acc.Message_.Add(y.Message_)
		acc.Witness = acc.Witness.Add(y.Witness)
	}
	return acc, nil
}

func (c *VerifierHomomorphic) ScaleOpening(x *Opening, n *saferith.Nat) (*Opening, error) {
	curve := x.Witness.ScalarField().Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	return &Opening{x.Message().Mul(scale), x.Witness.Mul(scale)}, nil
}
