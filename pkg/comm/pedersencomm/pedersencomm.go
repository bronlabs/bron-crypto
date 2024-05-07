package pedersencomm

import (
	"fmt"
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
	SomethingUpMySleeve = []byte(fmt.Sprintf("COPPER_KRYPTON_%s_SOMETHING_UP_MY_SLEEVE-", Name))
)

type Opening struct {
	Message_ Message
	Witness  Witness
}

var _ comm.Opening[Message] = (*Opening)(nil)

func (o *Opening) Message() Message {
	return o.Message_
}

type HomomorphicCommitmentScheme struct{}

var _ comm.HomomorphicCommitmentScheme[Message, Commitment, *Opening] = (*HomomorphicCommitmentScheme)(nil)

type HomomorphicCommitter struct {
	Prng      io.Reader
	Generator curves.Point
	HomomorphicCommitmentScheme
}

var _ comm.HomomorphicCommitter[Message, Commitment, *Opening] = (*HomomorphicCommitter)(nil)

type HomomorphicVerifier struct {
	SessionId []byte
	HomomorphicCommitmentScheme
}

var _ comm.HomomorphicVerifier[Message, Commitment, *Opening] = (*HomomorphicVerifier)(nil)

type Commitment struct {
	Commitment curves.Point
}

var _ comm.Commitment = (*Commitment)(nil)

// not UC-secure without session-id
func NewHomomorphicCommitter(sessionId []byte, prng io.Reader, curve curves.Curve) (*HomomorphicCommitter, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	// Generate a random point from the sessionId and NothingUpMySleeve
	h, err := hashing.HashChain(base.RandomOracleHashFunction, sessionId, SomethingUpMySleeve)
	if err != nil {
		return nil, errs.WrapHashing(err, "could not produce dlog of H")
	}
	generator, err := curve.Hash(h)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash to curve for H")
	}
	return &HomomorphicCommitter{prng, generator, HomomorphicCommitmentScheme{}}, nil
}

func NewHomomorphicVerifier(sessionId []byte) (*HomomorphicVerifier, error) {
	return &HomomorphicVerifier{sessionId, HomomorphicCommitmentScheme{}}, nil
}

func (c *HomomorphicCommitter) Commit(message Message) (Commitment, *Opening, error) {
	if c == nil {
		return Commitment{}, nil, errs.NewIsNil("receiver")
	}
	curve := message.ScalarField().Curve()
	witness, _ := message.ScalarField().Random(c.Prng)
	// Generate the committed value
	mG := curve.Generator().ScalarMul(message)
	// Generate the binding term
	rH := c.Generator.ScalarMul(witness)
	commitment := rH.Add(mG)
	return Commitment{commitment}, &Opening{message, witness}, nil
}

func (c *Commitment) Validate() error {
	if c == nil {
		return errs.NewIsNil("receiver")
	}
	if c.Commitment == nil {
		return errs.NewIsNil("commitment")
	}
	if c.Commitment.IsSmallOrder() {
		return errs.NewMembership("commitment is not part of the prime order subgroup")
	}
	return nil
}

func (o *Opening) Validate() error {
	if o == nil {
		return errs.NewIsNil("receiver")
	}
	if o.Message_ == nil {
		return errs.NewIsNil("message")
	}
	if o.Witness == nil {
		return errs.NewIsNil("witness")
	}
	return nil
}

func (v *HomomorphicVerifier) Verify(commitment Commitment, opening *Opening) error {
	if v == nil {
		return errs.NewIsNil("receiver")
	}
	if err := commitment.Validate(); err != nil {
		return errs.WrapFailed(err, "unvalid commitment")
	}
	if err := opening.Validate(); err != nil {
		return errs.WrapFailed(err, "unvalid opening")
	}
	curve := opening.Message_.ScalarField().Curve()
	// Reconstructs the 1st operand
	mG := curve.Generator().ScalarMul(opening.Message_)
	// Reconstructs the 2nd operand
	hBytes, err := hashing.HashChain(base.RandomOracleHashFunction, v.SessionId, SomethingUpMySleeve)
	if err != nil {
		return errs.WrapHashing(err, "could not produce dlog of H")
	}
	h, err := curve.Hash(hBytes)
	if err != nil {
		return errs.WrapHashing(err, "failed to hash to curve for H")
	}
	rH := h.ScalarMul(opening.Witness)
	// Reconstructs the corresponding commitment
	localCommitment := rH.Add(mG)
	if !commitment.Commitment.Equal(localCommitment) {
		return errs.NewVerification("verification failed")
	}
	return nil
}

func (hcs *HomomorphicCommitmentScheme) CombineCommitments(x Commitment, ys ...Commitment) (Commitment, error) {
	if hcs == nil {
		return Commitment{}, errs.NewIsNil("receiver")
	}
	if len(ys) == 0 {
		return x, nil
	}
	acc := x
	for _, y := range ys {
		acc.Commitment = acc.Commitment.Add(y.Commitment)
	}
	return acc, nil
}

func (hcs *HomomorphicCommitmentScheme) ScaleCommitment(x Commitment, n *saferith.Nat) (Commitment, error) {
	if hcs == nil {
		return Commitment{}, errs.NewIsNil("receiver")
	}
	curve := x.Commitment.Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	return Commitment{x.Commitment.ScalarMul(scale)}, nil
}

func (hcs *HomomorphicCommitmentScheme) CombineOpenings(x *Opening, ys ...*Opening) (*Opening, error) {
	if hcs == nil {
		return nil, errs.NewIsNil("receiver")
	}
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

func (hcs *HomomorphicCommitmentScheme) ScaleOpening(x *Opening, n *saferith.Nat) (*Opening, error) {
	if hcs == nil {
		return nil, errs.NewIsNil("receiver")
	}
	curve := x.Witness.ScalarField().Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	return &Opening{x.Message().Mul(scale), x.Witness.Mul(scale)}, nil
}
