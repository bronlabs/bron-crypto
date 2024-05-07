package pedersencomm

import (
	"fmt"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

const Name comm.Name = "PEDERSEN_COMMITMENT"

var _ comm.Message = Message(nil)
var _ Witness = Witness(nil)
var _ comm.Commitment = (*Commitment)(nil)
var _ comm.Opening[Message] = (*Opening)(nil)
var _ comm.HomomorphicCommitmentScheme[Message, *Commitment, *Opening] = (*HomomorphicCommitmentScheme)(nil)
var _ comm.HomomorphicCommitter[Message, *Commitment, *Opening] = (*HomomorphicCommitter)(nil)
var _ comm.HomomorphicVerifier[Message, *Commitment, *Opening] = (*HomomorphicVerifier)(nil)

var (
	// hardcoded seed used to derive generators along with the session-id.
	SomethingUpMySleeve = []byte(fmt.Sprintf("COPPER_KRYPTON_%s_SOMETHING_UP_MY_SLEEVE-", Name))
)

type Message curves.Scalar
type Witness curves.Scalar

type Opening struct {
	message Message
	Witness Witness
}

type HomomorphicCommitmentScheme struct{}

type HomomorphicCommitter struct {
	Prng io.Reader
	H    curves.Point
	HomomorphicCommitmentScheme
}

type HomomorphicVerifier struct {
	H curves.Point
	HomomorphicCommitmentScheme
}

type Commitment struct {
	Value curves.Point
}

// not UC-secure without session-id.
func NewHomomorphicCommitter(sessionId []byte, prng io.Reader, curve curves.Curve) (*HomomorphicCommitter, error) {
	if curve == nil {
		return nil, errs.NewIsNil("curve is nil")
	}
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	// Generate a random generator from the sessionId and SomethingUpMySleeve
	h, err := hashing.HashChain(base.RandomOracleHashFunction, sessionId, SomethingUpMySleeve)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash chain")
	}
	generator, err := curve.Hash(h)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash to curve for H")
	}
	return &HomomorphicCommitter{prng, generator, HomomorphicCommitmentScheme{}}, nil
}

func NewHomomorphicVerifier(sessionId []byte, curve curves.Curve) (*HomomorphicVerifier, error) {
	if curve == nil {
		return nil, errs.NewIsNil("curve is nil")
	}
	// Generate a random generator from the sessionId and SomethingUpMySleeve
	h, err := hashing.HashChain(base.RandomOracleHashFunction, sessionId, SomethingUpMySleeve)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash sessionId")
	}
	generator, err := curve.Hash(h)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash to curve for H")
	}
	return &HomomorphicVerifier{generator, HomomorphicCommitmentScheme{}}, nil
}

func (c *Commitment) Validate() error {
	if c == nil {
		return errs.NewIsNil("receiver")
	}
	if c.Value == nil {
		return errs.NewIsNil("commitment")
	}
	// TODO: Use IsInPrimeSubGroup once implemented
	// if c.Value.IsInPrimeSubGroup() {
	if c.Value.IsSmallOrder() {
		return errs.NewMembership("commitment is not part of the prime order subgroup")
	}
	return nil
}

func (o *Opening) Validate() error {
	if o == nil {
		return errs.NewIsNil("receiver")
	}
	if o.message == nil {
		return errs.NewIsNil("message")
	}
	if o.Witness == nil {
		return errs.NewIsNil("witness")
	}
	return nil
}

func (o *Opening) Message() Message {
	return o.message
}

func (c *HomomorphicCommitter) Commit(message Message) (*Commitment, *Opening, error) {
	if message == nil {
		return nil, nil, errs.NewIsNil("message")
	}
	curve := message.ScalarField().Curve()
	witness, err := message.ScalarField().Random(c.Prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "generating random scalar")
	}
	// Generate the committed value
	mG := curve.Generator().ScalarMul(message)
	// Generate the binding term
	rH := c.H.ScalarMul(witness)
	commitment := rH.Add(mG)
	return &Commitment{commitment}, &Opening{message, witness}, nil
}

func (v *HomomorphicVerifier) Verify(commitment *Commitment, opening *Opening) error {
	if err := commitment.Validate(); err != nil {
		return errs.WrapFailed(err, "unvalid commitment")
	}
	if err := opening.Validate(); err != nil {
		return errs.WrapFailed(err, "unvalid opening")
	}
	curve := opening.message.ScalarField().Curve()
	// Reconstructs the committed value
	mG := curve.Generator().ScalarMul(opening.message)
	// Reconstructs the binding value
	rH := v.H.ScalarMul(opening.Witness)
	localCommitment := rH.Add(mG)
	if !commitment.Value.Equal(localCommitment) {
		return errs.NewVerification("verification failed")
	}
	return nil
}

func (hcs *HomomorphicCommitmentScheme) CombineCommitments(x *Commitment, ys ...*Commitment) (*Commitment, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.WrapFailed(err, "unvalid commitment (1st operand)")
	}
	acc := &Commitment{x.Value.Clone()}
	for _, y := range ys {
		if err := y.Validate(); err != nil {
			return nil, errs.WrapFailed(err, "unvalid commitment (2nd operand)")
		}
		acc.Value = acc.Value.Add(y.Value)
	}
	return acc, nil
}

func (hcs *HomomorphicCommitmentScheme) ScaleCommitment(x *Commitment, n *saferith.Nat) (*Commitment, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.WrapFailed(err, "unvalid commitment")
	}
	if n == nil {
		return nil, errs.NewIsNil("scalar")
	}
	curve := x.Value.Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	return &Commitment{x.Value.ScalarMul(scale)}, nil
}

func (hcs *HomomorphicCommitmentScheme) CombineOpenings(x *Opening, ys ...*Opening) (*Opening, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.WrapFailed(err, "unvalid opening (1st operand)")
	}
	acc := &Opening{x.message.Clone(), x.Witness.Clone()}
	for _, y := range ys {
		if err := y.Validate(); err != nil {
			return nil, errs.WrapFailed(err, "unvalid opening (2nd operand)")
		}
		acc.message = acc.message.Add(y.message)
		acc.Witness = acc.Witness.Add(y.Witness)
	}
	return acc, nil
}

func (hcs *HomomorphicCommitmentScheme) ScaleOpening(x *Opening, n *saferith.Nat) (*Opening, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.WrapFailed(err, "unvalid opening")
	}
	if n == nil {
		return nil, errs.NewIsNil("scalar")
	}
	curve := x.Witness.ScalarField().Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	return &Opening{x.Message().Mul(scale), x.Witness.Mul(scale)}, nil
}
