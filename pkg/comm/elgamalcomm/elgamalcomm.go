package elgamalcomm

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

const Name comm.Name = "ELGAMAL_COMMITMENT"

var _ comm.Message = Message(nil)
var _ Witness = Witness(nil)
var _ comm.Commitment = (*Commitment)(nil)
var _ comm.Opening[Message] = (*Opening)(nil)
var _ comm.HomomorphicCommitmentScheme[Message, *Commitment, *Opening] = (*HomomorphicCommitmentScheme)(nil)
var _ comm.HomomorphicCommitter[Message, *Commitment, *Opening] = (*HomomorphicCommitter)(nil)
var _ comm.HomomorphicVerifier[Message, *Commitment, *Opening] = (*HomomorphicVerifier)(nil)

type Message curves.Point
type Witness curves.Scalar

var (
	// hardcoded seed used to derive generators along with the session-id.
	somethingUpMySleeve = []byte(fmt.Sprintf("COPPER_KRYPTON_%s_SOMETHING_UP_MY_SLEEVE-", Name))
)

type Opening struct {
	message   Message
	witness   Witness
	publicKey curves.Point
}

type Commitment struct {
	c1 curves.Point
	c2 curves.Point
}

type HomomorphicCommitmentScheme struct{}

type HomomorphicCommitter struct {
	prng io.Reader
	h    curves.Point
	HomomorphicCommitmentScheme
}

type HomomorphicVerifier struct {
	sessionId []byte
	h         curves.Point
	HomomorphicCommitmentScheme
}

// not UC-secure without session-id.
func NewHomomorphicCommitter(sessionId []byte, prng io.Reader, publicKey curves.Point) (*HomomorphicCommitter, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	if publicKey == nil {
		return nil, errs.NewIsNil("publicKey is nil")
	}
	// Generate a random point from the sessionId and somethingUpMySleeve
	hByte, err := hashing.HashChain(base.RandomOracleHashFunction, sessionId, somethingUpMySleeve)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash sessionId")
	}
	curve := publicKey.Curve()
	h, err := curve.Hash(hByte)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash to curve for H")
	}
	// Add the public key to it
	h = h.Add(publicKey)
	return &HomomorphicCommitter{prng, h, HomomorphicCommitmentScheme{}}, nil
}

func NewHomomorphicVerifier(sessionId []byte, publicKey curves.Point) (*HomomorphicVerifier, error) {
	if publicKey == nil {
		return nil, errs.NewIsNil("publicKey is nil")
	}
	// Generate a random point from the sessionId and somethingUpMySleeve
	hByte, err := hashing.HashChain(base.RandomOracleHashFunction, sessionId, somethingUpMySleeve)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash sessionId")
	}
	curve := publicKey.Curve()
	h, err := curve.Hash(hByte)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash to curve for H")
	}
	// Add the public key to it
	h = h.Add(publicKey)
	return &HomomorphicVerifier{sessionId, h, HomomorphicCommitmentScheme{}}, nil
}

func (c *Commitment) Validate() error {
	if c == nil {
		return errs.NewIsNil("commitment")
	}
	if c.c1 == nil {
		return errs.NewIsNil("first commitment component")
	}
	if c.c2 == nil {
		return errs.NewIsNil("second commitment component")
	}
	if c.c1.IsAdditiveIdentity() {
		return errs.NewIsIdentity("first commitment component is identity")
	}
	if c.c2.IsAdditiveIdentity() {
		return errs.NewIsIdentity("second commitment component is identity")
	}
	if c.c1.IsSmallOrder() {
		return errs.NewMembership("first commitment is not part of the prime order subgroup")
	}
	if c.c2.IsSmallOrder() {
		return errs.NewMembership("first commitment is not part of the prime order subgroup")
	}
	return nil
}

func (o *Opening) Validate() error {
	if o == nil {
		return errs.NewIsNil("opening")
	}
	if o.message == nil {
		return errs.NewIsNil("opening message")
	}
	if o.witness == nil {
		return errs.NewIsNil("opening witness")
	}
	return nil
}

func (o Opening) Message() Message {
	return o.message
}

func encrypt(publicKey curves.Point, message Message, nonce curves.Scalar) (curves.Point, curves.Point, error) {
	if publicKey == nil {
		return nil, nil, errs.NewIsNil("public key")
	}
	if publicKey.IsAdditiveIdentity() {
		return nil, nil, errs.NewIsIdentity("public key is identity")
	}
	curve := message.Curve()
	rE := publicKey.ScalarMul(nonce)
	c1 := curve.Generator().ScalarMul(nonce)
	c2 := rE.Add(message)
	return c1, c2, nil
}

func (c *HomomorphicCommitter) Commit(message Message) (*Commitment, *Opening, error) {
	if message == nil {
		return nil, nil, errs.NewIsNil("message")
	}
	witness, err := message.Curve().ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not draw a random scalar")
	}
	c1, c2, err := encrypt(c.h, message, witness)
	if err != nil {
		return nil, nil, errs.NewFailed("could not run Elgamal encryption")
	}
	return &Commitment{c1, c2}, &Opening{message, witness, c.h}, nil
}

func (_ *HomomorphicVerifier) Verify(commitment *Commitment, opening *Opening) error {
	if err := commitment.Validate(); err != nil {
		return errs.NewArgument("unvalid commitment")
	}
	if err := opening.Validate(); err != nil {
		return errs.NewArgument("unvalid opening")
	}
	localFirst, localSecond, err := encrypt(opening.publicKey, opening.message, opening.witness)
	if err != nil {
		return errs.NewFailed("could not run Elgamal encryption")
	}
	if !(commitment.c1.Equal(localFirst)) {
		return errs.NewVerification("verification failed for first component")
	}
	if !commitment.c2.Equal(localSecond) {
		return errs.NewVerification("verification failed for second component")
	}
	return nil
}

func (_ *HomomorphicCommitmentScheme) CombineCommitments(x *Commitment, ys ...*Commitment) (*Commitment, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.NewArgument("unvalid commitment (1st operand)")
	}
	acc := &Commitment{x.c1.Clone(), x.c2.Clone()}
	for _, y := range ys {
		if err := y.Validate(); err != nil {
			return nil, errs.NewArgument("unvalid commitment (2nd operand)")
		}
		acc.c1 = acc.c1.Add(y.c1)
		acc.c2 = acc.c2.Add(y.c2)
	}
	return acc, nil
}

func (_ *HomomorphicCommitmentScheme) ScaleCommitment(x *Commitment, n *saferith.Nat) (*Commitment, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.NewArgument("unvalid commitment")
	}
	curve := x.c1.Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	return &Commitment{x.c1.ScalarMul(scale), x.c2.ScalarMul(scale)}, nil
}

func (_ *HomomorphicCommitmentScheme) CombineOpenings(x *Opening, ys ...*Opening) (*Opening, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.NewArgument("unvalid opening (1st operand)")
	}
	acc := x
	for _, y := range ys {
		if err := y.Validate(); err != nil {
			return nil, errs.NewArgument("unvalid opening (2nd operand)")
		}
		acc.message = acc.message.Add(y.message)
		acc.witness = acc.witness.Add(y.witness)
	}
	return acc, nil
}

func (_ *HomomorphicCommitmentScheme) ScaleOpening(x *Opening, n *saferith.Nat) (*Opening, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.NewArgument("unvalid opening")
	}
	curve := x.witness.ScalarField().Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	return &Opening{x.Message().ScalarMul(scale), x.witness.Mul(scale), x.publicKey}, nil
}
