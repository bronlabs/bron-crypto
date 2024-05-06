package elgamalcomm

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

const Name comm.Name = "ELGAMAL_COMMITMENT"

type Message curves.Point

var _ comm.Message = Message(nil)

type Witness curves.Scalar

var _ Witness = Witness(nil)

var (
	// hardcoded seed used to derive generators along with the session-id
	somethingUpMySleeve = []byte(fmt.Sprintf("COPPER_KRYPTON_%s_SOMETHING_UP_MY_SLEEVE-", Name))
)

type Opening struct {
	message   Message
	witness   Witness
	publicKey curves.Point
}

var _ comm.Opening[Message] = (*Opening)(nil)

func (o Opening) Message() Message {
	return o.message
}

type HomomorphicCommitmentScheme struct{}

var _ comm.HomomorphicCommitmentScheme[Message, Commitment, Opening] = (*HomomorphicCommitmentScheme)(nil)

type HomomorphicCommitter struct {
	prng       io.Reader
	privateKey curves.Scalar
	PublicKey  curves.Point
	HomomorphicCommitmentScheme
}

var _ comm.HomomorphicCommitter[Message, Commitment, Opening] = (*HomomorphicCommitter)(nil)

type HomomorphicVerifier struct {
	sessionId []byte
	HomomorphicCommitmentScheme
}

var _ comm.HomomorphicVerifier[Message, Commitment, Opening] = (*HomomorphicVerifier)(nil)

type Commitment struct {
	c1 curves.Point
	c2 curves.Point
}

var _ comm.Commitment = (*Commitment)(nil)

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

// not UC-secure without session-id
func NewHomomorphicCommitter(sessionId []byte, prng io.Reader, privateKey curves.Scalar) (*HomomorphicCommitter, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	// Generate a random point from the sessionId and NothingUpMySleeve
	generatorMessage, err := hashing.HashChain(base.RandomOracleHashFunction, sessionId, somethingUpMySleeve)
	if err != nil {
		return nil, errs.WrapHashing(err, "could not produce dlog of H")
	}
	curve := privateKey.ScalarField().Curve()
	publicKey, err := curve.Hash(generatorMessage)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash to curve for H")
	}
	return &HomomorphicCommitter{prng, privateKey, publicKey, HomomorphicCommitmentScheme{}}, nil
}

func NewHomomorphicVerifier(sessionId []byte) (*HomomorphicVerifier, error) {
	return &HomomorphicVerifier{sessionId, HomomorphicCommitmentScheme{}}, nil
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
	first := curve.Generator().ScalarMul(nonce)
	second := rE.Add(message)
	return first, second, nil
}

func (c *HomomorphicCommitter) Commit(message Message) (Commitment, Opening, error) {
	if message == nil {
		return Commitment{}, Opening{}, errs.NewIsNil("message")
	}
	witness, err := message.Curve().ScalarField().Random(c.prng)
	if err != nil {
		return Commitment{}, Opening{}, errs.WrapFailed(err, "could not draw a random scalar")
	}
	first, second, err := encrypt(c.PublicKey, message, witness)
	if err != nil {
		return Commitment{}, Opening{}, errs.NewFailed("could not run Elgamal encryption")
	}
	return Commitment{first, second}, Opening{message, witness, c.PublicKey}, nil
}

func (v *HomomorphicVerifier) Verify(commitment Commitment, opening Opening) error {
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

func (hcs *HomomorphicCommitmentScheme) CombineCommitments(x Commitment, ys ...Commitment) (Commitment, error) {
	if hcs == nil {
		return Commitment{}, errs.NewIsNil("receiver")
	}
	if len(ys) == 0 {
		return x, nil
	}
	acc := x
	for _, y := range ys {
		acc.c1 = acc.c1.Add(y.c1)
		acc.c2 = acc.c2.Add(y.c2)
	}
	return acc, nil
}

func (hcs *HomomorphicCommitmentScheme) ScaleCommitment(x Commitment, n *saferith.Nat) (Commitment, error) {
	if hcs == nil {
		return Commitment{}, errs.NewIsNil("receiver")
	}
	curve := x.c1.Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	return Commitment{x.c1.ScalarMul(scale), x.c2.ScalarMul(scale)}, nil
}

func (hcs *HomomorphicCommitmentScheme) CombineOpenings(x Opening, ys ...Opening) (Opening, error) {
	if hcs == nil {
		return Opening{}, errs.NewIsNil("receiver")
	}
	if len(ys) == 0 {
		return x, nil
	}
	acc := x
	for _, y := range ys {
		acc.message = acc.message.Add(y.message)
		acc.witness = acc.witness.Add(y.witness)
	}
	return acc, nil
}

func (hcs *HomomorphicCommitmentScheme) ScaleOpening(x Opening, n *saferith.Nat) (Opening, error) {
	if hcs == nil {
		return Opening{}, errs.NewIsNil("receiver")
	}
	curve := x.witness.ScalarField().Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	return Opening{x.Message().ScalarMul(scale), x.witness.Mul(scale), x.publicKey}, nil
}
