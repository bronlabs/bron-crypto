package nthroot

import (
	crand "crypto/rand"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
)

const Name sigma.Name = "ZKPOK_NTH_ROOT"

type Statement *saferith.Nat

var _ sigma.Statement = Statement(nil)

type Witness *saferith.Nat

var _ sigma.Witness = Witness(nil)

type Commitment *saferith.Nat

var _ sigma.Commitment = Commitment(nil)

type State *saferith.Nat

var _ sigma.State = State(nil)

type Response *saferith.Nat

var _ sigma.Response = Response(nil)

type protocol struct {
	n        *saferith.Nat
	nSquared *saferith.Modulus
	prng     io.Reader
}

var _ sigma.Protocol[Statement, Witness, Commitment, State, Response] = (*protocol)(nil)

func NewSigmaProtocol(n *saferith.Nat, prng io.Reader) (sigma.Protocol[Statement, Witness, Commitment, State, Response], error) {
	if n == nil {
		return nil, errs.NewIsNil("n")
	}
	if prng == nil {
		prng = crand.Reader
	}

	return &protocol{
		n:        n,
		nSquared: saferith.ModulusFromNat(new(saferith.Nat).Mul(n, n, -1)),
		prng:     prng,
	}, nil
}

func (*protocol) Name() sigma.Name {
	return Name
}

func (p *protocol) ComputeProverCommitment(_ Statement, _ Witness) (Commitment, State, error) {
	r, err := crand.Int(p.prng, p.nSquared.Big())
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample commitment")
	}

	s := new(saferith.Nat).SetBig(r, p.nSquared.BitLen())
	a := new(saferith.Nat).Exp(s, p.n, p.nSquared)
	return a, s, nil
}

func (p *protocol) ComputeProverResponse(_ Statement, witness Witness, _ Commitment, state State, challenge sigma.ChallengeBytes) (Response, error) {
	e := p.mapBytesToChallenge(challenge)
	vToE := new(saferith.Nat).Exp(witness, e, p.nSquared)
	z := new(saferith.Nat).ModMul(state, vToE, p.nSquared)
	return z, nil
}

func (p *protocol) Verify(statement Statement, commitment Commitment, challenge sigma.ChallengeBytes, response Response) error {
	e := p.mapBytesToChallenge(challenge)
	uToE := new(saferith.Nat).Exp(statement, e, p.nSquared)
	zRhs := new(saferith.Nat).ModMul(commitment, uToE, p.nSquared)
	zLhs := new(saferith.Nat).Exp(response, p.n, p.nSquared)

	if _, eq, _ := zLhs.Cmp(zRhs); eq == 1 {
		return nil
	}

	return errs.NewVerification("verification failed")
}

func (p *protocol) RunSimulator(statement Statement, challenge sigma.ChallengeBytes) (Commitment, Response, error) {
	e := p.mapBytesToChallenge(challenge)
	zInt, err := crand.Int(p.prng, p.nSquared.Big())
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample response")
	}
	z := new(saferith.Nat).SetBig(zInt, p.nSquared.BitLen())

	zToN := new(saferith.Nat).Exp(z, p.n, p.nSquared)
	uToE := new(saferith.Nat).Exp(statement, e, p.nSquared)
	uToEInv := new(saferith.Nat).ModInverse(uToE, p.nSquared)
	a := new(saferith.Nat).ModMul(zToN, uToEInv, p.nSquared)
	return a, z, nil
}

func (*protocol) SpecialSoundness() uint {
	return 2
}

func (p *protocol) ValidateStatement(statement Statement, witness Witness) error {
	lhs := new(saferith.Nat).Exp(witness, p.n, p.nSquared)
	if _, eq, _ := lhs.Cmp(statement); eq == 1 {
		return nil
	}

	return errs.NewValidation("invalid statement")
}

func (p *protocol) GetChallengeBytesLength() int {
	return (p.n.AnnouncedLen() + 7) / 8
}

func (*protocol) SerializeStatement(statement Statement) []byte {
	return (*saferith.Nat)(statement).Bytes()
}

func (*protocol) SerializeCommitment(commitment Commitment) []byte {
	return (*saferith.Nat)(commitment).Bytes()
}

func (*protocol) SerializeResponse(response Response) []byte {
	return (*saferith.Nat)(response).Bytes()
}

func (*protocol) mapBytesToChallenge(eBytes sigma.ChallengeBytes) *saferith.Nat {
	return new(saferith.Nat).SetBytes(eBytes)
}
