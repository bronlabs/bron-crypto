package nthroots

import (
	crand "crypto/rand"
	"github.com/copperexchange/krypton-primitives/pkg/base/saferith_ex"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
)

const Name sigma.Name = "ZKPOK_NTH_ROOT"

type Statement []*saferith.Nat

var _ sigma.Statement = Statement(nil)

type Witness []*saferith.Nat

var _ sigma.Witness = Witness(nil)

type Commitment []*saferith.Nat

var _ sigma.Commitment = Commitment(nil)

type State []*saferith.Nat

var _ sigma.State = State(nil)

type Response []*saferith.Nat

var _ sigma.Response = Response(nil)

type protocol struct {
	t     int
	nMod  saferith_ex.Modulus
	nnMod saferith_ex.Modulus
	prng  io.Reader
}

var _ sigma.Protocol[Statement, Witness, Commitment, State, Response] = (*protocol)(nil)

func NewSigmaProtocol(nMod saferith_ex.Modulus, nnMod saferith_ex.Modulus, t int, prng io.Reader) (sigma.Protocol[Statement, Witness, Commitment, State, Response], error) {
	if nMod == nil || nnMod == nil {
		return nil, errs.NewIsNil("n")
	}
	if t < 1 {
		return nil, errs.NewVerification("t must be positive")
	}
	nnCheck := new(saferith.Nat).Mul(nMod.Nat(), nMod.Nat(), -1)
	if nnCheck.Eq(nnMod.Nat()) != 1 {
		return nil, errs.NewVerification("modulus doesn't match")
	}

	if prng == nil {
		prng = crand.Reader
	}

	return &protocol{
		t:     t,
		nMod:  nMod,
		nnMod: nnMod,
		prng:  prng,
	}, nil
}

func (*protocol) Name() sigma.Name {
	return Name
}

func (p *protocol) ComputeProverCommitment(_ Statement, _ Witness) (Commitment, State, error) {
	s := make([]*saferith.Nat, p.t)
	for i := 0; i < p.t; i++ {
		siBig, err := crand.Int(p.prng, p.nnMod.Nat().Big())
		if err != nil {
			return nil, nil, errs.WrapRandomSample(err, "cannot sample commitment")
		}
		s[i] = new(saferith.Nat).SetBig(siBig, p.nnMod.Modulus().BitLen())
	}

	a := p.nnMod.MultiBaseExp(s, p.nMod.Nat())
	return a, s, nil
}

func (p *protocol) ComputeProverResponse(_ Statement, witness Witness, _ Commitment, state State, challenge sigma.ChallengeBytes) (Response, error) {
	e := p.mapBytesToChallenge(challenge)
	vsToE := p.nnMod.MultiBaseExp(witness, e)

	z := make([]*saferith.Nat, p.t)
	for i, vToE := range vsToE {
		z[i] = new(saferith.Nat).ModMul(state[i], vToE, p.nnMod.Modulus())
	}
	return z, nil
}

func (p *protocol) Verify(statement Statement, commitment Commitment, challenge sigma.ChallengeBytes, response Response) error {
	e := p.mapBytesToChallenge(challenge)

	usToE := p.nnMod.MultiBaseExp(statement, e)
	zLhs := p.nnMod.MultiBaseExp(response, p.nMod.Nat())
	for i := range usToE {
		zRhs := new(saferith.Nat).ModMul(commitment[i], usToE[i], p.nnMod.Modulus())
		if zLhs[i].Eq(zRhs) != 1 {
			return errs.NewVerification("verification failed")
		}
	}

	return nil
}

func (p *protocol) RunSimulator(statement Statement, challenge sigma.ChallengeBytes) (Commitment, Response, error) {
	e := p.mapBytesToChallenge(challenge)
	z := make([]*saferith.Nat, p.t)
	for i := range z {
		zInt, err := crand.Int(p.prng, p.nnMod.Nat().Big())
		if err != nil {
			return nil, nil, errs.WrapRandomSample(err, "cannot sample response")
		}
		z[i] = new(saferith.Nat).SetBig(zInt, p.nnMod.Modulus().BitLen())
	}

	zsToN := p.nnMod.MultiBaseExp(z, p.nMod.Nat())
	usToE := p.nnMod.MultiBaseExp(statement, e)
	usToEInv := make([]*saferith.Nat, p.t)
	for i, uToE := range usToE {
		usToEInv[i] = new(saferith.Nat).ModInverse(uToE, p.nnMod.Modulus())
	}

	a := make([]*saferith.Nat, p.t)
	for i := 0; i < p.t; i++ {
		a[i] = new(saferith.Nat).ModMul(zsToN[i], usToEInv[i], p.nnMod.Modulus())
	}

	return a, z, nil
}

func (p *protocol) ValidateStatement(statement Statement, witness Witness) error {
	lhs := p.nnMod.MultiBaseExp(witness, p.nMod.Nat())
	for i := 0; i < p.t; i++ {
		if lhs[i].Eq(statement[i]) != 1 {
			return errs.NewValidation("invalid statement")
		}
	}

	return nil
}

func (p *protocol) GetChallengeBytesLength() int {
	byteLen := (p.nnMod.Modulus().BitLen() + 7) / 8
	return byteLen
}

func (*protocol) SerializeStatement(statement Statement) []byte {
	var xBytes []byte
	for _, x := range statement {
		xBytes = append(xBytes, x.Bytes()...)
	}
	return xBytes
}

func (*protocol) SerializeCommitment(commitment Commitment) []byte {
	var aBytes []byte
	for _, a := range commitment {
		aBytes = append(aBytes, a.Bytes()...)
	}
	return aBytes
}

func (*protocol) SerializeResponse(response Response) []byte {
	var zBytes []byte
	for _, z := range response {
		zBytes = append(zBytes, z.Bytes()...)
	}
	return zBytes
}

func (p *protocol) mapBytesToChallenge(eBytes sigma.ChallengeBytes) *saferith.Nat {
	return new(saferith.Nat).SetBytes(eBytes)
}
