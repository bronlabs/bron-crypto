package nthroots

import (
	crand "crypto/rand"
	"io"

	"github.com/cronokirby/saferith"
	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/modular"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma"
)

const Name sigma.Name = "ZKPOK_NTH_ROOTS"

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
	nMod  modular.FastModulus
	nnMod modular.FastModulus
	prng  io.Reader
}

var _ sigma.Protocol[Statement, Witness, Commitment, State, Response] = (*protocol)(nil)

func NewSigmaProtocol(nMod modular.FastModulus, t int, prng io.Reader) (sigma.Protocol[Statement, Witness, Commitment, State, Response], error) {
	if nMod == nil {
		return nil, errs.NewIsNil("n")
	}
	if t < 1 {
		return nil, errs.NewVerification("t must be positive")
	}

	if prng == nil {
		prng = crand.Reader
	}

	return &protocol{
		t:     t,
		nMod:  nMod,
		nnMod: nMod.Square(),
		prng:  prng,
	}, nil
}

func (*protocol) Name() sigma.Name {
	return Name
}

func (p *protocol) ComputeProverCommitment(_ Statement, _ Witness) (Commitment, State, error) {
	s := make([]*saferith.Nat, p.t)
	for i := 0; i < p.t; i++ {
		siBig, err := crand.Int(p.prng, p.nnMod.Modulus().Nat().Big())
		if err != nil {
			return nil, nil, errs.WrapRandomSample(err, "cannot sample commitment")
		}
		s[i] = new(saferith.Nat).SetBig(siBig, p.nnMod.Modulus().BitLen())
	}

	a, err := p.nnMod.MultiBaseExp(s, p.nMod.Modulus().Nat())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot compute exp")
	}

	return a, s, nil
}

func (p *protocol) ComputeProverResponse(_ Statement, witness Witness, _ Commitment, state State, challenge sigma.ChallengeBytes) (Response, error) {
	e := p.mapBytesToChallenge(challenge)
	vsToE, err := p.nnMod.MultiBaseExp(witness, e)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute exp")
	}

	z := make([]*saferith.Nat, p.t)
	for i, vToE := range vsToE {
		z[i] = new(saferith.Nat).ModMul(state[i], vToE, p.nnMod.Modulus())
	}
	return z, nil
}

func (p *protocol) Verify(statement Statement, commitment Commitment, challenge sigma.ChallengeBytes, response Response) error {
	e := p.mapBytesToChallenge(challenge)

	if len(statement) != len(response) {
		return errs.NewVerification("verification failed")
	}
	usToE := make([]*saferith.Nat, len(statement))
	zLhs := make([]*saferith.Nat, len(response))

	var errGroup errgroup.Group
	errGroup.Go(func() error {
		var err error
		usToE, err = p.nnMod.MultiBaseExp(statement, e)
		return err //nolint:wrapcheck // checked on errGroup.Wait
	})
	errGroup.Go(func() error {
		var err error
		zLhs, err = p.nnMod.MultiBaseExp(response, p.nMod.Modulus().Nat())
		return err //nolint:wrapcheck // checked on errGroup.Wait
	})
	err := errGroup.Wait()
	if err != nil {
		return errs.WrapFailed(err, "cannot compute exp")
	}

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
		zInt, err := crand.Int(p.prng, p.nnMod.Modulus().Big())
		if err != nil {
			return nil, nil, errs.WrapRandomSample(err, "cannot sample response")
		}
		z[i] = new(saferith.Nat).SetBig(zInt, p.nnMod.Modulus().BitLen())
	}

	zsToN, err := p.nnMod.MultiBaseExp(z, p.nMod.Modulus().Nat())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot compute exp")
	}
	usToE, err := p.nnMod.MultiBaseExp(statement, e)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot compute exp")
	}

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
	lhs, err := p.nnMod.MultiBaseExp(witness, p.nMod.Modulus().Nat())
	if err != nil {
		return errs.WrapFailed(err, "cannot compute exp")
	}

	for i := 0; i < p.t; i++ {
		if lhs[i].Eq(statement[i]) != 1 {
			return errs.NewValidation("invalid statement")
		}
	}

	return nil
}

func (p *protocol) SoundnessError() int {
	return p.nMod.Modulus().BitLen()
}

func (*protocol) SpecialSoundness() uint {
	return 2
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

func (*protocol) mapBytesToChallenge(eBytes sigma.ChallengeBytes) *saferith.Nat {
	return new(saferith.Nat).SetBytes(eBytes)
}
