package fischlin

import (
	crand "crypto/rand"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	Name compiler.Name = "Fischlin"

	transcriptLabel = "COPPER_KRYPTON_NIZK_FISCHLIN-"

	statementLabel  = "statementLabel-"
	commitmentLabel = "commitmentLabel-"
	challengeLabel  = "challengeLabel-"
)

type Proof[A sigma.Commitment, Z sigma.Response] struct {
	Rho uint     `json:"rho"`
	B   uint     `json:"b"`
	A   []A      `json:"a"`
	E   [][]byte `json:"e"`
	Z   []Z      `json:"z"`
}

var _ compiler.NICompiler[sigma.Statement, sigma.Witness] = (*rf[
	sigma.Statement, sigma.Witness, sigma.Statement, sigma.State, sigma.Response,
])(nil)

type rf[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response] struct {
	rho           uint
	b             uint
	t             uint
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
	prng          io.Reader
}

func NewCompiler[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response](sigmaProtocol sigma.Protocol[X, W, A, S, Z], rho uint, prng io.Reader) (compiler.NICompiler[X, W], error) {
	if sigmaProtocol == nil {
		return nil, errs.NewIsNil("sigmaProtocol")
	}
	if prng == nil {
		prng = crand.Reader
	}

	b := (base.ComputationalSecurity + rho - 1) / rho
	t := b + 5
	if rho > 64 {
		t = b + 6
	}

	return &rf[X, W, A, S, Z]{
		rho:           rho,
		b:             b,
		t:             t,
		sigmaProtocol: sigmaProtocol,
		prng:          prng,
	}, nil
}

func (c *rf[X, W, A, S, Z]) NewProver(sessionId []byte, transcript transcripts.Transcript) (compiler.NIProver[X, W], error) {
	if len(sessionId) == 0 {
		return nil, errs.NewArgument("sessionId is empty")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, c.sigmaProtocol.Name())
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, c.prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	return &prover[X, W, A, S, Z]{
		sessionId:     boundSessionId,
		transcript:    transcript,
		sigmaProtocol: c.sigmaProtocol,
		prng:          c.prng,
	}, nil
}

func (c *rf[X, W, A, S, Z]) NewVerifier(sessionId []byte, transcript transcripts.Transcript) (compiler.NIVerifier[X], error) {
	if len(sessionId) == 0 {
		return nil, errs.NewArgument("sessionId is empty")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, c.sigmaProtocol.Name())
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, c.prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	return &verifier[X, W, A, S, Z]{
		sessionId:     boundSessionId,
		transcript:    transcript,
		sigmaProtocol: c.sigmaProtocol,
	}, nil
}

func (*rf[_, _, _, _, _]) Name() compiler.Name {
	return Name
}

func (c *rf[_, _, _, _, _]) SigmaProtocolName() sigma.Name {
	return c.sigmaProtocol.Name()
}
