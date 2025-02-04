package fischlin

import (
	crand "crypto/rand"
	"fmt"
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/utils"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	Name compiler.Name = "Fischlin"

	transcriptLabel = "BRONLABS_KRYPTON_NIZK_FISCHLIN-"

	rhoLabel        = "rhoLabel-"
	statementLabel  = "statementLabel-"
	commitmentLabel = "commitmentLabel-"
	challengeLabel  = "challengeLabel-"
	responseLabel   = "responseLabel-"
)

type Proof[A sigma.Commitment, Z sigma.Response] struct {
	Rho uint64   `json:"rho"`
	B   uint64   `json:"b"`
	A   []A      `json:"a"`
	E   [][]byte `json:"e"`
	Z   []Z      `json:"z"`
}

var _ compiler.NICompiler[sigma.Statement, sigma.Witness] = (*simplifiedFischlin[
	sigma.Statement, sigma.Witness, sigma.Statement, sigma.State, sigma.Response,
])(nil)

type simplifiedFischlin[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response] struct {
	rho           uint64
	b             uint64
	t             uint64
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
	prng          io.Reader
}

func NewCompiler[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response](sigmaProtocol sigma.Protocol[X, W, A, S, Z], rho uint64, prng io.Reader) (compiler.NICompiler[X, W], error) {
	if sigmaProtocol == nil {
		return nil, errs.NewIsNil("sigmaProtocol")
	}
	if prng == nil {
		prng = crand.Reader
	}

	// For rho, b, t parameters a target soundness error is 2^(-128). For more information how they should be chosen refer to
	// "Optimising and Implementing Fischlin's Transform for UC-Secure Zero-Knowledge" by Chen & Lindell,
	// chapter 4 ("Optimal Parameters and Experimental Results").
	b1 := (base.ComputationalSecurity + rho - 1) / rho
	b2 := uint64(utils.CeilLog2(int(sigmaProtocol.SpecialSoundness()) - 1))
	b := b1 + b2
	t := b + 5
	if rho > 64 {
		t = b + 6
	}
	if rho < 2 || b < 2 || t >= 64 {
		return nil, errs.NewArgument("invalid rho")
	}

	return &simplifiedFischlin[X, W, A, S, Z]{
		rho:           rho,
		b:             b,
		t:             t,
		sigmaProtocol: sigmaProtocol,
		prng:          prng,
	}, nil
}

func (c *simplifiedFischlin[X, W, A, S, Z]) NewProver(sessionId []byte, transcript transcripts.Transcript) (compiler.NIProver[X, W], error) {
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
		rho:           c.rho,
		b:             c.b,
		t:             c.t,
	}, nil
}

func (c *simplifiedFischlin[X, W, A, S, Z]) NewVerifier(sessionId []byte, transcript transcripts.Transcript) (compiler.NIVerifier[X], error) {
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

func (*simplifiedFischlin[_, _, _, _, _]) Name() compiler.Name {
	return Name
}

func (c *simplifiedFischlin[_, _, _, _, _]) SigmaProtocolName() sigma.Name {
	return c.sigmaProtocol.Name()
}
