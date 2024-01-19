package randomised_fischlin

import (
	crand "crypto/rand"
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	domainSeparationTag = "COPPER_SIGMA_NIZKPOK_RANDOMISED_FISCHLIN-"

	sessionIdLabel  = "sessionIdLabel"
	statementLabel  = "statementLabel"
	commitmentLabel = "commitmentLabel"
	challengeLabel  = "challengeLabel"

	lambda         = base.ComputationalSecurity
	lambdaNextPow2 = lambda | (lambda >> 1) | (lambda >> 2) | (lambda >> 4) | (lambda >> 8) | (lambda >> 16)
	lambdaLog2     = lambdaNextPow2 & ^(lambdaNextPow2 >> 1)
	l              = 8
	r              = lambda / l
	t              = lambdaLog2 * l
	lBytes         = l / 8
	tBytes         = t / 8
)

type Proof[A sigma.Commitment, E sigma.Challenge, Z sigma.Response] struct {
	A []A `json:"a"`
	E []E `json:"e"`
	Z []Z `json:"z"`
}

var _ compiler.NICompiler[sigma.Statement, sigma.Witness] = (*rf[
	sigma.Statement, sigma.Witness, sigma.Statement, sigma.CommitmentState, sigma.Challenge, sigma.Response,
])(nil)

type rf[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.CommitmentState, E sigma.Challenge, Z sigma.Response] struct {
	sigmaProtocol sigma.Protocol[X, W, A, S, E, Z]
	prng          io.Reader
}

func NewCompiler[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.CommitmentState, E sigma.Challenge, Z sigma.Response](sigmaProtocol sigma.Protocol[X, W, A, S, E, Z], prng io.Reader) (compiler.NICompiler[X, W], error) {
	if sigmaProtocol == nil {
		return nil, errs.NewIsNil("sigmaProtocol")
	}
	if prng == nil {
		prng = crand.Reader
	}

	return &rf[X, W, A, S, E, Z]{
		sigmaProtocol: sigmaProtocol,
		prng:          prng,
	}, nil
}

func (c rf[X, W, A, S, E, Z]) NewProver(sessionId []byte, transcript transcripts.Transcript) (compiler.NIProver[X, W], error) {
	if len(sessionId) == 0 {
		return nil, errs.NewInvalidArgument("sessionId is empty")
	}

	dst := fmt.Sprintf("%s-%s", domainSeparationTag, c.sigmaProtocol.DomainSeparationLabel())
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, nil)
	} else {
		transcript.AppendMessages("DST", []byte(dst))
	}
	transcript.AppendMessages(sessionIdLabel, sessionId)

	return &prover[X, W, A, S, E, Z]{
		sessionId:     sessionId,
		transcript:    transcript,
		sigmaProtocol: c.sigmaProtocol,
		prng:          c.prng,
	}, nil
}

func (c rf[X, W, A, S, E, Z]) NewVerifier(sessionId []byte, transcript transcripts.Transcript) (compiler.NIVerifier[X], error) {
	if len(sessionId) == 0 {
		return nil, errs.NewInvalidArgument("sessionId is empty")
	}

	dst := fmt.Sprintf("%s-%s", domainSeparationTag, c.sigmaProtocol.DomainSeparationLabel())
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, nil)
	} else {
		transcript.AppendMessages("DST", []byte(dst))
	}
	transcript.AppendMessages(sessionIdLabel, sessionId)

	return &verifier[X, W, A, S, E, Z]{
		sessionId:     sessionId,
		transcript:    transcript,
		sigmaProtocol: c.sigmaProtocol,
	}, nil
}
