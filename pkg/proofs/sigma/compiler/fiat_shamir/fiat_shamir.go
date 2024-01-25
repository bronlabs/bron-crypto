package fiatShamir

import (
	"fmt"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	Name compiler.Name = "FiatShamir"

	domainSeparationTag = "COPPER_SIGMA_NIZKPOK_FIAT_SHAMIR-"
	sessionIdLabel      = "sessionIdLabel"
	statementLabel      = "statementLabel"
	commitmentLabel     = "commitmentLabel"
	challengeLabel      = "challengeLabel"
)

type Proof[A sigma.Commitment, Z sigma.Response] struct {
	A A `json:"a"`
	Z Z `json:"z"`
}

var _ compiler.NICompiler[sigma.Statement, sigma.Witness] = (*fs[
	sigma.Statement, sigma.Witness, sigma.Statement, sigma.State, sigma.Response,
])(nil)

type fs[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response] struct {
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
}

func NewCompiler[
	X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response,
](sigmaProtocol sigma.Protocol[X, W, A, S, Z]) (compiler.NICompiler[X, W], error) {
	return &fs[X, W, A, S, Z]{
		sigmaProtocol: sigmaProtocol,
	}, nil
}

func (c fs[X, W, A, S, Z]) NewProver(sessionId []byte, transcript transcripts.Transcript) (compiler.NIProver[X, W], error) {
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

	return &prover[X, W, A, S, Z]{
		transcript:    transcript,
		sigmaProtocol: c.sigmaProtocol,
	}, nil
}

func (c fs[X, W, A, S, Z]) NewVerifier(sessionId []byte, transcript transcripts.Transcript) (compiler.NIVerifier[X], error) {
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

	return &verifier[X, W, A, S, Z]{
		transcript:    transcript,
		sigmaProtocol: c.sigmaProtocol,
	}, nil
}
