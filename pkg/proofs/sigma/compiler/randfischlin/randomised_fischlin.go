package randfischlin

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
	Name compiler.Name = "RandomisedFischlin"

	transcriptLabel = "COPPER_KRYPTON_NIZK_R_FISCHLIN-"

	statementLabel  = "statementLabel-"
	commitmentLabel = "commitmentLabel-"
	challengeLabel  = "challengeLabel-"

	Lambda     = base.ComputationalSecurity
	LambdaLog2 = base.ComputationalSecurityLog2
	L          = 8
	R          = Lambda / L
	T          = LambdaLog2 * L
	LBytes     = L / 8
	TBytes     = T / 8
)

type Proof[A sigma.Commitment, Z sigma.Response] struct {
	A []A      `json:"a"`
	E [][]byte `json:"e"`
	Z []Z      `json:"z"`
}

var _ compiler.NICompiler[sigma.Statement, sigma.Witness] = (*rf[
	sigma.Statement, sigma.Witness, sigma.Statement, sigma.State, sigma.Response,
])(nil)

type rf[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response] struct {
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
	prng          io.Reader
}

func NewCompiler[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response](sigmaProtocol sigma.Protocol[X, W, A, S, Z], prng io.Reader) (compiler.NICompiler[X, W], error) {
	if sigmaProtocol == nil {
		return nil, errs.NewIsNil("sigmaProtocol")
	}
	if prng == nil {
		prng = crand.Reader
	}
	if s := sigmaProtocol.SoundnessError(); s < base.ComputationalSecurity {
		return nil, errs.NewArgument("sigmaProtocol soundness (%d) is too low (<%d) for a non-interactive proof",
			s, base.ComputationalSecurity)
	}

	return &rf[X, W, A, S, Z]{
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
		return nil, errs.WrapHashing(err, "couldn't bind to transcript")
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
