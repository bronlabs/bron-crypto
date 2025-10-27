package randfischlin

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"golang.org/x/crypto/sha3"
)

const (
	Name compiler.Name = "RandomisedFischlin"

	transcriptLabel = "BRON_CRYPTO_NIZK_RANDOMISED_FISCHLIN-"
	crsLabel        = "crsLabel-"
	statementLabel  = "statementLabel-"
	commitmentLabel = "commitmentLabel-"
	challengeLabel  = "challengeLabel-"

	Lambda     = base.ComputationalSecurityBits
	LambdaLog2 = base.ComputationalSecurityLog2Ceil
	L          = 8
	R          = Lambda / L
	T          = LambdaLog2 * L
	LBytes     = L / 8
	TBytes     = T / 8
)

var (
	randomOracle = sha3.New256
)

type Proof[A sigma.Commitment, Z sigma.Response] struct {
	A []A      `cbor:"a"`
	E [][]byte `cbor:"e"`
	Z []Z      `cbor:"z"`
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
	if s := sigmaProtocol.SoundnessError(); s < base.ComputationalSecurityBits {
		return nil, errs.NewArgument("sigmaProtocol soundness (%d) is too low (<%d) for a non-interactive proof",
			s, base.ComputationalSecurityBits)
	}

	return &rf[X, W, A, S, Z]{
		sigmaProtocol: sigmaProtocol,
		prng:          prng,
	}, nil
}

func (c *rf[X, W, A, S, Z]) NewProver(sessionId network.SID, transcript transcripts.Transcript) (compiler.NIProver[X, W], error) {
	if transcript == nil {
		return nil, errs.NewIsNil("transcript")
	}

	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, c.sigmaProtocol.Name(), hex.EncodeToString(sessionId[:]))
	transcript.AppendDomainSeparator(dst)

	return &prover[X, W, A, S, Z]{
		sessionId:     sessionId,
		transcript:    transcript,
		sigmaProtocol: c.sigmaProtocol,
		prng:          c.prng,
	}, nil
}

func (c *rf[X, W, A, S, Z]) NewVerifier(sessionId network.SID, transcript transcripts.Transcript) (compiler.NIVerifier[X, W], error) {
	if transcript == nil {
		return nil, errs.NewIsNil("transcript")
	}

	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, c.sigmaProtocol.Name(), hex.EncodeToString(sessionId[:]))
	transcript.AppendDomainSeparator(dst)

	return &verifier[X, W, A, S, Z]{
		sessionId:     sessionId,
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
