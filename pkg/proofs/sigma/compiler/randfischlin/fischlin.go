// Package randfischlin implements a randomised variant of Fischlin's transform
// for compiling interactive sigma protocols into non-interactive zero-knowledge proofs.
//
// This variant uses fixed parameters (Lambda=128, L=8, R=16) rather than computing
// them from the protocol's special soundness. Challenges are sampled randomly and
// searched until a hash-to-zero condition is met.
//
// The randomised approach can be more efficient than standard Fischlin for certain
// protocols while maintaining 128-bit computational security.
package randfischlin

import (
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	compiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	// Name is the identifier for the Randomised Fischlin compiler.
	Name compiler.Name = "RandomisedFischlin"

	transcriptLabel = "BRON_CRYPTO_NIZK_RANDOMISED_FISCHLIN-"
	crsLabel        = "crsLabel-"
	statementLabel  = "statementLabel-"
	commitmentLabel = "commitmentLabel-"
	challengeLabel  = "challengeLabel-"

	// Lambda is the computational security parameter in bits.
	Lambda = base.ComputationalSecurityBits
	// LambdaLog2 is the ceiling of log2(Lambda).
	LambdaLog2 = base.ComputationalSecurityLog2Ceil
	// L is the hash output length parameter.
	L = 8
	// R is the number of parallel repetitions.
	R = Lambda / L
	// T is the challenge sampling bound in bits.
	T = LambdaLog2 * L
	// LBytes is L converted to bytes.
	LBytes = L / 8
	// TBytes is T converted to bytes.
	TBytes = T / 8
)

var (
	randomOracle = sha3.New256
)

// Proof represents a randomised Fischlin non-interactive proof containing R
// parallel executions of the sigma protocol. Each execution includes a
// commitment (A), challenge (E), and response (Z).
type Proof[A sigma.Commitment, Z sigma.Response] struct {
	A []A      `cbor:"a"`
	E [][]byte `cbor:"e"`
	Z []Z      `cbor:"z"`
}

var _ compiler.NonInteractiveProtocol[sigma.Statement, sigma.Witness] = (*rf[
	sigma.Statement, sigma.Witness, sigma.Statement, sigma.State, sigma.Response,
])(nil)

type rf[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response] struct {
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
	prng          io.Reader
}

// NewCompiler creates a new randomised Fischlin compiler for the given sigma protocol.
// The sigma protocol must have soundness error at least 2^(-128). The prng is used
// for randomness during proof generation.
func NewCompiler[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response](sigmaProtocol sigma.Protocol[X, W, A, S, Z], prng io.Reader) (compiler.NonInteractiveProtocol[X, W], error) {
	if sigmaProtocol == nil || prng == nil {
		return nil, ErrNil.WithMessage("sigmaProtocol or prng")
	}

	if s := sigmaProtocol.SoundnessError(); s < base.ComputationalSecurityBits {
		return nil, ErrInvalid.WithMessage("sigmaProtocol soundness (%d) is too low (<%d) for a non-interactive proof",
			s, base.ComputationalSecurityBits)
	}

	return &rf[X, W, A, S, Z]{
		sigmaProtocol: sigmaProtocol,
		prng:          prng,
	}, nil
}

// NewProver creates a new non-interactive prover for generating randomised Fischlin proofs.
// The sessionID and transcript are used for domain separation.
func (c *rf[X, W, A, S, Z]) NewProver(sessionID network.SID, transcript transcripts.Transcript) (compiler.NIProver[X, W], error) {
	if transcript == nil {
		return nil, ErrNil.WithMessage("transcript")
	}

	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, c.sigmaProtocol.Name(), hex.EncodeToString(sessionID[:]))
	transcript.AppendDomainSeparator(dst)

	return &prover[X, W, A, S, Z]{
		sessionID:     sessionID,
		transcript:    transcript,
		sigmaProtocol: c.sigmaProtocol,
		prng:          c.prng,
	}, nil
}

// NewVerifier creates a new non-interactive verifier for checking randomised Fischlin proofs.
// The sessionID and transcript must match those used by the prover.
func (c *rf[X, W, A, S, Z]) NewVerifier(sessionID network.SID, transcript transcripts.Transcript) (compiler.NIVerifier[X], error) {
	if transcript == nil {
		return nil, ErrNil.WithMessage("transcript")
	}

	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, c.sigmaProtocol.Name(), hex.EncodeToString(sessionID[:]))
	transcript.AppendDomainSeparator(dst)

	return &verifier[X, W, A, S, Z]{
		sessionID:     sessionID,
		transcript:    transcript,
		sigmaProtocol: c.sigmaProtocol,
	}, nil
}

// Name returns the compiler name ("RandomisedFischlin").
func (*rf[_, _, _, _, _]) Name() compiler.Name {
	return Name
}

// SigmaProtocolName returns the name of the underlying sigma protocol.
func (c *rf[_, _, _, _, _]) SigmaProtocolName() sigma.Name {
	return c.sigmaProtocol.Name()
}
