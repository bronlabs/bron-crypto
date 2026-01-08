// Package fischlin implements the Fischlin transform for compiling interactive
// sigma protocols into non-interactive zero-knowledge proofs with UC security.
//
// Fischlin's transform provides universally composable (UC) security, which is
// stronger than the standard Fiat-Shamir transform. It achieves this by requiring
// the prover to find challenge/response pairs that hash to zero.
//
// The parameters rho (number of repetitions), b (hash output bits), and t (search
// bound) are computed based on the sigma protocol's special soundness property to
// achieve a target soundness error of 2^(-128).
//
// Reference: "Optimising and Implementing Fischlin's Transform for UC-Secure
// Zero-Knowledge" by Chen & Lindell.
package fischlin

import (
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	compiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	// Name is the identifier for the Fischlin compiler.
	Name compiler.Name = "Fischlin"

	transcriptLabel = "BRON_CRYPTO_NIZK_FISCHLIN-"

	commonHLabel    = "commonHLabel-"
	rhoLabel        = "rhoLabel-"
	statementLabel  = "statementLabel-"
	commitmentLabel = "commitmentLabel-"
	challengeLabel  = "challengeLabel-"
	responseLabel   = "responseLabel-"
)

var (
	randomOracle = sha3.New256
)

// Proof represents a Fischlin non-interactive proof containing rho parallel
// executions of the sigma protocol. Each execution includes a commitment (A),
// challenge (E), and response (Z). The Rho and B parameters are included
// for verification.
type Proof[A sigma.Commitment, Z sigma.Response] struct {
	Rho uint64   `cbor:"rho"`
	B   uint64   `cbor:"b"`
	A   []A      `cbor:"a"`
	E   [][]byte `cbor:"e"`
	Z   []Z      `cbor:"z"`
}

var _ compiler.NonInteractiveProtocol[sigma.Statement, sigma.Witness] = (*simplifiedFischlin[
	sigma.Statement, sigma.Witness, sigma.Statement, sigma.State, sigma.Response,
])(nil)

type simplifiedFischlin[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response] struct {
	rho           uint64
	b             uint64
	t             uint64
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
	prng          io.Reader
}

// NewCompiler creates a new Fischlin compiler for the given sigma protocol.
// The prng is used for randomness during proof generation.
func NewCompiler[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response](sigmaProtocol sigma.Protocol[X, W, A, S, Z], prng io.Reader) (compiler.NonInteractiveProtocol[X, W], error) {
	if sigmaProtocol == nil || prng == nil {
		return nil, ErrNil.WithMessage("sigmaProtocol or prng")
	}

	rho := getRho(sigmaProtocol)
	b1 := (base.ComputationalSecurityBits + rho - 1) / rho
	b2 := uint64(mathutils.CeilLog2(int(sigmaProtocol.SpecialSoundness()) - 1))
	b := b1 + b2
	t := b + 5
	if rho > 64 {
		t = b + 6
	}
	if rho < 2 || b < 2 || t >= 64 {
		return nil, ErrInvalid.WithMessage("invalid rho")
	}

	return &simplifiedFischlin[X, W, A, S, Z]{
		rho:           rho,
		b:             b,
		t:             t,
		sigmaProtocol: sigmaProtocol,
		prng:          prng,
	}, nil
}

// NewProver creates a new non-interactive prover for generating Fischlin proofs.
// The sessionId and transcript are used for domain separation.
func (c *simplifiedFischlin[X, W, A, S, Z]) NewProver(sessionId network.SID, transcript transcripts.Transcript) (compiler.NIProver[X, W], error) {
	if transcript == nil {
		return nil, ErrNil.WithMessage("transcript")
	}

	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, c.sigmaProtocol.Name(), hex.EncodeToString(sessionId[:]))
	transcript.AppendDomainSeparator(dst)

	return &prover[X, W, A, S, Z]{
		sessionId:     sessionId,
		transcript:    transcript,
		sigmaProtocol: c.sigmaProtocol,
		prng:          c.prng,
		rho:           c.rho,
		b:             c.b,
		t:             c.t,
	}, nil
}

// NewVerifier creates a new non-interactive verifier for checking Fischlin proofs.
// The sessionId and transcript must match those used by the prover.
func (c *simplifiedFischlin[X, W, A, S, Z]) NewVerifier(sessionId network.SID, transcript transcripts.Transcript) (compiler.NIVerifier[X], error) {
	if transcript == nil {
		return nil, ErrNil.WithMessage("transcript")
	}

	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, c.sigmaProtocol.Name(), hex.EncodeToString(sessionId[:]))
	transcript.AppendDomainSeparator(dst)

	return &verifier[X, W, A, S, Z]{
		sessionId:     sessionId,
		transcript:    transcript,
		sigmaProtocol: c.sigmaProtocol,
	}, nil
}

// Name returns the compiler name ("Fischlin").
func (*simplifiedFischlin[_, _, _, _, _]) Name() compiler.Name {
	return Name
}

// SigmaProtocolName returns the name of the underlying sigma protocol.
func (c *simplifiedFischlin[_, _, _, _, _]) SigmaProtocolName() sigma.Name {
	return c.sigmaProtocol.Name()
}
