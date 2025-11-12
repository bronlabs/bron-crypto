package fischlin

import (
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	compiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	Name compiler.Name = "Fischlin"

	transcriptLabel = "BRON_CRYPTO_NIZK_FISCHLIN-"

	rhoLabel        = "rhoLabel-"
	statementLabel  = "statementLabel-"
	commitmentLabel = "commitmentLabel-"
	challengeLabel  = "challengeLabel-"
	responseLabel   = "responseLabel-"
)

var (
	randomOracle = sha3.New256
)

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

func NewCompiler[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response](sigmaProtocol sigma.Protocol[X, W, A, S, Z], prng io.Reader) (compiler.NonInteractiveProtocol[X, W], error) {
	if sigmaProtocol == nil || prng == nil {
		return nil, errs.NewIsNil("sigmaProtocol or prng")
	}

	// For rho, b, t parameters a target soundness error is 2^(-128). For more information how they should be chosen, refer to
	// "Optimising and Implementing Fischlin's Transform for UC-Secure Zero-Knowledge" by Chen & Lindell,
	// chapter 4 ("Optimal Parameters and Experimental Results").
	rho := getRho(sigmaProtocol)
	b1 := (base.ComputationalSecurityBits + rho - 1) / rho
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

func (c *simplifiedFischlin[X, W, A, S, Z]) NewProver(sessionId network.SID, transcript transcripts.Transcript) (compiler.NIProver[X, W], error) {
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
		rho:           c.rho,
		b:             c.b,
		t:             c.t,
	}, nil
}

func (c *simplifiedFischlin[X, W, A, S, Z]) NewVerifier(sessionId network.SID, transcript transcripts.Transcript) (compiler.NIVerifier[X], error) {
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

func (*simplifiedFischlin[_, _, _, _, _]) Name() compiler.Name {
	return Name
}

func (c *simplifiedFischlin[_, _, _, _, _]) SigmaProtocolName() sigma.Name {
	return c.sigmaProtocol.Name()
}
