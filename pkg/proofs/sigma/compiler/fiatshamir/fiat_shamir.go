package fiatshamir

import (
	"encoding/hex"
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir/zkmodule"
	compiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
)

const (
	// Name is the identifier for the Fiat-Shamir compiler.
	Name compiler.Name = "FiatShamir"

	transcriptLabel = "BRON_CRYPTO_NIZKP_FIATSHAMIR-"
	statementLabel  = "statementLabel-"
	commitmentLabel = "commitmentLabel-"
	challengeLabel  = "challengeLabel-"
)

// Proof represents a Fiat-Shamir non-interactive proof containing
// the prover's commitment (a), challenge (e), and response (z).
type Proof[A sigma.Commitment, Z sigma.Response] = zkmodule.Proof[A, Z]

type fs[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response] struct {
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
}

// NewCompiler creates a new Fiat-Shamir compiler for the given sigma protocol.
// The sigma protocol must have soundness error at least 2^(-128) to ensure
// computational security of the resulting non-interactive proof.
func NewCompiler[
	X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response,
](sigmaProtocol sigma.Protocol[X, W, A, S, Z]) (compiler.NonInteractiveProtocol[X, W], error) {
	if sigmaProtocol == nil {
		return nil, proofs.ErrInvalidArgument.WithMessage("sigmaProtocol is nil")
	}
	if s := sigmaProtocol.SoundnessError(); s < base.ComputationalSecurityBits {
		return nil, proofs.ErrInvalidArgument.WithMessage("sigmaProtocol soundness (%d) is too low (<%d) for a non-interactive proof",
			s, base.ComputationalSecurityBits)
	}
	return &fs[X, W, A, S, Z]{
		sigmaProtocol: sigmaProtocol,
	}, nil
}

// NewProver creates a new non-interactive prover for generating Fiat-Shamir proofs.
// The sessionID and transcript are used for domain separation.
func (c *fs[X, W, A, S, Z]) NewProver(ctx *session.Context) (compiler.NIProver[X, W], error) {
	if ctx == nil {
		return nil, proofs.ErrInvalidArgument.WithMessage("ctx is nil")
	}
	sid := ctx.SessionID()
	dst := fmt.Sprintf("%s-%s-%s", hex.EncodeToString(sid[:]), transcriptLabel, c.sigmaProtocol.Name())
	ctx.Transcript().AppendDomainSeparator(dst)

	return &prover[X, W, A, S, Z]{
		ctx:           ctx,
		sigmaProtocol: c.sigmaProtocol,
	}, nil
}

// NewVerifier creates a new non-interactive verifier for checking Fiat-Shamir proofs.
// The sessionID and transcript must match those used by the prover.
func (c *fs[X, W, A, S, Z]) NewVerifier(ctx *session.Context) (compiler.NIVerifier[X], error) {
	if ctx == nil {
		return nil, proofs.ErrInvalidArgument.WithMessage("ctx is nil")
	}
	sid := ctx.SessionID()
	dst := fmt.Sprintf("%s-%s-%s", hex.EncodeToString(sid[:]), transcriptLabel, c.sigmaProtocol.Name())
	ctx.Transcript().AppendDomainSeparator(dst)

	return &verifier[X, W, A, S, Z]{
		ctx:           ctx,
		sigmaProtocol: c.sigmaProtocol,
	}, nil
}

// Name returns the compiler name ("FiatShamir").
func (*fs[_, _, _, _, _]) Name() compiler.Name {
	return Name
}

// SigmaProtocolName returns the name of the underlying sigma protocol.
func (c *fs[_, _, _, _, _]) SigmaProtocolName() sigma.Name {
	return c.sigmaProtocol.Name()
}
