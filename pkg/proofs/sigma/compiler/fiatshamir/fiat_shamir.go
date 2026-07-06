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

	// transcriptLabel domain-separates this compiler's transcript from other
	// protocols sharing the session. The per-message labels (statement,
	// commitment, challenge, response) are owned by the zkmodule engine, which
	// performs the actual absorption and challenge derivation.
	transcriptLabel = "BRON_CRYPTO_NIZKP_FIATSHAMIR-"
)

// Proof is a Fiat-Shamir non-interactive proof: the prover's commitment (a),
// the challenge (e) derived from the transcript hash, and the response (z). It
// is an alias for the engine type zkmodule.Proof, so proofs produced here
// (de)serialise identically to that type.
type Proof[A sigma.Commitment, Z sigma.Response] = zkmodule.Proof[A, Z]

// Protocol implements the NonInteractiveProtocol interface for Fiat-Shamir proofs.
type Protocol[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response] struct {
	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
}

// NewCompiler creates a new Fiat-Shamir compiler for the given sigma protocol.
// The sigma protocol must have soundness error at least 2^(-128) to ensure
// computational security of the resulting non-interactive proof.
func NewCompiler[
	X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response,
](sigmaProtocol sigma.Protocol[X, W, A, S, Z]) (*Protocol[X, W, A, S, Z], error) {
	if sigmaProtocol == nil {
		return nil, proofs.ErrInvalidArgument.WithMessage("sigmaProtocol is nil")
	}
	if s := sigmaProtocol.SoundnessError(); s < base.ComputationalSecurityBits {
		return nil, proofs.ErrInvalidArgument.WithMessage("sigmaProtocol soundness (%d) is too low (<%d) for a non-interactive proof",
			s, base.ComputationalSecurityBits)
	}
	return &Protocol[X, W, A, S, Z]{
		sigmaProtocol: sigmaProtocol,
	}, nil
}

// NewProver returns a non-interactive prover bound to ctx. The session ID and
// the underlying sigma-protocol name are folded into a transcript domain
// separator so that proofs from different sessions or protocols cannot be
// cross-replayed.
func (c *Protocol[X, W, A, S, Z]) NewProver(ctx *session.Context) (compiler.NIProver[X, W], error) {
	if ctx == nil {
		return nil, proofs.ErrInvalidArgument.WithMessage("ctx is nil")
	}
	sid := ctx.SessionID()
	dst := fmt.Sprintf("%s-%s-%s", hex.EncodeToString(sid[:]), transcriptLabel, c.sigmaProtocol.Name())
	ctx.Transcript().AppendDomainSeparator(dst)

	return &Prover[X, W, A, S, Z]{
		ctx:           ctx,
		sigmaProtocol: c.sigmaProtocol,
	}, nil
}

// NewVerifier returns a non-interactive verifier bound to ctx. It applies the
// same domain separator as NewProver; the verifier's session must match the
// prover's, otherwise the challenge recomputed from the transcript will not
// agree with the one in the proof.
func (c *Protocol[X, W, A, S, Z]) NewVerifier(ctx *session.Context) (compiler.NIVerifier[X], error) {
	if ctx == nil {
		return nil, proofs.ErrInvalidArgument.WithMessage("ctx is nil")
	}
	sid := ctx.SessionID()
	dst := fmt.Sprintf("%s-%s-%s", hex.EncodeToString(sid[:]), transcriptLabel, c.sigmaProtocol.Name())
	ctx.Transcript().AppendDomainSeparator(dst)

	return &Verifier[X, W, A, S, Z]{
		ctx:           ctx,
		sigmaProtocol: c.sigmaProtocol,
	}, nil
}

// Name returns the compiler name ("FiatShamir").
func (*Protocol[_, _, _, _, _]) Name() compiler.Name {
	return Name
}

// SigmaProtocolName returns the name of the underlying sigma protocol.
func (c *Protocol[_, _, _, _, _]) SigmaProtocolName() sigma.Name {
	return c.sigmaProtocol.Name()
}
