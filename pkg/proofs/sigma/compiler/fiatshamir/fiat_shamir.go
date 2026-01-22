// Package fiatshamir implements the Fiat-Shamir transform for compiling interactive
// sigma protocols into non-interactive zero-knowledge proofs.
//
// The Fiat-Shamir transform replaces the verifier's random challenge with a hash
// of the transcript, making the protocol non-interactive. This is a simple and
// efficient approach that provides computational security.
//
// The transform requires that the underlying sigma protocol has soundness error
// at least 2^(-128) to ensure computational security of the resulting NIZK proof.
package fiatshamir

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	compiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/errs"
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
// the prover's commitment (a) and response (z).
type Proof[A sigma.Commitment, Z sigma.Response] struct {
	a A
	z Z
}

type proofDTO[A sigma.Commitment, Z sigma.Response] struct {
	A A `cbor:"A"`
	Z Z `cbor:"Z"`
}

// MarshalCBOR serialises the proof to CBOR format.
func (p *Proof[A, Z]) MarshalCBOR() ([]byte, error) {
	dto := &proofDTO[A, Z]{
		A: p.a,
		Z: p.z,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal Fiat-Shamir proof")
	}
	return data, nil
}

// UnmarshalCBOR deserializes the proof from CBOR format.
func (p *Proof[A, Z]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*proofDTO[A, Z]](data)
	if err != nil {
		return err
	}
	p.a = dto.A
	p.z = dto.Z
	return nil
}

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
		return nil, ErrNil.WithMessage("sigmaProtocol")
	}
	if s := sigmaProtocol.SoundnessError(); s < base.ComputationalSecurityBits {
		return nil, ErrInvalid.WithMessage("sigmaProtocol soundness (%d) is too low (<%d) for a non-interactive proof",
			s, base.ComputationalSecurityBits)
	}
	return &fs[X, W, A, S, Z]{
		sigmaProtocol: sigmaProtocol,
	}, nil
}

// NewProver creates a new non-interactive prover for generating Fiat-Shamir proofs.
// The sessionID and transcript are used for domain separation.
func (c *fs[X, W, A, S, Z]) NewProver(sessionID network.SID, transcript transcripts.Transcript) (compiler.NIProver[X, W], error) {
	dst := fmt.Sprintf("%s-%s-%s", sessionID, transcriptLabel, c.sigmaProtocol.Name())
	transcript.AppendDomainSeparator(dst)

	return &prover[X, W, A, S, Z]{
		transcript:    transcript,
		sigmaProtocol: c.sigmaProtocol,
	}, nil
}

// NewVerifier creates a new non-interactive verifier for checking Fiat-Shamir proofs.
// The sessionID and transcript must match those used by the prover.
func (c *fs[X, W, A, S, Z]) NewVerifier(sessionID network.SID, transcript transcripts.Transcript) (compiler.NIVerifier[X], error) {
	dst := fmt.Sprintf("%s-%s-%s", sessionID, transcriptLabel, c.sigmaProtocol.Name())
	transcript.AppendDomainSeparator(dst)

	return &verifier[X, W, A, S, Z]{
		transcript:    transcript,
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
