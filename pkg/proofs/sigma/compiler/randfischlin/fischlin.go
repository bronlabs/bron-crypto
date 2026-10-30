package randfischlin

import (
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	compiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
)

const (
	// Name is the identifier for the Randomised Fischlin compiler.
	Name compiler.Name = "RandomisedFischlin"

	transcriptLabel = "BRON_CRYPTO_NIZK_RANDOMISED_FISCHLIN-"
	crsLabel        = "crsLabel-"
	statementLabel  = "statementLabel-"
	commitmentLabel = "commitmentLabel-"
	challengeLabel  = "challengeLabel-"
)

var (
	randomOracle = sha3.New256
)

// Proof represents a randomised Fischlin non-interactive proof containing r
// parallel executions of the sigma protocol. Each execution includes a
// commitment (A), challenge (E), and response (Z). The parameters are not
// carried in the proof; the verifier derives them from its sigma protocol.
type Proof[A sigma.Commitment, Z sigma.Response] struct {
	A []A      `cbor:"a"`
	E [][]byte `cbor:"e"`
	Z []Z      `cbor:"z"`
}

type proofDTO[A sigma.Commitment, Z sigma.Response] struct {
	A []A      `cbor:"a"`
	E [][]byte `cbor:"e"`
	Z []Z      `cbor:"z"`
}

// UnmarshalCBOR deserialises a randomised Fischlin proof and validates its
// proof elements. The number of repetitions is checked by the verifier.
func (p *Proof[A, Z]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*proofDTO[A, Z]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot unmarshal proof")
	}
	if dto == nil || len(dto.A) == 0 || len(dto.A) != len(dto.E) || len(dto.A) != len(dto.Z) {
		return proofs.ErrInvalidArgument.WithMessage("invalid proof dimensions")
	}
	for i := range dto.A {
		if utils.IsNil(dto.A[i]) || len(dto.E[i]) == 0 || utils.IsNil(dto.Z[i]) {
			return proofs.ErrInvalidArgument.WithMessage("proof contains an invalid element at index %d", i)
		}
	}
	p.A = dto.A
	p.E = dto.E
	p.Z = dto.Z
	return nil
}

// Protocol implements the NonInteractiveProtocol interface for randomised Fischlin proofs.
type Protocol[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response] struct {
	params

	sigmaProtocol sigma.Protocol[X, W, A, S, Z]
	prng          io.Reader
}

// NewCompiler creates a new randomised Fischlin compiler for the given sigma protocol.
// The sigma protocol must be strongly n-special sound for some n >= 2 and have soundness
// error at least 2^(-128); the transform parameters are derived from n (see newParams),
// so n-special sound protocols such as batch proofs are supported at the cost of
// (n - 1) times more hash evaluations for the prover. The prng is used for randomness
// during proof generation.
func NewCompiler[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response](sigmaProtocol sigma.Protocol[X, W, A, S, Z], prng io.Reader) (*Protocol[X, W, A, S, Z], error) {
	if sigmaProtocol == nil || prng == nil {
		return nil, proofs.ErrInvalidArgument.WithMessage("sigmaProtocol or prng is nil")
	}

	if s := sigmaProtocol.SoundnessError(); s < base.ComputationalSecurityBits {
		return nil, proofs.ErrInvalidArgument.WithMessage("sigmaProtocol soundness (%d) is too low (<%d) for a non-interactive proof",
			s, base.ComputationalSecurityBits)
	}

	parameters, err := newParams(sigmaProtocol.SpecialSoundness(), sigmaProtocol.GetChallengeBytesLength())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot derive parameters")
	}

	return &Protocol[X, W, A, S, Z]{
		params:        parameters,
		sigmaProtocol: sigmaProtocol,
		prng:          prng,
	}, nil
}

// NewProver creates a new non-interactive prover for generating randomised Fischlin proofs.
// The sessionID and transcript are used for domain separation.
func (c *Protocol[X, W, A, S, Z]) NewProver(ctx *session.Context) (compiler.NIProver[X, W], error) {
	if ctx == nil {
		return nil, proofs.ErrInvalidArgument.WithMessage("ctx is nil")
	}

	sessionID := ctx.SessionID()
	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, c.sigmaProtocol.Name(), hex.EncodeToString(sessionID[:]))
	ctx.Transcript().AppendDomainSeparator(dst)

	return &Prover[X, W, A, S, Z]{
		params:        c.params,
		ctx:           ctx,
		sigmaProtocol: c.sigmaProtocol,
		prng:          c.prng,
	}, nil
}

// NewVerifier creates a new non-interactive verifier for checking randomised Fischlin proofs.
// The sessionID and transcript must match those used by the prover.
func (c *Protocol[X, W, A, S, Z]) NewVerifier(ctx *session.Context) (compiler.NIVerifier[X], error) {
	if ctx == nil {
		return nil, proofs.ErrInvalidArgument.WithMessage("ctx is nil")
	}

	sessionID := ctx.SessionID()
	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, c.sigmaProtocol.Name(), hex.EncodeToString(sessionID[:]))
	ctx.Transcript().AppendDomainSeparator(dst)

	return &Verifier[X, W, A, S, Z]{
		params:        c.params,
		ctx:           ctx,
		sigmaProtocol: c.sigmaProtocol,
	}, nil
}

// Name returns the compiler name ("RandomisedFischlin").
func (*Protocol[_, _, _, _, _]) Name() compiler.Name {
	return Name
}

// SigmaProtocolName returns the name of the underlying sigma protocol.
func (c *Protocol[_, _, _, _, _]) SigmaProtocolName() sigma.Name {
	return c.sigmaProtocol.Name()
}
