package zkmodule

import (
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

// Transcript labels providing domain separation for each absorbed message.
// They bind the proof to its role (statement, commitment, challenge, response)
// so that bytes absorbed in one position can never be reinterpreted in another,
// which is what makes the Fiat-Shamir challenge depend unambiguously on the
// whole (statement, commitment) prefix.
const (
	statementLabel  = "BRON_CRYPTO_CGGMP21_ZKMODULE_ZK_STATEMENT-"
	commitmentLabel = "BRON_CRYPTO_CGGMP21_ZKMODULE_ZK_COMMITMENT-"
	challengeLabel  = "BRON_CRYPTO_CGGMP21_ZKMODULE_ZK_CHALLENGE-"
	responseLabel   = "BRON_CRYPTO_CGGMP21_ZKMODULE_ZK_RESPONSE-"
)

// Proof is a non-interactive sigma-protocol proof produced by the Fiat-Shamir
// transform of CGGMP21 Figure 3. It holds the prover's first message
// (commitment a), the challenge e derived from the random oracle over
// (statement, a), and the response z. The challenge is carried alongside the
// transcript so that a verifier can re-derive it independently and reject any
// proof whose recorded challenge does not match the one bound by the transcript
// hash; this is what makes the transform sound in the random-oracle model.
type Proof[A sigma.Commitment, Z sigma.Response] struct {
	a A
	e sigma.ChallengeBytes
	z Z
}

// proofDTO is the wire representation of a Proof. It is the deserialisation
// trust boundary: UnmarshalCBOR rebuilds a Proof from it only after validating
// every field.
type proofDTO[A sigma.Commitment, Z sigma.Response] struct {
	A A                    `cbor:"A"`
	E sigma.ChallengeBytes `cbor:"E"`
	Z Z                    `cbor:"Z"`
}

// Commitment returns the prover's first sigma message a (the commitment).
func (p *Proof[A, Z]) Commitment() A {
	return p.a
}

// Challenge returns the Fiat-Shamir challenge e bound to this proof. It is the
// byte string the verifier must reproduce by hashing (statement, a); a mismatch
// means the proof was not generated against this transcript.
func (p *Proof[A, Z]) Challenge() sigma.ChallengeBytes {
	return p.e
}

// Response returns the prover's response z to the challenge e.
func (p *Proof[A, Z]) Response() Z {
	return p.z
}

// MarshalCBOR serialises the proof (commitment, challenge, response) to CBOR.
func (p *Proof[A, Z]) MarshalCBOR() ([]byte, error) {
	dto := &proofDTO[A, Z]{
		A: p.a,
		E: p.e,
		Z: p.z,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal proof")
	}
	return data, nil
}

// UnmarshalCBOR deserialises a proof from CBOR. As the decoding trust boundary
// it rejects a structurally well-formed but cryptographically meaningless proof:
// a missing commitment or response, or an empty challenge, can never verify and
// must not be silently accepted, so each is reported as proofs.ErrInvalidArgument.
func (p *Proof[A, Z]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*proofDTO[A, Z]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot unmarshal proof")
	}
	if dto == nil {
		return proofs.ErrInvalidArgument.WithMessage("proof cannot be nil")
	}
	if utils.IsNil(dto.A) {
		return proofs.ErrInvalidArgument.WithMessage("commitment (A) cannot be nil")
	}
	if len(dto.E) == 0 {
		return proofs.ErrInvalidArgument.WithMessage("challenge (E) cannot be nil")
	}
	if utils.IsNil(dto.Z) {
		return proofs.ErrInvalidArgument.WithMessage("response (Z) cannot be nil")
	}
	p.a = dto.A
	p.e = dto.E
	p.z = dto.Z
	return nil
}

// Commit runs the first move of the sigma protocol, returning the commitment a
// and the secret prover state s, without yet deriving or binding a challenge.
//
// Keeping commitment generation separate from challenge derivation is the
// defining feature of CGGMP21 Figure 3: it lets the caller fold a into a larger
// session transcript before the challenge is sampled, which is what enables
// straight-line (forking-lemma-free) witness extraction in the random-oracle
// model. The returned state s is secret prover randomness and must be handed
// back to Prove unchanged; it must not be exposed to the verifier.
func Commit[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](protocol sigma.Protocol[X, W, A, S, Z], statement X, witness W) (commitment A, state S, err error) {
	var nilA A
	var nilS S
	if protocol == nil {
		return nilA, nilS, proofs.ErrInvalidArgument.WithMessage("protocol is nil")
	}

	a, s, err := protocol.ComputeProverCommitment(statement, witness)
	if err != nil {
		return nilA, nilS, errs.Wrap(err).WithMessage("cannot commit")
	}
	return a, s, nil
}

// Prove completes the Fiat-Shamir transform for a commitment previously
// produced by Commit on the same statement and witness. It absorbs the
// statement and commitment into the session transcript, extracts the challenge
// e from the transcript hash (the random-oracle query, sized to the protocol's
// challenge length), computes the response z, absorbs z to keep prover and
// verifier transcripts in lock-step, and returns the proof (a, e, z).
//
// Deriving e from the transcript rather than from a verifier message is what
// makes the proof non-interactive; binding it to (statement, a) is what makes it
// sound. The same ctx must drive any surrounding protocol so the transcript
// state matches the verifier's at the point e is extracted.
func Prove[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](ctx *session.Context, protocol sigma.Protocol[X, W, A, S, Z], statement X, witness W, commitment A, state S) (*Proof[A, Z], error) {
	if ctx == nil || protocol == nil {
		return nil, proofs.ErrInvalidArgument.WithMessage("ctx/protocol is nil")
	}

	ctx.Transcript().AppendBytes(statementLabel, statement.Bytes())
	ctx.Transcript().AppendBytes(commitmentLabel, commitment.Bytes())
	e, err := ctx.Transcript().ExtractBytes(challengeLabel, uint(protocol.GetChallengeBytesLength()))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot sample challenge")
	}

	z, err := protocol.ComputeProverResponse(statement, witness, commitment, state, e)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot prove")
	}
	ctx.Transcript().AppendBytes(responseLabel, z.Bytes())

	return &Proof[A, Z]{
		a: commitment,
		e: e,
		z: z,
	}, nil
}

// Verify checks a Fiat-Shamir proof against the statement. It replays the same
// transcript absorption as Prove — statement then commitment — re-derives the
// challenge e' from the transcript hash, and rejects the proof unless e' equals
// the challenge recorded in the proof. Recomputing the challenge is what binds
// the proof to (statement, a) and forecloses a prover choosing e after seeing a;
// only then is the underlying sigma relation checked. The response is finally
// absorbed so the verifier's transcript ends identical to the prover's.
//
// The challenge comparison is on public, transcript-derived bytes, so the
// non-constant-time slices.Equal leaks nothing secret.
func Verify[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](ctx *session.Context, protocol sigma.Protocol[X, W, A, S, Z], statement X, proof *Proof[A, Z]) error {
	if ctx == nil || protocol == nil || proof == nil {
		return proofs.ErrInvalidArgument.WithMessage("ctx/protocol/proof is nil")
	}

	ctx.Transcript().AppendBytes(statementLabel, statement.Bytes())
	ctx.Transcript().AppendBytes(commitmentLabel, proof.a.Bytes())
	ePrime, err := ctx.Transcript().ExtractBytes(challengeLabel, uint(protocol.GetChallengeBytesLength()))
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot sample challenge")
	}
	if !slices.Equal(ePrime, proof.e) {
		return proofs.ErrVerificationFailed.WithMessage("invalid proof")
	}
	if err := protocol.Verify(statement, proof.a, ePrime, proof.z); err != nil {
		return proofs.ErrVerificationFailed.WithMessage("invalid proof")
	}
	ctx.Transcript().AppendBytes(responseLabel, proof.z.Bytes())

	return nil
}
