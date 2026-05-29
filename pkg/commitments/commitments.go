package commitments

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

type (
	// Name identifies a commitment scheme implementation.
	Name string
	// Message is the plaintext being committed.
	Message any
	// Witness is the secret randomness used to hide the message. It is part of the
	// opening and must stay private until the commitment is revealed.
	Witness any
	// Commitment is the opaque, public commitment value. The self-referential type
	// parameter makes it Equatable, so a recomputed commitment can be compared
	// against the original during verification.
	Commitment[C Commitment[C]] base.Equatable[C]
)

// WitnessSampler samples the randomness (witness) used when committing. Hiding
// relies on the witness being drawn freshly and unpredictably, so prng must be a
// cryptographically secure source.
type WitnessSampler[W Witness] interface {
	SampleWitness(prng io.Reader) (W, error)
}

// CommitmentKey is the public parameter that defines a concrete commitment scheme.
// CommitWithWitness deterministically maps (message, witness) to a commitment, and
// Open verifies a claimed opening (returning ErrVerificationFailed on mismatch).
// Which of binding and hiding is perfect versus computational is scheme-specific;
// see each implementation. K is the self-referential key type, made Equatable so
// keys can be compared.
type CommitmentKey[K CommitmentKey[K, M, W, C], M Message, W Witness, C Commitment[C]] interface {
	Type() Name
	WitnessSampler[W]
	CommitWithWitness(message M, witness W) (C, error)
	Open(commitment C, message M, witness W) error
	base.Equatable[K]
}

// TrapdoorKey is a CommitmentKey augmented with a secret trapdoor. Equivocate uses
// that trapdoor to open an existing commitment to a different message, so binding
// does NOT hold against a trapdoor holder — this is the standard equivocation tool
// used by simulators in security proofs. Export returns the public CommitmentKey
// with the trapdoor stripped. The prng passed to Equivocate corrects the output
// witness' distribution for schemes that require it (a no-op where it is already
// correct).
type TrapdoorKey[K CommitmentKey[K, M, W, C], T TrapdoorKey[K, T, M, W, C], M Message, W Witness, C Commitment[C]] interface {
	CommitmentKey[T, M, W, C]
	Export() K
	Equivocate(message M, witness W, newMessage M, prng io.Reader) (W, error) // prng is needed to correct output witness' distribution if needed.
}

// Homomorphic describes a commitment scheme whose messages, witnesses, and
// commitments each carry an algebraic operation under which committing is a
// homomorphism: combining commitments corresponds to combining the underlying
// messages and witnesses. This supports aggregation, scalar weighting,
// re-randomisation, and message shifting without opening. S is the scalar type for
// the ScalarOp variants.
type Homomorphic[M Message, W Witness, C Commitment[C], S any] interface {
	WitnessSampler[W]

	// WitnessOp combines witnesses; the result opens the CommitmentOp of the
	// corresponding commitments.
	WitnessOp(first, second W, rest ...W) (W, error)
	// WitnessOpInv returns the inverse witness, matching CommitmentOpInv.
	WitnessOpInv(W) (W, error)
	// WitnessScalarOp scales a witness by a scalar, matching CommitmentScalarOp.
	WitnessScalarOp(W, S) (W, error)

	// MessageOp combines messages; a commitment to the result equals the
	// CommitmentOp of the individual commitments.
	MessageOp(first, second M, rest ...M) (M, error)
	// MessageOpInv returns the inverse message, matching CommitmentOpInv.
	MessageOpInv(M) (M, error)
	// MessageScalarOp scales a message by a scalar, matching CommitmentScalarOp.
	MessageScalarOp(M, S) (M, error)

	// CommitmentOp combines commitments; by the homomorphism the result commits to
	// the combined message under the combined witness.
	CommitmentOp(first, second C, rest ...C) (C, error)
	// CommitmentOpInv returns the inverse commitment (negated message and witness).
	CommitmentOpInv(C) (C, error)
	// CommitmentScalarOp scales a commitment, scaling both its message and witness.
	CommitmentScalarOp(C, S) (C, error)

	// ReRandomise blinds a commitment with witnessShift, yielding an unlinkable
	// commitment to the same message; its opening witness is the original combined
	// with witnessShift.
	ReRandomise(commitment C, witnessShift W) (C, error)
	// Shift adds message to the committed value under the same witness.
	Shift(C, M) (C, error)
}

// GroupHomomorphic refines Homomorphic for schemes whose message, witness, and
// commitment spaces are explicit algebraic groups, exposing those groups so callers
// can sample, check membership, and reason about orders. Message and witness groups
// are Group (not FiniteGroup) so that unknown-order groups — e.g. the RSA-based
// integer commitment — are supported.
type GroupHomomorphic[
	M interface {
		Message
		base.Transparent[MV]
	}, MG algebra.Group[MV], MV algebra.GroupElement[MV], // This is not FiniteGroup to support unknown-order groups.
	W interface {
		Witness
		base.Transparent[WV]
	}, WG algebra.Group[WV], WV algebra.GroupElement[WV], // This is not FiniteGroup to support unknown-order groups.
	C interface {
		Commitment[C]
		base.Transparent[CV]
	}, CG algebra.FiniteGroup[CV], CV algebra.GroupElement[CV],
	S any,
] interface {
	Homomorphic[M, W, C, S]

	MessageGroup() MG
	WitnessGroup() WG
	CommitmentGroup() CG
}

// HomomorphicCommitmentKey is a CommitmentKey whose scheme is also Homomorphic.
type HomomorphicCommitmentKey[K HomomorphicCommitmentKey[K, M, W, C, S], M Message, W Witness, C Commitment[C], S any] interface {
	CommitmentKey[K, M, W, C]
	Homomorphic[M, W, C, S]
}

// HomomorphicTrapdoorKey is a TrapdoorKey whose scheme is also Homomorphic: it can
// both equivocate (via the trapdoor) and combine commitments homomorphically.
type HomomorphicTrapdoorKey[K HomomorphicCommitmentKey[K, M, W, C, S], T HomomorphicTrapdoorKey[K, T, M, W, C, S], M Message, W Witness, C Commitment[C], S any] interface {
	TrapdoorKey[K, T, M, W, C]
	Homomorphic[M, W, C, S]
}

// GroupHomomorphicCommitmentKey is a HomomorphicCommitmentKey whose message,
// witness, and commitment spaces are exposed as explicit algebraic groups (see
// GroupHomomorphic).
type GroupHomomorphicCommitmentKey[
	K GroupHomomorphicCommitmentKey[K, M, MG, MV, W, WG, WV, C, CG, CV, S],
	M interface {
		Message
		base.Transparent[MV]
	}, MG algebra.Group[MV], MV algebra.GroupElement[MV],
	W interface {
		Witness
		base.Transparent[WV]
	}, WG algebra.Group[WV], WV algebra.GroupElement[WV],
	C interface {
		Commitment[C]
		base.Transparent[CV]
	}, CG algebra.FiniteGroup[CV], CV algebra.GroupElement[CV],
	S any,
] interface {
	HomomorphicCommitmentKey[K, M, W, C, S]
	GroupHomomorphic[M, MG, MV, W, WG, WV, C, CG, CV, S]
}

// GroupHomomorphicTrapdoorKey is a HomomorphicTrapdoorKey whose message, witness,
// and commitment spaces are exposed as explicit algebraic groups (see
// GroupHomomorphic).
type GroupHomomorphicTrapdoorKey[
	K GroupHomomorphicCommitmentKey[K, M, MG, MV, W, WG, WV, C, CG, CV, S],
	T GroupHomomorphicTrapdoorKey[K, T, M, MG, MV, W, WG, WV, C, CG, CV, S],
	M interface {
		Message
		base.Transparent[MV]
	}, MG algebra.Group[MV], MV algebra.GroupElement[MV],
	W interface {
		Witness
		base.Transparent[WV]
	}, WG algebra.Group[WV], WV algebra.GroupElement[WV],
	C interface {
		Commitment[C]
		base.Transparent[CV]
	}, CG algebra.FiniteGroup[CV], CV algebra.GroupElement[CV],
	S any,
] interface {
	HomomorphicTrapdoorKey[K, T, M, W, C, S]
	GroupHomomorphic[M, MG, MV, W, WG, WV, C, CG, CV, S]
}
