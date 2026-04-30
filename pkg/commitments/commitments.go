package commitments

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

// Name identifies a commitment scheme implementation.
type Name string

type (
	// CommitmentKey represents scheme configuration/CRS material.
	CommitmentKey                                      any
	TrapdoorKey[K CommitmentKey, M Message, W Witness] interface {
		// CommitmentKey returns the commitment key associated with the trapdoor.
		CommitmentKey() K
	}
	// Message is the plaintext being committed.
	Message any
	// Witness is the randomness used to hide the message.
	Witness any
	// Commitment is the opaque commitment value.
	Commitment[C any] base.Equatable[C]

	// ReRandomisableCommitment supports re-randomisation of an existing commitment.
	ReRandomisableCommitment[C Commitment[C], W Witness, K CommitmentKey] interface {
		Commitment[C]
		// ReRandomiseWithWitness re-randomises an existing commitment using caller-supplied witness shift.
		ReRandomiseWithWitness(K, W) (C, error)
		// ReRandomise re-randomises an existing commitment using fresh randomness shift.
		ReRandomise(K, io.Reader) (C, W, error)
	}
)

type (
	// Committer produces commitments from messages (and optionally supplied witnesses).
	Committer[W Witness, M Message, C Commitment[C]] interface {
		// Commit samples fresh randomness and commits to a message, returning the commitment and witness.
		Commit(message M, prng io.Reader) (C, W, error)
		// CommitWithWitness commits to a message using caller-supplied witness randomness.
		CommitWithWitness(message M, W W) (C, error)
	}

	// CommitterOption is a functional option for configuring committers.
	CommitterOption[
		COM Committer[W, M, C], W Witness, M Message, C Commitment[C],
	] = func(COM) error
)

// Verifier checks commitments against messages and witnesses.
type (
	Verifier[W Witness, M Message, C Commitment[C]] interface {
		// Verify checks commitments against provided messages and witnesses.
		Verify(commitment C, message M, witness W) error
	}

	// VerifierOption is a functional option for configuring verifiers.
	VerifierOption[
		VF Verifier[W, M, C], W Witness, M Message, C Commitment[C],
	] = func(VF) error
)

// Scheme exposes a commitment protocol with its committer, verifier, and key material.
type Scheme[K CommitmentKey, W Witness, M Message, C Commitment[C], COM Committer[W, M, C], VF Verifier[W, M, C]] interface {
	// Name returns the identifier of the commitment scheme.
	Name() Name
	// Committer returns a committer configured with the scheme.
	Committer(...CommitterOption[COM, W, M, C]) (COM, error)
	// Verifier returns a verifier compatible with commitments produced by the scheme.
	Verifier(...VerifierOption[VF, W, M, C]) (VF, error)
	// Key exposes the scheme key.
	Key() K
}

// EquivocableScheme extends Scheme with a trapdoor key for equivocation of commitments.
type EquivocableScheme[K CommitmentKey, T TrapdoorKey[K, M, W], W Witness, M Message, C Commitment[C], COM Committer[W, M, C], VF Verifier[W, M, C]] interface {
	Scheme[K, W, M, C, COM, VF]
	// Equivocate produces a witness that opens a commitment to a new message, given
	// the original message and witness. prng is consumed when the equivocator must
	// re-randomise the output to match the honest witness distribution; flavours
	// whose canonical equivocated witness already follows the honest distribution
	// may ignore prng but must not panic on a nil reader.
	Equivocate(message M, witness W, newMessage M, prng io.Reader) (W, error)
	// Trapdoor returns a trapdoor key that can be used to equivocate commitments.
	TrapdoorKey() T
}

// ******** Homomorphic.

type HomomorphicScheme[
	K CommitmentKey,
	W interface {
		Witness
		algebra.HomomorphicLike[W, WT]
	}, WT algebra.GroupElement[WT],
	M interface {
		Message
		algebra.HomomorphicLike[M, MT]
	}, MT algebra.GroupElement[MT],
	C interface {
		Commitment[C]
		algebra.HomomorphicLike[C, CT]
		algebra.Actable[C, M]
	}, CT algebra.GroupElement[CT],
	CO Committer[W, M, C], VF Verifier[W, M, C],
] Scheme[K, W, M, C, CO, VF]

type GroupHomomorphicScheme[
	K CommitmentKey,
	W interface {
		Witness
		algebra.HomomorphicLike[W, WT]
	}, WT algebra.RingElement[WT],
	M interface {
		Message
		algebra.HomomorphicLike[M, MT]
	}, MT algebra.RingElement[MT],
	C interface {
		Commitment[C]
		algebra.HomomorphicLike[C, CT]
		algebra.Actable[C, M]
	}, CT algebra.AbelianGroupElement[CT, WT],
	CO Committer[W, M, C], VF Verifier[W, M, C],
	G algebra.AbelianGroup[CT, WT],
] interface {
	HomomorphicScheme[K, W, WT, M, MT, C, CT, CO, VF]
	// Group exposes the group structure.
	Group() G
}
