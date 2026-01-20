package commitments

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

// Name identifies a commitment scheme implementation.
type Name string

type (
	// Key represents scheme configuration/CRS material.
	Key any
	// Message is the plaintext being committed.
	Message any
	// Witness is the randomness used to hide the message.
	Witness any
	// Commitment is the opaque commitment value.
	Commitment[C any] base.Equatable[C]

	// ReRandomisableCommitment supports re-randomisation of an existing commitment.
	ReRandomisableCommitment[C Commitment[C], W Witness, K Key] interface {
		Commitment[C]
		// ReRandomiseWithWitness re-randomises an existing commitment using caller-supplied witness shift.
		ReRandomiseWithWitness(K, W) (C, error)
		// ReRandomise re-randomises an existing commitment using fresh randomness shift.
		ReRandomise(K, io.Reader) (C, W, error)
	}
)

// Committer produces commitments from messages (and optionally supplied witnesses).
type Committer[W Witness, M Message, C Commitment[C]] interface {
	// Commit samples fresh randomness and commits to a message, returning the commitment and witness.
	Commit(message M, prng io.Reader) (C, W, error)
	// CommitWithWitness commits to a message using caller-supplied witness randomness.
	CommitWithWitness(message M, W W) (C, error)
}

// Verifier checks commitments against messages and witnesses.
type Verifier[W Witness, M Message, C Commitment[C]] interface {
	// Verify checks commitments against provided messages and witnesses.
	Verify(commitment C, message M, witness W) error
}

// Scheme exposes a commitment protocol with its committer, verifier, and key material.
type Scheme[K Key, W Witness, M Message, C Commitment[C], CO Committer[W, M, C], VF Verifier[W, M, C]] interface {
	// Name returns the identifier of the commitment scheme.
	Name() Name
	// Committer returns a committer configured with the scheme.
	Committer() CO
	// Verifier returns a verifier compatible with commitments produced by the scheme.
	Verifier() VF
	// Key exposes the scheme key.
	Key() K
}

// ******** Homomorphic.

type HomomorphicScheme[
	K Key,
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
	K Key,
	W interface {
		Witness
		algebra.HomomorphicLike[W, WT]
	}, WT algebra.UintLike[WT],
	M interface {
		Message
		algebra.HomomorphicLike[M, MT]
	}, MT algebra.UintLike[MT],
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
