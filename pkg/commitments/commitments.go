package commitments

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

type Name string

type (
	Key        any
	Message    any
	Witness    any
	Commitment any

	ReRandomisableCommitment[C Commitment, W Witness, K Key] interface {
		Commitment
		ReRandomiseWithWitness(K, W) (C, error)
		ReRandomise(K, io.Reader) (C, W, error)
	}
)

type Committer[W Witness, M Message, C Commitment] interface {
	Commit(message M, prng io.Reader) (C, W, error)
	CommitWithWitness(message M, W W) (C, error)
}

type Verifier[W Witness, M Message, C Commitment] interface {
	Verify(commitment C, message M, witness W) error
}

type Scheme[K Key, W Witness, M Message, C Commitment, CO Committer[W, M, C], VF Verifier[W, M, C]] interface {
	Name() Name
	Committer() CO
	Verifier() VF
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
		Commitment
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
		Commitment
		algebra.HomomorphicLike[C, CT]
		algebra.Actable[C, M]
	}, CT algebra.AbelianGroupElement[CT, WT],
	CO Committer[W, M, C], VF Verifier[W, M, C],
	G algebra.AbelianGroup[CT, WT],
] interface {
	HomomorphicScheme[K, W, WT, M, MT, C, CT, CO, VF]
	Group() G
}
