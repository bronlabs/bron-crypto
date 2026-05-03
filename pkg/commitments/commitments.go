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
	// Witness is the randomness used to hide the message.
	Witness any
	// Commitment is the opaque commitment value.
	Commitment[C any] base.Equatable[C]
)

type WitnessSampler[W Witness] interface {
	SampleWitness(prng io.Reader) (W, error)
}

type CommitmentKey[K CommitmentKey[K, M, W, C], M Message, W Witness, C Commitment[C]] interface {
	WitnessSampler[W]
	CommitWithWitness(message M, witness W) (C, error)
	Open(commitment C, message M, witness W) error
	base.Equatable[K]
}

type TrapdoorKey[K CommitmentKey[K, M, W, C], T TrapdoorKey[K, T, M, W, C], M Message, W Witness, C Commitment[C]] interface {
	CommitmentKey[T, M, W, C]
	Export() K
	Equivocate(message M, witness W, newMessage M, prng io.Reader) (W, error) // prng is needed to correct output witness' distribution if needed.
}

type Homomorphic[M Message, W Witness, C Commitment[C], S any] interface {
	WitnessSampler[W]

	WitnessOp(first, second W, rest ...W) (W, error)
	WitnessOpInv(W) (W, error)
	WitnessScalarOp(W, S) (W, error)

	MessageOp(first, second M, rest ...M) (M, error)
	MessageOpInv(M) (M, error)
	MessageScalarOp(M, S) (M, error)

	CommitmentOp(first, second C, rest ...C) (C, error)
	CommitmentOpInv(C) (C, error)
	CommitmentScalarOp(C, S) (C, error)

	ReRandomise(commitment C, witnessShift W) (C, error)
	Shift(C, M) (C, error)
}

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
type HomomorphicCommitmentKey[K HomomorphicCommitmentKey[K, M, W, C, S], M Message, W Witness, C Commitment[C], S any] interface {
	CommitmentKey[K, M, W, C]
	Homomorphic[M, W, C, S]
}

type HomomorphicTrapdoorKey[K HomomorphicCommitmentKey[K, M, W, C, S], T HomomorphicTrapdoorKey[K, T, M, W, C, S], M Message, W Witness, C Commitment[C], S any] interface {
	TrapdoorKey[K, T, M, W, C]
	Homomorphic[M, W, C, S]
}

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
