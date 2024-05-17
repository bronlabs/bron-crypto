package vectorcommitments

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
)

//type Vector[M commitments.Message] []M

type Vector[M commitments.Message] interface {
	datastructures.Equatable[M]
}

type VectorCommitment interface {
	commitments.Commitment
	Length() uint
}

type VectorCommitter[M commitments.Message, C VectorCommitment, O commitments.Opening[Vector[M]]] interface {
	commitments.Committer[Vector[M], C, O]
	OpenAtIndex(index uint, vector Vector[M], fullOpening O) (opening commitments.Opening[M], err error)
}

type VectorVerifier[M commitments.Message, C VectorCommitment, O commitments.Opening[Vector[M]]] interface {
	commitments.Verifier[Vector[M], C, O]
	VerifyAtIndex(index uint, vector Vector[M], opening commitments.Opening[M]) error
}
