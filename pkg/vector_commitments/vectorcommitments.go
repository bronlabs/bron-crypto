package vectorcommitments

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
)

type Vector[VectorElement commitments.Message] interface {
	commitments.Message
	ds.Equatable[Vector[VectorElement]]
}

type VectorCommitment commitments.Commitment

type VectorCommitter[VectorElement commitments.Message, C VectorCommitment, V Vector[VectorElement], O commitments.Opening[V]] interface {
	commitments.Committer[V, C, O]
	OpenAtIndex(index uint, vector V, fullOpening O) (opening commitments.Opening[VectorElement], err error)
}

type VectorVerifier[VectorElement commitments.Message, C VectorCommitment, V Vector[VectorElement], O commitments.Opening[V]] interface {
	commitments.Verifier[V, C, O]
	VerifyAtIndex(index uint, vector V, opening commitments.Opening[VectorElement]) error
}
