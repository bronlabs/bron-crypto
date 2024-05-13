package veccomm

import "github.com/copperexchange/krypton-primitives/pkg/comm"

type Vector[M comm.Message] []M

type VectorCommitment interface {
	comm.Commitment
}

type VectorCommitter[M comm.Message, C VectorCommitment, O comm.Opening[Vector[M]]] interface {
	comm.Committer[Vector[M], C, O]
	OpenAtIndex(index uint, vector Vector[M], fullOpening O) (opening comm.Opening[M], err error)
}

type VectorVerifier[M comm.Message, C VectorCommitment, O comm.Opening[Vector[M]]] interface {
	comm.Verifier[Vector[M], C, O]
	VerifyAtIndex(index uint, vector Vector[M], opening comm.Opening[M]) error
}
