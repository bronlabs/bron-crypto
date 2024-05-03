package veccomm

import "github.com/copperexchange/krypton-primitives/pkg/comm"

type Vector[M comm.Message] []M

type VectorCommitment interface {
	comm.Commitment
	Length() uint
}

// type VectorOpening interface {
// 	comm.Opening[V Vector[comm.Message]]
// 	Length() uint
// }

type VectorCommitter[M comm.Message, V Vector[M], C VectorCommitment, O comm.Opening[V]] interface {
	comm.Committer[V, C, O]
	OpenAtIndex(index uint, vector V, fullOpening O) (opening comm.Opening[M], err error)
}

type VectorVerifier[M comm.Message, V Vector[M], C VectorCommitment, O comm.Opening[V]] interface {
	comm.Verifier[V, C, O]
	VerifyAtIndex(index uint, vector V, opening comm.Opening[M]) error
}
