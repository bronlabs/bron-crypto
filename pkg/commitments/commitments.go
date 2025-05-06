package commitments

import "io"

type (
	Commitment any
	Message    any
	Witness    any
	Scalar     any
)

type CommittingKey[C Commitment, M Message, W Witness] interface {
	RandomWitness(prng io.Reader) (witness W, err error)
	CommitWithWitness(message M, witness W) (commitment C, err error)
	Commit(message M, prng io.Reader) (commitment C, witness W, err error)
	Verify(commitment C, message M, witness W) (err error)
}

type HomomorphicCommittingKey[C Commitment, M Message, W Witness, S Scalar] interface {
	CommittingKey[C, M, W]

	MessageAdd(lhs, rhs M) (message M, err error)
	MessageSub(lhs, rhs M) (message M, err error)
	MessageNeg(x M) (message M, err error)
	MessageMul(lhs M, rhs S) (message M, err error)

	CommitmentAdd(lhs, rhs C) (commitment C, err error)
	CommitmentAddMessage(lhs C, rhs M) (commitment C, err error)
	CommitmentSub(lhs, rhs C) (commitment C, err error)
	CommitmentSubMessage(lhs C, rhs M) (commitment C, err error)
	CommitmentNeg(x C) (commitment C, err error)
	CommitmentMul(lhs C, rhs S) (commitment C, err error)

	WitnessAdd(lhs, rhs W) (witness W, err error)
	WitnessSub(lhs, rhs W) (witness W, err error)
	WitnessNeg(x W) (witness W, err error)
	WitnessMul(lhs W, rhs S) (witness W, err error)
}
