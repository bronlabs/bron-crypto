package commitments

import "io"

type Commitment any
type Message any
type Witness any
type Scalar any

type Scheme[C Commitment, M Message, W Witness] interface {
	RandomWitness(prng io.Reader) W
	CommitWithWitness(message M, witness W) C
	Commit(message M, prng io.Reader) (C, W)
	Verify(message M, commitment C, witness W) error
	IsEqual(lhs, rhs C) bool
}

type HomomorphicScheme[C Commitment, M Message, W Witness, S Scalar] interface {
	Scheme[C, M, W]
	CommitmentSum(x C, ys ...C) C
	CommitmentAdd(x, y C) C
	CommitmentSub(x, y C) C
	CommitmentNeg(x C) C
	CommitmentScale(x C, s S) C

	WitnessSum(x W, ys ...W) W
	WitnessAdd(x, y W) W
	WitnessSub(x, y W) W
	WitnessNeg(x W) W
	WitnessScale(x W, s S) W
}
