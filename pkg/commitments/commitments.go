package commitments

import "io"

type Commitment any
type Message any
type Opening any
type Scalar any

type Scheme[C Commitment, M Message, O Opening] interface {
	RandomOpening(prng io.Reader) (O, error)
	CommitWithOpening(message M, witness O) (C, error)
	Commit(message M, prng io.Reader) (C, O, error)
	Verify(message M, commitment C, witness O) error
	IsEqual(lhs, rhs C) bool
}

type HomomorphicScheme[C Commitment, M Message, O Opening, S Scalar] interface {
	Scheme[C, M, O]
	CommitmentSum(x C, ys ...C) C
	CommitmentAdd(x, y C) C
	CommitmentSub(x, y C) C
	CommitmentNeg(x C) C
	CommitmentScale(x C, s S) C

	OpeningSum(x O, ys ...O) O
	OpeningAdd(x, y O) O
	OpeningSub(x, y O) O
	OpeningNeg(x O) O
	OpeningScale(x O, s S) O
}
