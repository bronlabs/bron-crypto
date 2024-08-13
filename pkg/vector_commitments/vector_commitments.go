package vectorcommitments

import "io"

type Element any
type Commitment any
type Opening any

type Scheme[C Commitment, E Element, O Opening] interface {
	RandomOpening(prng io.Reader) (O, error)
	CommitWithOpening(vector []E, opening O) (C, error)
	Commit(vector []E, prng io.Reader) (C, O, error)
	Verify(vector []E, commitment C, opening O) error

	CommitmentEqual(lhs, rhs C) bool
}
