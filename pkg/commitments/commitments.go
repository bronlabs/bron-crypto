package commitments

import (
	"github.com/cronokirby/saferith"
)

type (
	Name       string
	Message    any
	Commitment any
)

type Opening[M Message] interface {
	Message() M
}

type HomomorphicCommitmentScheme[M Message, C Commitment, O Opening[M]] interface {
	CombineCommitments(x C, ys ...C) (C, error)
	ScaleCommitment(x C, n *saferith.Nat) (C, error)

	CombineOpenings(x O, ys ...O) (O, error)
	ScaleOpening(x O, n *saferith.Nat) (O, error)
}

type Committer[M Message, C Commitment, O Opening[M]] interface {
	Commit(message M) (C, O, error)
}

type HomomorphicCommitter[M Message, C Commitment, O Opening[M]] interface {
	Committer[M, C, O]
	HomomorphicCommitmentScheme[M, C, O]
}

type Verifier[M Message, C Commitment, O Opening[M]] interface {
	Verify(commitment C, opening O) error
}

type HomomorphicVerifier[M Message, C Commitment, O Opening[M]] interface {
	Verifier[M, C, O]
	HomomorphicCommitmentScheme[M, C, O]
}
