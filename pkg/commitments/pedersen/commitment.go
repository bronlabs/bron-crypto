package pedersen

type (
	Name       string
	Message    any
	Commitment any
	Witness    any
)

type Committer[M Message, C Commitment, W Witness] interface {
	Commit(sessionId []byte, message M) (C, W, error)
}

type Opener[M Message, C Commitment, W Witness] interface {
	Open(sessionId []byte, commitment C, witness W, message M) error
}

type CommitmentScheme[M Message, C Commitment, W Witness] interface {
	Committer[M, C, W]
	Opener[M, C, W]
}
