package sigma

import (
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

const (
	domainSeparationTag = "COPPER_SIGMA_POK-"

	sessionIdLabel  = "sessionIdLabel"
	statementLabel  = "statementLabel"
	commitmentLabel = "commitmentLabel"
	challengeLabel  = "challengeLabel"
	responseLabel   = "responseLabel"
)

type (
	Statement       any
	Witness         any
	Commitment      any
	CommitmentState any
	Challenge       any
	Response        any
)

type Protocol[X Statement, W Witness, A Commitment, S CommitmentState, E Challenge, Z Response] interface {
	GenerateCommitment(statement X, witness W) (A, S, error)
	GenerateChallenge(entropy []byte) (E, error)
	GenerateResponse(statement X, witness W, state S, challenge E) (Z, error)
	Verify(statement X, commitment A, challenge E, response Z) error

	DomainSeparationLabel() string
	SerializeStatement(statement X) []byte
	SerializeCommitment(commitment A) []byte
	SerializeChallenge(challenge E) []byte
	SerializeResponse(response Z) []byte
}

type participant[X Statement, W Witness, A Commitment, S CommitmentState, E Challenge, Z Response] struct {
	sessionId  []byte
	transcript transcripts.Transcript

	sigmaProtocol Protocol[X, W, A, S, E, Z]
	statement     X
	commitment    A
	challenge     E
	response      Z

	round uint
}
