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
	Statement  any
	Witness    any
	Commitment any
	State      any
	Response   any
)

type Protocol[X Statement, W Witness, A Commitment, S State, Z Response] interface {
	ComputeProverCommitment(statement X, witness W) (A, S, error)
	ComputeProverResponse(statement X, witness W, commitment A, state S, challenge []byte) (Z, error)
	Verify(statement X, commitment A, challenge []byte, response Z) error

	// RunSimulator produces a transcript that's statistically identical to (or indistinguishable from)
	// the output of the real Prover.
	// In the context of Honest-Verifier Zero-Knowledge Proofs of Knowledge,
	// the simulator is an algorithm that is able to fake a commitment and a convincing proof
	// without knowledge of the witness
	// In order to fake it, the simulator "rewinds" (aka does things in reverse order):
	// first create a response, and then compute the commitment intelligently so that the full transcript (a, e, z)
	// would be valid if played in the right order.
	RunSimulator(statement X, challenge []byte) (A, Z, error)

	ValidateStatement(statement X, witness W) error
	GetChallengeBytesLength() int

	DomainSeparationLabel() string
	SerializeStatement(statement X) []byte
	SerializeCommitment(commitment A) []byte
	SerializeResponse(response Z) []byte
}

type participant[X Statement, W Witness, A Commitment, S State, Z Response] struct {
	sessionId  []byte
	transcript transcripts.Transcript

	sigmaProtocol  Protocol[X, W, A, S, Z]
	statement      X
	commitment     A
	challengeBytes []byte
	response       Z

	round uint
}
