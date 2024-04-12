package sigma

import (
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

const (
	transcriptLabel = "COPPER_KRYPTON_SIGMA_POK-"

	statementLabel  = "statementLabel-"
	commitmentLabel = "commitmentLabel-"
	challengeLabel  = "challengeLabel-"
	responseLabel   = "responseLabel-"
)

type (
	Name       string
	Statement  any
	Witness    any
	Commitment any
	State      any
	Response   any
	// Sigma protocols are defined on an arbitrary [enumerable] challenge space. Our implementation choice is to enforce working with a binary encoding of a challenge. This is to make OR-composition easier.
	// Internally, each implementation for the sigma protocol interface will deserialize ChallengeBytes into their own suitable challenge type.
	ChallengeBytes []byte
)

type Protocol[X Statement, W Witness, A Commitment, S State, Z Response] interface {
	Name() Name
	ComputeProverCommitment(statement X, witness W) (A, S, error)
	ComputeProverResponse(statement X, witness W, commitment A, state S, challenge ChallengeBytes) (Z, error)
	Verify(statement X, commitment A, challenge ChallengeBytes, response Z) error

	// RunSimulator produces a transcript that's statistically identical to (or indistinguishable from)
	// the output of the real Prover.
	// In the context of Honest-Verifier Zero-Knowledge Proofs of Knowledge,
	// the simulator is an algorithm that is able to fake a commitment and a convincing proof
	// without knowledge of the witness
	// In order to fake it, the simulator "rewinds" (aka does things in reverse order):
	// first create a response, and then compute the commitment intelligently so that the full transcript (a, e, z)
	// would be valid if played in the right order.
	RunSimulator(statement X, challenge ChallengeBytes) (A, Z, error)

	// SpecialSoundness returns n for which protocol has n-special soundness.
	// In other words it returns minimal number of how many distinct, valid
	// sigma protocol transcripts T_i = (x, e_i, z_i) for i = 1, 2, ..., n
	// are required for existence of polynomial-time extractor of witness.
	SpecialSoundness() uint

	ValidateStatement(statement X, witness W) error
	GetChallengeBytesLength() int
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
