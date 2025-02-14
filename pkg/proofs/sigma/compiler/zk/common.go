package zkcompiler

import (
	hashcommitments "github.com/bronlabs/krypton-primitives/pkg/commitments/hash"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts"
)

const (
	transcriptLabel          = "zkCompiler"
	statementLabel           = "zkCompilerStatement"
	challengeCommitmentLabel = "zkCompilerChallengeCommitment"
	commitmentLabel          = "zkCompilerCommitment"
	challengeLabel           = "zkCompilerChallenge"
	responseLabel            = "zkCompilerResponse"
)

type participant[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	sessionId []byte
	tape      transcripts.Transcript

	ck             *hashcommitments.CommittingKey
	protocol       sigma.Protocol[X, W, A, S, Z]
	statement      X
	commitment     A
	challengeBytes sigma.ChallengeBytes
	response       Z

	round uint
}
