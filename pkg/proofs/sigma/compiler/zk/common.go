package zkcompiler

import (
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptLabel          = "zkCompiler"
	statementLabel           = "zkCompilerStatement"
	challengeCommitmentLabel = "zkCompilerChallengeCommitment"
	commitmentLabel          = "zkCompilerCommitment"
	challengeLabel           = "zkCompilerChallenge"
	responseLabel            = "zkCompilerResponse"
)

type CommitmentScheme commitments.Scheme[hash_comm.Key, hash_comm.Witness, hash_comm.Message, hash_comm.Commitment, *hash_comm.Committer, *hash_comm.Verifier]

type participant[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	sessionId network.SID
	tape      transcripts.Transcript

	protocol   sigma.Protocol[X, W, A, S, Z]
	statement  X
	commitment A
	response   Z
	comm       *hash_comm.Scheme

	round uint
}
