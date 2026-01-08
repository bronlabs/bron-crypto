// Package zk implements a zero-knowledge compiler that transforms honest-verifier
// zero-knowledge (HVZK) sigma protocols into fully zero-knowledge interactive
// protocols using commitment schemes.
//
// The compiler adds a preliminary round where the verifier commits to the challenge
// before seeing the prover's commitment. This prevents a malicious verifier from
// choosing challenges adaptively, ensuring zero-knowledge against any verifier.
//
// The resulting protocol has 5 rounds:
//  1. Verifier commits to challenge
//  2. Prover sends commitment (a)
//  3. Verifier opens challenge commitment
//  4. Prover sends response (z)
//  5. Verifier verifies the proof
package zk

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

// CommitmentScheme is the type alias for the hash-based commitment scheme used
// to commit to verifier challenges.
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
