package zkcompiler

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	pedersen_comm "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
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

var pedersenCommitmentCurve = k256.NewCurve()

type participant[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	sessionId []byte
	tape      transcripts.Transcript

	ck              *pedersen_comm.CommittingKey
	protocol        sigma.Protocol[X, W, A, S, Z]
	statement       X
	commitment      A
	challengeScalar pedersen_comm.Message
	response        Z

	round uint
}

func (*participant[X, W, A, S, Z]) challengeBytesToPedersenMessage(challengeBytes []byte) (pedersen_comm.Message, error) {
	if len(challengeBytes) > k256Impl.FqBytes {
		return nil, errs.NewFailed("challenge is too big")
	}

	challengeScalarBytes := make([]byte, k256Impl.FqBytes)
	copy(challengeScalarBytes[k256Impl.FqBytes-len(challengeBytes):], challengeBytes)
	challengeScalar, err := pedersenCommitmentCurve.ScalarField().Element().SetBytes(challengeScalarBytes)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "couldn't construct challenge")
	}

	return challengeScalar, nil
}

func (p *participant[X, W, A, S, Z]) pedersenMessageToChallengeBytes(message pedersen_comm.Message) []byte {
	scalarBytes := message.Bytes()
	return scalarBytes[k256Impl.FqBytes-p.protocol.GetChallengeBytesLength():]
}
