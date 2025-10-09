package zkcompiler

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	pedersen_comm "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
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

type participant[X sigma.Statement, XV algebra.PrimeGroupElement[XV, WV], W sigma.Witness, WV algebra.PrimeFieldElement[WV], A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	sessionId network.SID
	tape      transcripts.Transcript

	ck              *pedersen_comm.Key[XV, WV]
	protocol        sigma.Protocol[X, W, A, S, Z]
	statement       X
	commitment      A
	challengeScalar pedersen_comm.Message[WV]
	response        Z
	pedersenGroup   algebra.PrimeGroup[XV, WV]

	round uint
}

func CommitmentScheme[XV algebra.PrimeGroupElement[XV, WV], WV algebra.PrimeFieldElement[WV]](g algebra.PrimeGroup[XV, WV], key *pedersen_comm.Key[XV, WV]) (commitments.Scheme[*pedersen_comm.Witness[WV], *pedersen_comm.Message[WV], *pedersen_comm.Commitment[XV, WV]], error) {
	return pedersen_comm.NewScheme(key)
}

func (p *participant[X, XV, W, WV, A, S, Z]) challengeBytesToPedersenMessage(challengeBytes []byte) (*pedersen_comm.Message[WV], error) {
	if len(challengeBytes) > k256Impl.FqBytes {
		return nil, errs.NewFailed("challenge is too big")
	}

	challengeScalarBytes := make([]byte, k256Impl.FqBytes)
	copy(challengeScalarBytes[k256Impl.FqBytes-len(challengeBytes):], challengeBytes)
	challengeScalar, err := p.pedersenGroup.ScalarStructure().FromBytes(challengeScalarBytes)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "couldn't construct challenge")
	}
	return pedersen_comm.NewMessage(challengeScalar), nil
}

func (p *participant[X, XV, W, WV, A, S, Z]) pedersenMessageToChallengeBytes(message pedersen_comm.Message[WV]) []byte {
	scalarBytes, err := message.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return scalarBytes[k256Impl.FqBytes-p.protocol.GetChallengeBytesLength():]
}
