package compiler

// TODO: add fischlin/rfischlin compiler

import (
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

type Name string

type NIZKPoKProof []byte

type NIProver[X sigma.Statement, W sigma.Witness] interface {
	Prove(statement X, witness W) (NIZKPoKProof, error)
}

type NIVerifier[X sigma.Statement, W sigma.Witness] interface {
	Verify(statement X, proof NIZKPoKProof) error
}

type NICompiler[X sigma.Statement, W sigma.Witness] interface {
	Name() Name
	SigmaProtocolName() sigma.Name
	NewProver(sessionId network.SID, transcript transcripts.Transcript) (NIProver[X, W], error)
	NewVerifier(sessionId network.SID, transcript transcripts.Transcript) (NIVerifier[X, W], error)
}
