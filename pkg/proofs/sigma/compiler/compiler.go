package compiler

import (
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

type NIZKPoKProof any

type NIProver[X sigma.Statement, W sigma.Witness] interface {
	Prove(statement X, witness W) (NIZKPoKProof, error)
}

type NIVerifier[X sigma.Statement] interface {
	Verify(statement X, proof NIZKPoKProof) error
}

type NICompiler[X sigma.Statement, W sigma.Witness] interface {
	NewProver(sid []byte, transcript transcripts.Transcript) (NIProver[X, W], error)
	NewVerifier(sid []byte, transcript transcripts.Transcript) (NIVerifier[X], error)
}
