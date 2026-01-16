// Package internal defines the core interfaces for non-interactive zero-knowledge
// proof compilers.
package internal

import (
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

// Name is the identifier for a compiler implementation (e.g., "FiatShamir", "Fischlin").
type Name string

// NIZKPoKProof is a serialised non-interactive zero-knowledge proof of knowledge.
// The format depends on the compiler that generated it.
type NIZKPoKProof []byte

// NIProver is the interface for generating non-interactive proofs.
// Given a statement and witness, it produces a proof that the prover knows
// a valid witness for the statement.
type NIProver[X sigma.Statement, W sigma.Witness] interface {
	// Prove generates a non-interactive proof for the given statement and witness.
	Prove(statement X, witness W) (NIZKPoKProof, error)
}

// NIVerifier is the interface for verifying non-interactive proofs.
// It checks that a proof is valid for a given statement.
type NIVerifier[X sigma.Statement] interface {
	// Verify checks that the proof is valid for the given statement.
	// Returns nil if verification succeeds, or an error if it fails.
	Verify(statement X, proof NIZKPoKProof) error
}

// NonInteractiveProtocol is the interface for a compiled non-interactive protocol.
// It provides factory methods to create provers and verifiers that share the same
// session ID and transcript for domain separation.
type NonInteractiveProtocol[X sigma.Statement, W sigma.Witness] interface {
	// Name returns the name of this compiler (e.g., "FiatShamir").
	Name() Name
	// SigmaProtocolName returns the name of the underlying sigma protocol.
	SigmaProtocolName() sigma.Name
	// NewProver creates a new prover for generating proofs.
	NewProver(sessionId network.SID, transcript transcripts.Transcript) (NIProver[X, W], error)
	// NewVerifier creates a new verifier for checking proofs.
	NewVerifier(sessionId network.SID, transcript transcripts.Transcript) (NIVerifier[X], error)
}
