package compiler

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fischlin"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/bronlabs/errs-go/errs"
)

// Name is the identifier for a compiler implementation.
type Name = internal.Name

// NIZKPoKProof is a serialised non-interactive zero-knowledge proof of knowledge.
type NIZKPoKProof = internal.NIZKPoKProof

// NIProver is the interface for generating non-interactive proofs.
type NIProver[X sigma.Statement, W sigma.Witness] = internal.NIProver[X, W]

// NIVerifier is the interface for verifying non-interactive proofs.
type NIVerifier[X sigma.Statement] = internal.NIVerifier[X]

// NonInteractiveProtocol is the interface for a compiled non-interactive protocol
// that can create provers and verifiers for generating and verifying proofs.
type NonInteractiveProtocol[X sigma.Statement, W sigma.Witness] = internal.NonInteractiveProtocol[X, W]

// Compile transforms an interactive sigma protocol into a non-interactive protocol
// using the specified compiler. The compilerName must be one of fiatshamir.Name,
// fischlin.Name, or randfischlin.Name. The prng is used by Fischlin-based compilers
// for randomness during proof generation.
func Compile[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response](compilerName Name, sigmaProtocol sigma.Protocol[X, W, A, S, Z], prng io.Reader) (NonInteractiveProtocol[X, W], error) {
	switch compilerName {
	case fiatshamir.Name:
		return fiatshamir.NewCompiler(sigmaProtocol) //nolint:wrapcheck // pass through
	case fischlin.Name:
		return fischlin.NewCompiler(sigmaProtocol, prng) //nolint:wrapcheck // pass through
	case randfischlin.Name:
		return randfischlin.NewCompiler(sigmaProtocol, prng) //nolint:wrapcheck // pass through
	default:
		return nil, ErrUnsupportedType.WithMessage("unknown compiler name: %s", compilerName)
	}
}

// IsSupported returns true if the given compiler name is a valid, supported compiler.
func IsSupported(name Name) bool {
	switch name {
	case fiatshamir.Name, fischlin.Name, randfischlin.Name:
		return true
	default:
		return false
	}
}

var (
	ErrUnsupportedType = errs.New("unsupported type")
)
