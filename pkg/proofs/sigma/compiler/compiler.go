package compiler

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fischlin"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/internal"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/randfischlin"
)

type Name = internal.Name

type NIZKPoKProof = internal.NIZKPoKProof

type NIProver[X sigma.Statement, W sigma.Witness] = internal.NIProver[X, W]

type NIVerifier[X sigma.Statement] = internal.NIVerifier[X]

type NICompiler[X sigma.Statement, W sigma.Witness] = internal.NICompiler[X, W]

func Compile[X sigma.Statement, W sigma.Witness, A sigma.Statement, S sigma.State, Z sigma.Response](compilerName Name, sigmaProtocol sigma.Protocol[X, W, A, S, Z], prng io.Reader) (NICompiler[X, W], error) {
	switch compilerName {
	case fiatshamir.Name:
		return fiatshamir.NewCompiler(sigmaProtocol)
	case fischlin.Name:
		return fischlin.NewCompiler(sigmaProtocol, prng)
	case randfischlin.Name:
		return randfischlin.NewCompiler(sigmaProtocol, prng)
	default:
		return nil, errs.NewArgument("unknown compiler name: %s", compilerName)
	}
}
