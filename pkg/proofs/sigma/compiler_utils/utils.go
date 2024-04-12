package compiler_utils

import (
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	fiatShamir "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/fischlin"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
)

var compilers = map[compiler.Name]any{
	fiatShamir.Name:         nil,
	fischlin.Name:           nil,
	randomisedFischlin.Name: nil,
}

func MakeNonInteractive[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](compilerName compiler.Name, protocol sigma.Protocol[X, W, A, S, Z], prng io.Reader) (compiler.NICompiler[X, W], error) {
	switch compilerName {
	case randomisedFischlin.Name:
		rf, err := randomisedFischlin.NewCompiler(protocol, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create randomised fischlin compiler")
		}
		return rf, nil
	case fiatShamir.Name:
		fs, err := fiatShamir.NewCompiler(protocol)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create fiat-shamir compiler")
		}
		return fs, nil
	case fischlin.Name:
		rho := getSimplifiedFischlinRho(protocol.Name())
		sf, err := fischlin.NewCompiler(protocol, rho, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create simplified compiler")
		}
		return sf, nil
	default:
		return nil, errs.NewFailed(fmt.Sprintf("no such compiler %s", compilerName))
	}
}

func CompilerIsSupported(name compiler.Name) bool {
	_, exists := compilers[name]
	return exists
}
