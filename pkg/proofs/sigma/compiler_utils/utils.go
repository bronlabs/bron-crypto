package compilerUtils

import (
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	fiatShamir "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/fiat_shamir"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"
)

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
	default:
		return nil, errs.NewFailed(fmt.Sprintf("no such compiler %s", compilerName))
	}
}
