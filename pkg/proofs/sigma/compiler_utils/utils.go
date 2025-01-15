package compiler_utils

import (
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler"
	fiatShamir "github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler/fiatshamir"
	randomisedFischlin "github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
)

var compilers = map[compiler.Name]any{
	fiatShamir.Name:         nil,
	randomisedFischlin.Name: nil,
}

func RegisterNICompilersForGob() {
	fiatShamir.RegisterForGob()
	randomisedFischlin.RegisterForGob()
}

func MakeNonInteractive[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](compilerName compiler.Name, protocol sigma.Protocol[X, W, A, S, Z], prng io.Reader) (compiler.NICompiler[X, W], error) {
	if s := protocol.SoundnessError(); s < base.ComputationalSecurity {
		return nil, errs.NewArgument("protocol soundness (%d) is too low (<%d) for a non-interactive proof",
			s, base.ComputationalSecurity)
	}
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
		return nil, errs.NewFailed("no such compiler %s", compilerName)
	}
}

func CompilerIsSupported(name compiler.Name) bool {
	_, exists := compilers[name]
	return exists
}
