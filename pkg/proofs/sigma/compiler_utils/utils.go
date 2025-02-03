package compilerUtils

import (
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler"
	fiatShamir "github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler/fischlin"
)

var compilers = map[compiler.Name]any{
	fiatShamir.Name: nil,
	fischlin.Name:   nil,
}

func RegisterNICompilersForGob() {
	fiatShamir.RegisterForGob()
	fischlin.RegisterForGob()
}

func MakeNonInteractive[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](compilerName compiler.Name, protocol sigma.Protocol[X, W, A, S, Z], prng io.Reader) (compiler.NICompiler[X, W], error) {
	if s := protocol.SoundnessError(); s < base.ComputationalSecurity {
		return nil, errs.NewArgument("protocol soundness (%d) is too low (<%d) for a non-interactive proof",
			s, base.ComputationalSecurity)
	}
	switch compilerName {
	case fiatShamir.Name:
		fs, err := fiatShamir.NewCompiler(protocol)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create fiat-shamir compiler")
		}
		return fs, nil
	case fischlin.Name:
		rho := getFischlinRho(protocol.Name())
		sf, err := fischlin.NewCompiler(protocol, rho, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create simplified compiler")
		}
		return sf, nil
	default:
		return nil, errs.NewFailed("no such compiler %s", compilerName)
	}
}

func CompilerIsSupported(name compiler.Name) bool {
	_, exists := compilers[name]
	return exists
}
