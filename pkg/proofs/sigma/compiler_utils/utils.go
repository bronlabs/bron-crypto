package compilerUtils

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	fiatShamir "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fischlin"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/randfischlin"
)

var compilers = map[compiler.Name]bool{
	fiatShamir.Name:   true,
	fischlin.Name:     true,
	randfischlin.Name: true,
}

func RegisterNICompilersForGob() {
	fiatShamir.RegisterForGob()
	fischlin.RegisterForGob()
	randfischlin.RegisterForGob()
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
			return nil, errs.WrapFailed(err, "cannot create fischlin compiler")
		}
		return sf, nil
	case randfischlin.Name:
		rf, err := randfischlin.NewCompiler(protocol, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create randomised fischlin compiler")
		}
		return rf, nil
	default:
		return nil, errs.NewFailed("no such compiler %s", compilerName)
	}
}

func CompilerIsSupported(name compiler.Name) bool {
	_, exists := compilers[name]
	return exists
}
