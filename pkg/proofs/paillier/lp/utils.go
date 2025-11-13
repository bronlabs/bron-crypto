package lp

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/nthroot"
)

func nthRootStatementLearnOrder[A znstar.ArithmeticPaillier](x *nthroot.Statement[A], g *znstar.PaillierGroupKnownOrder) (*nthroot.Statement[*modular.OddPrimeSquareFactors], error) {
	if x == nil || g == nil {
		return nil, errs.NewIsNil("x or g")
	}
	learnedX, err := x.Value().LearnOrder(g)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to learn order of x")
	}
	return &nthroot.Statement[*modular.OddPrimeSquareFactors]{
		X: learnedX,
	}, nil
}

func nthRootCommitmentLearnOrder[A znstar.ArithmeticPaillier](a *nthroot.Commitment[A], g *znstar.PaillierGroupKnownOrder) (*nthroot.Commitment[*modular.OddPrimeSquareFactors], error) {
	if a == nil || g == nil {
		return nil, errs.NewIsNil("c or g")
	}
	learnedA, err := a.Value().LearnOrder(g)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to learn order of c")
	}
	return &nthroot.Commitment[*modular.OddPrimeSquareFactors]{
		A: learnedA,
	}, nil
}

func nthRootResponseLearnOrder[A znstar.ArithmeticPaillier](z *nthroot.Response[A], g *znstar.PaillierGroupKnownOrder) (*nthroot.Response[*modular.OddPrimeSquareFactors], error) {
	if z == nil || g == nil {
		return nil, errs.NewIsNil("r or g")
	}
	learnedZ, err := z.Value().LearnOrder(g)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to learn order of r")
	}
	return &nthroot.Response[*modular.OddPrimeSquareFactors]{
		Z: learnedZ,
	}, nil
}
