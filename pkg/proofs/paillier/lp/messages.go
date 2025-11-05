package lp

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/nthroots"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compose/sigand"
)

type Round1Output struct {
	NthRootsProverOutput sigand.Commitment[*nthroots.Commitment[*modular.SimpleModulus]]
	X                    sigand.Statement[*nthroots.Statement[*modular.SimpleModulus]]
}

func (r1out *Round1Output) Validate(k int) error {
	if r1out == nil {
		return errs.NewIsNil("round 1 output")
	}
	if len(r1out.X) != k {
		return errs.NewLength("X length (%d) != %d", len(r1out.X), k)
	}
	return nil
}

type Round2Output struct {
	NthRootsVerifierOutput sigma.ChallengeBytes
}

type Round3Output struct {
	NthRootsProverOutput sigand.Response[*nthroots.Response[*modular.SimpleModulus]]
}

type Round4Output struct {
	YPrime []*numct.Nat
}

func (r4out *Round4Output) Validate(k int) error {
	if r4out == nil {
		return errs.NewIsNil("round 4 output")
	}
	if len(r4out.YPrime) != k {
		return errs.NewLength("YPrime length (%d) != %d", len(r4out.YPrime), k)
	}
	return nil
}
