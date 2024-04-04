package lp

import (
	"github.com/cronokirby/saferith"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/nthroot"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
)

type Round1Output struct {
	NthRootProverOutputs []nthroot.Commitment
	X                    []*paillier.CipherText

	_ ds.Incomparable
}

func (r1out *Round1Output) Validate(k int) error {
	if r1out == nil {
		return errs.NewIsNil("round 1 output")
	}
	if len(r1out.NthRootProverOutputs) != k {
		return errs.NewLength("NthRootProverOutputs length (%d) != %d", len(r1out.NthRootProverOutputs), k)
	}
	if len(r1out.X) != k {
		return errs.NewLength("X length (%d) != %d", len(r1out.X), k)
	}
	return nil
}

type Round2Output struct {
	NthRootVerifierOutputs []sigma.ChallengeBytes

	_ ds.Incomparable
}

func (r2out *Round2Output) Validate(k int) error {
	if r2out == nil {
		return errs.NewIsNil("round 2 output")
	}
	if len(r2out.NthRootVerifierOutputs) != k {
		return errs.NewLength("NthRootVerifierOutputs length (%d) != %d", len(r2out.NthRootVerifierOutputs), k)
	}
	return nil
}

type Round3Output struct {
	NthRootProverOutputs []nthroot.Response

	_ ds.Incomparable
}

func (r3out *Round3Output) Validate(k int) error {
	if r3out == nil {
		return errs.NewIsNil("round 3 output")
	}
	if len(r3out.NthRootProverOutputs) != k {
		return errs.NewLength("NthRootProverOutputs length (%d) != %d", len(r3out.NthRootProverOutputs), k)
	}
	for i := range k {
		if r3out.NthRootProverOutputs[i] == nil {
			return errs.NewIsNil("NthRootProverOutputs[%d]", i)
		}
	}
	return nil
}

type Round4Output struct {
	YPrime []*saferith.Nat

	_ ds.Incomparable
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
