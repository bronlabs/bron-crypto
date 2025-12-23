package lp

import (
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/nthroot"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compose/sigand"
)

// Round1Output carries the verifier's first-round data.
type Round1Output struct {
	NthRootsProverOutput sigand.Commitment[*nthroot.Commitment[*modular.SimpleModulus]]
	X                    sigand.Statement[*nthroot.Statement[*modular.SimpleModulus]]
}

// Validate checks the Round1Output shape.
func (r1out *Round1Output) Validate(k int) error {
	if r1out == nil {
		return ErrInvalidArgument.WithMessage("round 1 output is nil")
	}
	if len(r1out.X) != k {
		return ErrInvalidArgument.WithMessage("X length (%d) != %d", len(r1out.X), k)
	}
	return nil
}

// Round2Output carries the verifier's challenge bytes.
type Round2Output struct {
	NthRootsVerifierOutput sigma.ChallengeBytes
}

// Round3Output carries the prover's Nth-root responses.
type Round3Output struct {
	NthRootsProverOutput sigand.Response[*nthroot.Response[*modular.SimpleModulus]]
}

// Round4Output carries the final Paillier public-key verification data.
type Round4Output struct {
	YPrime []*numct.Nat
}

// Validate checks the Round4Output shape.
func (r4out *Round4Output) Validate(k int) error {
	if r4out == nil {
		return ErrInvalidArgument.WithMessage("round 4 output is nil")
	}
	if len(r4out.YPrime) != k {
		return ErrInvalidArgument.WithMessage("YPrime length (%d) != %d", len(r4out.YPrime), k)
	}
	return nil
}
