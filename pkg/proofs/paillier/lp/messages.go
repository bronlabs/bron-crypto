package lp

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
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
func (m *Round1Output) Validate(p *Prover, _ sharing.ID) error {
	if m == nil {
		return proofs.ErrValidationFailed.WithMessage("round 1 output is nil")
	}
	if len(m.X) != p.k {
		return proofs.ErrValidationFailed.WithMessage("X length (%d) != %d", len(m.X), p.k)
	}
	if sliceutils.ContainsNil(m.X) {
		return proofs.ErrValidationFailed.WithMessage("X contains nil")
	}
	if len(m.NthRootsProverOutput) != p.k {
		return proofs.ErrValidationFailed.WithMessage("NthRootsProverOutput length (%d) != %d", len(m.NthRootsProverOutput), p.k)
	}
	if sliceutils.ContainsNil(m.NthRootsProverOutput) {
		return proofs.ErrValidationFailed.WithMessage("NthRootsProverOutput contains nil")
	}
	for _, x := range m.X {
		if x == nil {
			return proofs.ErrValidationFailed.WithMessage("X contains nil")
		}
	}
	return nil
}

// Round2Output carries the verifier's challenge bytes.
type Round2Output struct {
	NthRootsVerifierOutput sigma.ChallengeBytes
}

func (m *Round2Output) Validate(_ *Verifier, _ sharing.ID) error {
	if m == nil {
		return proofs.ErrValidationFailed.WithMessage("round 2 output is nil")
	}
	if len(m.NthRootsVerifierOutput) < base.StatisticalSecurityBytesCeil {
		return proofs.ErrValidationFailed.WithMessage("NthRootsVerifierOutput length (%d) < %d", len(m.NthRootsVerifierOutput), base.ComputationalSecurityBytesCeil)
	}
	return nil
}

// Round3Output carries the prover's Nth-root responses.
type Round3Output struct {
	NthRootsProverOutput sigand.Response[*nthroot.Response[*modular.SimpleModulus]]
}

func (m *Round3Output) Validate(p *Prover, _ sharing.ID) error {
	if m == nil {
		return proofs.ErrValidationFailed.WithMessage("round 3 output is nil")
	}
	if len(m.NthRootsProverOutput) != p.k {
		return proofs.ErrValidationFailed.WithMessage("NthRootsProverOutput length (%d) != %d", len(m.NthRootsProverOutput), p.k)
	}
	if sliceutils.ContainsNil(m.NthRootsProverOutput) {
		return proofs.ErrValidationFailed.WithMessage("NthRootsProverOutput contains nil")
	}
	return nil
}

// Round4Output carries the final Paillier public-key verification data.
type Round4Output struct {
	YPrime []*numct.Nat
}

// Validate checks the Round4Output shape.
func (m *Round4Output) Validate(p *Verifier, _ sharing.ID) error {
	if m == nil {
		return proofs.ErrInvalidArgument.WithMessage("round 4 output is nil")
	}
	if len(m.YPrime) != p.k {
		return proofs.ErrInvalidArgument.WithMessage("YPrime length (%d) != %d", len(m.YPrime), p.k)
	}
	if sliceutils.ContainsNil(m.YPrime) {
		return proofs.ErrInvalidArgument.WithMessage("YPrime contains nil")
	}
	return nil
}
