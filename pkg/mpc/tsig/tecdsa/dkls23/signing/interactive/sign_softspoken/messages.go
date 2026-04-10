package sign_softspoken

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	rvole_softspoken "github.com/bronlabs/bron-crypto/pkg/mpc/rvole/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// Round1Broadcast carries round 1 broadcast messages.
type Round1Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigRCommitment hash_comm.Commitment `cbor:"bigRCommitment"`
}

func (m *Round1Broadcast[P, B, S]) Validate(_ *Cosigner[P, B, S], _ sharing.ID) error {
	if m == nil {
		return ErrNil.WithMessage("missing fields in Round1Broadcast message")
	}
	if m.BigRCommitment == [hash_comm.DigestSize]byte{} {
		return ErrNil.WithMessage("missing BigRCommitment")
	}

	return nil
}

// Round1P2P carries round 1 peer-to-peer messages.
type Round1P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	MulR1 *rvole_softspoken.Round1P2P[P, B, S] `cbor:"mulR1"`
}

func (m *Round1P2P[P, B, S]) Validate(p *Cosigner[P, B, S], from sharing.ID) error {
	if m == nil || m.MulR1 == nil {
		return ErrNil.WithMessage("missing fields in Round1P2P message")
	}
	alice, ok := p.state.aliceMul[from]
	if !ok {
		return ErrNil.WithMessage("missing alice")
	}
	if err := m.MulR1.Validate(alice, from); err != nil {
		return errs.Wrap(err)
	}
	return nil
}

// Round2Broadcast carries round 2 broadcast messages.
type Round2Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigR        P                 `cbor:"bigR"`
	BigRWitness hash_comm.Witness `cbor:"bigRWitness"`
	Pk          P                 `cbor:"pk"`
}

func (m *Round2Broadcast[P, B, S]) Validate(_ *Cosigner[P, B, S], _ sharing.ID) error {
	if m == nil || utils.IsNil(m.BigR) || utils.IsNil(m.Pk) {
		return ErrNil.WithMessage("missing fields in Round2Broadcast message")
	}
	if m.BigRWitness == [hash_comm.DigestSize]byte{} {
		return ErrNil.WithMessage("missing BigRWitness")
	}

	if m.BigR.IsZero() || !m.BigR.IsTorsionFree() {
		return ErrValidation.WithMessage("invalid R")
	}
	if m.Pk.IsZero() || !m.Pk.IsTorsionFree() {
		return ErrValidation.WithMessage("invalid PK")
	}

	return nil
}

// Round2P2P carries round 2 peer-to-peer messages.
type Round2P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	MulR2  *rvole_softspoken.Round2P2P[P, B, S] `cbor:"mulR2"`
	GammaU P                                    `cbor:"gammaU"`
	GammaV P                                    `cbor:"gammaV"`
	Psi    S                                    `cbor:"psi"`
}

func (m *Round2P2P[P, B, S]) Validate(p *Cosigner[P, B, S], from sharing.ID) error {
	if m == nil || m.MulR2 == nil || utils.IsNil(m.GammaU) || utils.IsNil(m.GammaV) || utils.IsNil(m.Psi) {
		return ErrNil.WithMessage("missing fields in Round2P2P message")
	}
	if m.GammaU.IsZero() || !m.GammaU.IsTorsionFree() {
		return ErrValidation.WithMessage("invalid gamma u")
	}
	if m.GammaV.IsZero() || !m.GammaV.IsTorsionFree() {
		return ErrValidation.WithMessage("invalid gamma v")
	}
	bob, ok := p.state.bobMul[from]
	if !ok {
		return ErrNil.WithMessage("missing bob")
	}
	if err := m.MulR2.Validate(bob, from); err != nil {
		return errs.Wrap(err)
	}

	return nil
}
