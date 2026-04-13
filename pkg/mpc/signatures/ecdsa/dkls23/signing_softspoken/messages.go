package signing_softspoken

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	rvole_softspoken "github.com/bronlabs/bron-crypto/pkg/mpc/rvole/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
)

// Round1P2P carries round 1 peer-to-peer messages.
type Round1P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	OtR1 *ecbbot.Round1P2P[P, S] `cbor:"otR1"`
}

func (m *Round1P2P[P, B, S]) Validate(p *Cosigner[P, B, S], from sharing.ID) error {
	if m == nil || m.OtR1 == nil {
		return dkls23.ErrNil.WithMessage("missing fields in Round1P2P message")
	}
	recv, ok := p.baseOtReceivers[from]
	if !ok {
		return dkls23.ErrNil.WithMessage("missing OT receiver")
	}
	if err := m.OtR1.Validate(recv, from); err != nil {
		return errs.Wrap(err)
	}

	return nil
}

// Round2P2P carries round 2 peer-to-peer messages.
type Round2P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	OtR2 *ecbbot.Round2P2P[P, S] `cbor:"otR2"`
}

func (m *Round2P2P[P, B, S]) Validate(p *Cosigner[P, B, S], from sharing.ID) error {
	if m == nil || m.OtR2 == nil {
		return dkls23.ErrNil.WithMessage("missing fields in Round2P2P message")
	}
	send, ok := p.baseOtSenders[from]
	if !ok {
		return dkls23.ErrNil.WithMessage("missing OT sender")
	}
	if err := m.OtR2.Validate(send, from); err != nil {
		return errs.Wrap(err)
	}

	return nil
}

// Round3Broadcast carries round 3 broadcast messages.
type Round3Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigRCommitment hash_comm.Commitment `cbor:"bigRCommitment"`
}

func (m *Round3Broadcast[P, B, S]) Validate(p *Cosigner[P, B, S], from sharing.ID) error {
	if m == nil {
		return dkls23.ErrNil.WithMessage("missing fields in Round3Broadcast message")
	}
	if m.BigRCommitment == [hash_comm.DigestSize]byte{} {
		return dkls23.ErrNil.WithMessage("missing BigRCommitment")
	}

	return nil
}

// Round3P2P carries round 3 peer-to-peer messages.
type Round3P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	MulR1 *rvole_softspoken.Round1P2P[P, B, S] `cbor:"mulR1"`
}

func (m *Round3P2P[P, B, S]) Validate(p *Cosigner[P, B, S], from sharing.ID) error {
	if m == nil || m.MulR1 == nil {
		return dkls23.ErrNil.WithMessage("missing fields in Round3P2P message")
	}
	alice, ok := p.aliceMul[from]
	if !ok {
		return dkls23.ErrNil.WithMessage("missing alice")
	}
	if err := m.MulR1.Validate(alice, from); err != nil {
		return errs.Wrap(err)
	}

	return nil
}

// Round4Broadcast carries round 4 broadcast messages.
type Round4Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigR        P                 `cbor:"bigR"`
	BigRWitness hash_comm.Witness `cbor:"bigRWitness"`
	Pk          P                 `cbor:"pk"`
}

func (m *Round4Broadcast[P, B, S]) Validate(_ *Cosigner[P, B, S], _ sharing.ID) error {
	if m == nil || utils.IsNil(m.BigR) || utils.IsNil(m.Pk) {
		return dkls23.ErrNil.WithMessage("missing fields in Round4Broadcast message")
	}
	if m.BigRWitness == [hash_comm.DigestSize]byte{} {
		return dkls23.ErrNil.WithMessage("missing BigRWitness")
	}

	if m.BigR.IsZero() || !m.BigR.IsTorsionFree() {
		return dkls23.ErrValidationFailed.WithMessage("invalid BigR")
	}
	if m.Pk.IsZero() || !m.Pk.IsTorsionFree() {
		return dkls23.ErrValidationFailed.WithMessage("invalid Pk")
	}

	return nil
}

// Round4P2P carries round 4 peer-to-peer messages.
type Round4P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	MulR2  *rvole_softspoken.Round2P2P[P, B, S] `cbor:"mulR2"`
	GammaU P                                    `cbor:"gammaU"`
	GammaV P                                    `cbor:"gammaV"`
	Psi    S                                    `cbor:"psi"`
}

func (m *Round4P2P[P, B, S]) Validate(p *Cosigner[P, B, S], from sharing.ID) error {
	if m == nil || m.MulR2 == nil || utils.IsNil(m.GammaV) || utils.IsNil(m.GammaU) || utils.IsNil(m.Psi) {
		return dkls23.ErrNil.WithMessage("missing fields in Round4P2P message")
	}
	bob, ok := p.bobMul[from]
	if !ok {
		return dkls23.ErrNil.WithMessage("missing bob")
	}
	if err := m.MulR2.Validate(bob, from); err != nil {
		return errs.Wrap(err)
	}
	if m.GammaU.IsZero() || !m.GammaU.IsTorsionFree() ||
		m.GammaV.IsZero() || !m.GammaV.IsTorsionFree() ||
		m.Psi.IsZero() {

		return dkls23.ErrValidationFailed.WithMessage("invalid input")
	}

	return nil
}
