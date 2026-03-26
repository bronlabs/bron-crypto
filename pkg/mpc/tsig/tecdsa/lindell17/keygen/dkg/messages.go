package dkg

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lp"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lpdl"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/errs-go/errs"
)

// Round1Broadcast carries the first-round broadcast data.
type Round1Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigQCommitment hash_comm.Commitment
}

func (m *Round1Broadcast[P, B, S]) Validate(participant *Participant[P, B, S], _ sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round1Broadcast message")
	}
	if m.BigQCommitment == [hash_comm.DigestSize]byte{} {
		return ErrValidation.WithMessage("missing BigQ commitment in Round1Broadcast message")
	}
	return nil
}

// Round2Broadcast carries the second-round broadcast data.
type Round2Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigQOpening          hash_comm.Witness
	BigQPrime            P
	BigQPrimeProof       compiler.NIZKPoKProof
	BigQDoublePrime      P
	BigQDoublePrimeProof compiler.NIZKPoKProof
}

func (m *Round2Broadcast[P, B, S]) Validate(participant *Participant[P, B, S], _ sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round2Broadcast message")
	}
	if m.BigQOpening == [hash_comm.DigestSize]byte{} {
		return ErrValidation.WithMessage("missing BigQ opening in Round2Broadcast message")
	}
	if utils.IsNil(m.BigQPrime) {
		return ErrValidation.WithMessage("missing BigQ' in Round2Broadcast message")
	}
	if m.BigQPrime.IsOpIdentity() || !m.BigQDoublePrime.IsTorsionFree() {
		return ErrValidation.WithMessage("invalid BigQ' in Round2Broadcast message")
	}
	if ct.SliceIsZero(m.BigQPrimeProof) == ct.True {
		return ErrValidation.WithMessage("missing BigQ' proof in Round2Broadcast message")
	}
	if utils.IsNil(m.BigQDoublePrime) {
		return ErrValidation.WithMessage("missing BigQ'' in Round2Broadcast message")
	}
	if m.BigQDoublePrime.IsOpIdentity() || !m.BigQDoublePrime.IsTorsionFree() {
		return ErrValidation.WithMessage("invalid BigQ'' in Round2Broadcast message")
	}
	if ct.SliceIsZero(m.BigQDoublePrimeProof) == ct.True {
		return ErrValidation.WithMessage("missing BigQ'' proof in Round2Broadcast message")
	}
	return nil
}

// Round3Broadcast carries the third-round broadcast data.
type Round3Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	CKeyPrime         *paillier.Ciphertext
	CKeyDoublePrime   *paillier.Ciphertext
	PaillierPublicKey *paillier.PublicKey
}

func (m *Round3Broadcast[P, B, S]) Validate(participant *Participant[P, B, S], _ sharing.ID) error {
	if m == nil || m.CKeyPrime == nil || m.CKeyDoublePrime == nil || m.PaillierPublicKey == nil {
		return ErrValidation.WithMessage("missing fields in Round3Broadcast message")
	}

	n := m.PaillierPublicKey.N()
	n2 := m.PaillierPublicKey.N2()
	if n.BitLen() != participant.paillierKeyLen {
		return ErrValidation.WithMessage("invalid Paillier public key size in Round3Broadcast message")
	}
	cs := m.PaillierPublicKey.CiphertextSpace()
	if m.CKeyPrime.N2().Value().Equal(n2.Nat()) == ct.False {
		return ErrValidation.WithMessage("CKey' has incorrect modulus in Round3Broadcast message")
	}
	if !cs.Contains(m.CKeyPrime) {
		return ErrValidation.WithMessage("CKey' is not a valid ciphertext in Round3Broadcast message")
	}
	if m.CKeyDoublePrime.N2().Value().Equal(n2.Nat()) == ct.False {
		return ErrValidation.WithMessage("CKey'' has incorrect modulus in Round3Broadcast message")
	}
	if !cs.Contains(m.CKeyDoublePrime) {
		return ErrValidation.WithMessage("CKey'' is not a valid ciphertext in Round3Broadcast message")
	}
	return nil
}

// Round4P2P carries round 4 point-to-point data.
type Round4P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	LpRound1Output              *lp.Round1Output
	LpdlPrimeRound1Output       *lpdl.Round1Output[P, B, S]
	LpdlDoublePrimeRound1Output *lpdl.Round1Output[P, B, S]
}

func (m *Round4P2P[P, B, S]) Validate(participant *Participant[P, B, S], sender sharing.ID) error {
	if m == nil || m.LpRound1Output == nil || m.LpdlPrimeRound1Output == nil || m.LpdlDoublePrimeRound1Output == nil {
		return ErrValidation.WithMessage("missing fields in Round4P2P message")
	}
	if err := m.LpRound1Output.Validate(participant.state.lpProvers[sender], sender); err != nil {
		return errs.Wrap(err)
	}
	if err := m.LpdlPrimeRound1Output.Validate(participant.state.lpdlPrimeProvers[sender], sender); err != nil {
		return errs.Wrap(err)
	}
	if err := m.LpdlDoublePrimeRound1Output.Validate(participant.state.lpdlDoublePrimeProvers[sender], sender); err != nil {
		return errs.Wrap(err)
	}
	return nil
}

// Round5P2P carries round 5 point-to-point data.
type Round5P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	LpRound2Output              *lp.Round2Output
	LpdlPrimeRound2Output       *lpdl.Round2Output[P, B, S]
	LpdlDoublePrimeRound2Output *lpdl.Round2Output[P, B, S]
}

func (m *Round5P2P[P, B, S]) Validate(participant *Participant[P, B, S], sender sharing.ID) error {
	if m == nil || m.LpRound2Output == nil || m.LpdlPrimeRound2Output == nil || m.LpdlDoublePrimeRound2Output == nil {
		return ErrValidation.WithMessage("missing fields in Round5P2P message")
	}
	if err := m.LpRound2Output.Validate(participant.state.lpVerifiers[sender], sender); err != nil {
		return errs.Wrap(err)
	}
	if err := m.LpdlPrimeRound2Output.Validate(participant.state.lpdlPrimeVerifiers[sender], sender); err != nil {
		return errs.Wrap(err)
	}
	if err := m.LpdlDoublePrimeRound2Output.Validate(participant.state.lpdlDoublePrimeVerifiers[sender], sender); err != nil {
		return errs.Wrap(err)
	}
	return nil
}

// Round6P2P carries round 6 point-to-point data.
type Round6P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	LpRound3Output              *lp.Round3Output
	LpdlPrimeRound3Output       *lpdl.Round3Output[P, B, S]
	LpdlDoublePrimeRound3Output *lpdl.Round3Output[P, B, S]
}

func (m *Round6P2P[P, B, S]) Validate(participant *Participant[P, B, S], sender sharing.ID) error {
	if m == nil || m.LpRound3Output == nil || m.LpdlPrimeRound3Output == nil || m.LpdlDoublePrimeRound3Output == nil {
		return ErrValidation.WithMessage("missing fields in Round6P2P message")
	}
	if err := m.LpRound3Output.Validate(participant.state.lpProvers[sender], sender); err != nil {
		return errs.Wrap(err)
	}
	if err := m.LpdlPrimeRound3Output.Validate(participant.state.lpdlPrimeProvers[sender], sender); err != nil {
		return errs.Wrap(err)
	}
	if err := m.LpdlDoublePrimeRound3Output.Validate(participant.state.lpdlDoublePrimeProvers[sender], sender); err != nil {
		return errs.Wrap(err)
	}
	return nil
}

// Round7P2P carries round 7 point-to-point data.
type Round7P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	LpRound4Output              *lp.Round4Output
	LpdlPrimeRound4Output       *lpdl.Round4Output[P, B, S]
	LpdlDoublePrimeRound4Output *lpdl.Round4Output[P, B, S]
}

func (m *Round7P2P[P, B, S]) Validate(participant *Participant[P, B, S], sender sharing.ID) error {
	if m == nil || m.LpRound4Output == nil || m.LpdlPrimeRound4Output == nil || m.LpdlDoublePrimeRound4Output == nil {
		return ErrValidation.WithMessage("missing fields in Round7P2P message")
	}
	if err := m.LpRound4Output.Validate(participant.state.lpVerifiers[sender], sender); err != nil {
		return errs.Wrap(err)
	}
	if err := m.LpdlPrimeRound4Output.Validate(participant.state.lpdlPrimeVerifiers[sender], sender); err != nil {
		return errs.Wrap(err)
	}
	if err := m.LpdlDoublePrimeRound4Output.Validate(participant.state.lpdlDoublePrimeVerifiers[sender], sender); err != nil {
		return errs.Wrap(err)
	}
	return nil
}
