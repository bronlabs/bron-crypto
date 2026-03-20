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

func (*Round3Broadcast[P, B, S]) Validate(participant *Participant[P, B, S], _ sharing.ID) error {
	return nil
}

// Round4P2P carries round 4 point-to-point data.
type Round4P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	LpRound1Output              *lp.Round1Output
	LpdlPrimeRound1Output       *lpdl.Round1Output
	LpdlDoublePrimeRound1Output *lpdl.Round1Output
}

func (m *Round4P2P[P, B, S]) Validate(participant *Participant[P, B, S], _ sharing.ID) error {
	if m == nil || m.LpRound1Output == nil || m.LpdlPrimeRound1Output == nil || m.LpdlDoublePrimeRound1Output == nil {
		return ErrValidation.WithMessage("missing fields in Round4P2P message")
	}
	// LP has no fucking validation method.
	return nil
}

// Round5P2P carries round 5 point-to-point data.
type Round5P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	LpRound2Output              *lp.Round2Output
	LpdlPrimeRound2Output       *lpdl.Round2Output
	LpdlDoublePrimeRound2Output *lpdl.Round2Output
}

func (*Round5P2P[P, B, S]) Validate(participant *Participant[P, B, S], _ sharing.ID) error {
	return nil
}

// Round6P2P carries round 6 point-to-point data.
type Round6P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	LpRound3Output              *lp.Round3Output
	LpdlPrimeRound3Output       *lpdl.Round3Output
	LpdlDoublePrimeRound3Output *lpdl.Round3Output
}

func (*Round6P2P[P, B, S]) Validate(participant *Participant[P, B, S], _ sharing.ID) error {
	return nil
}

// Round7P2P carries round 7 point-to-point data.
type Round7P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	LpRound4Output              *lp.Round4Output
	LpdlPrimeRound4Output       *lpdl.Round4Output[P, B, S]
	LpdlDoublePrimeRound4Output *lpdl.Round4Output[P, B, S]
}

func (*Round7P2P[P, B, S]) Validate(participant *Participant[P, B, S], _ sharing.ID) error {
	return nil
}
