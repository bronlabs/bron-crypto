package dkg

import (
	"encoding/binary"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

type Round1Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	V hashcom.Commitment
}

func (m *Round1Broadcast[P, B, S]) Validate(p *Participant[P, B, S], senderID sharing.ID) error {
	if m == nil {
		return cggmp21.ErrValidationFailed.WithMessage("nil message")
	}
	if m.V == ([hashcom.DigestSize]byte{}) {
		return cggmp21.ErrValidationFailed.WithMessage("empty commitment")
	}

	return nil
}

type CommitmentMessage[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	SessionID                 network.SID
	SharingID                 sharing.ID
	PaillierPublicKey         *paillier.PublicKey
	RingPedersenCommitmentKey *intcom.CommitmentKey
	Psi                       compiler.NIZKPoKProof
	Rid                       []byte
}

func (m *CommitmentMessage[P, B, S]) Bytes() []byte {
	var data []byte
	data = append(data, m.SessionID[:]...)
	data = binary.LittleEndian.AppendUint64(data, uint64(m.SharingID))
	data = append(data, m.PaillierPublicKey.Group().N().BytesBE()...)
	data = append(data, m.RingPedersenCommitmentKey.Group().Modulus().BytesBE()...)
	data = append(data, m.RingPedersenCommitmentKey.S().Value().BytesBE()...)
	data = append(data, m.RingPedersenCommitmentKey.T().Value().BytesBE()...)
	data = append(data, m.Psi...)
	data = append(data, m.Rid...)
	return data
}

type Round2Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Message *CommitmentMessage[P, B, S]
	U       hashcom.Witness
}

func (m *Round2Broadcast[P, B, S]) Validate(p *Participant[P, B, S], senderID sharing.ID) error {
	if m == nil {
		return cggmp21.ErrValidationFailed.WithMessage("nil message")
	}
	if m.U == ([hashcom.DigestSize]byte{}) {
		return cggmp21.ErrValidationFailed.WithMessage("empty witness")
	}
	if m.Message == nil {
		return cggmp21.ErrValidationFailed.WithMessage("nil commitment message")
	}
	if m.Message.SessionID != p.ctx.SessionID() {
		return cggmp21.ErrValidationFailed.WithMessage("invalid session id")
	}
	if m.Message.SharingID != senderID {
		return cggmp21.ErrValidationFailed.WithMessage("invalid sharing id")
	}
	if m.Message.PaillierPublicKey == nil {
		return cggmp21.ErrValidationFailed.WithMessage("nil Paillier public key")
	}
	if m.Message.RingPedersenCommitmentKey == nil {
		return cggmp21.ErrValidationFailed.WithMessage("nil ring pedersen trapdoor key")
	}
	if len(m.Message.Psi) == 0 || ct.SliceIsZero(m.Message.Psi) == ct.True {
		return cggmp21.ErrValidationFailed.WithMessage("psi proof is empty")
	}
	if len(m.Message.Rid) != p.Kappa() {
		return cggmp21.ErrValidationFailed.WithMessage("rid length is %d != kappa = %d", len(m.Message.Rid), p.Kappa())
	}
	return nil
}

type Round3P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	PsiJI     compiler.NIZKPoKProof
	PsiIPrime compiler.NIZKPoKProof
}

func (m *Round3P2P[P, B, S]) Validate(*Participant[P, B, S], sharing.ID) error {
	if m == nil {
		return cggmp21.ErrValidationFailed.WithMessage("nil message")
	}
	if len(m.PsiIPrime) == 0 || ct.SliceIsZero(m.PsiIPrime) == ct.True {
		return cggmp21.ErrValidationFailed.WithMessage("psi i prime proof is empty")
	}
	if len(m.PsiJI) == 0 || ct.SliceIsZero(m.PsiJI) == ct.True {
		return cggmp21.ErrValidationFailed.WithMessage("psi ji proof is empty")
	}
	return nil
}
