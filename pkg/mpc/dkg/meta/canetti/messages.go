package canetti

import (
	"encoding/binary"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr"
)

type Round1Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	V hash_comm.Commitment
}

func (m *Round1Broadcast[G, S]) Validate(*Participant[G, S], sharing.ID) error {
	if m == nil {
		return ErrVerificationFailed.WithMessage("nil message")
	}
	if m.V == ([hash_comm.DigestSize]byte{}) {
		return ErrVerificationFailed.WithMessage("empty commitment")
	}

	return nil
}

type CommitmentMessage[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	SessionID network.SID
	SharingID sharing.ID
	Rho       []byte
	X         *feldman.VerificationVector[G, S]
	A         *batch_schnorr.Commitment[G, S]
}

func (m *CommitmentMessage[G, S]) bytes() []byte {
	var data []byte
	data = append(data, m.SessionID[:]...)
	data = binary.LittleEndian.AppendUint64(data, uint64(m.SharingID))
	data = binary.LittleEndian.AppendUint64(data, uint64(len(m.Rho)))
	data = append(data, m.Rho...)
	data = binary.LittleEndian.AppendUint64(data, uint64(len(m.X.Value().Data())))
	for _, x := range m.X.Value().Data() {
		data = append(data, x.Bytes()...)
	}
	data = append(data, m.A.Bytes()...)
	return data
}

type Round2Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	Message *CommitmentMessage[G, S]
	U       hash_comm.Witness
}

func (m *Round2Broadcast[G, S]) Validate(p *Participant[G, S], senderID sharing.ID) error {
	if m == nil || m.Message == nil || m.Message.X == nil || m.Message.Rho == nil || m.Message.A == nil {
		return ErrVerificationFailed.WithMessage("nil argument")
	}
	if m.U == ([hash_comm.DigestSize]byte{}) {
		return ErrVerificationFailed.WithMessage("empty witness")
	}
	if m.Message.SessionID != p.ctx.SessionID() {
		return ErrVerificationFailed.WithMessage("invalid session id")
	}
	if m.Message.SharingID != senderID {
		return ErrVerificationFailed.WithMessage("invalid sharing id")
	}
	if len(m.Message.Rho) != p.rhoLen {
		return ErrVerificationFailed.WithMessage("invalid rho length")
	}
	r, c := m.Message.X.Value().Dimensions()
	if r != int(p.sharingScheme.MSP().D()) || c != 1 {
		return ErrVerificationFailed.WithMessage("invalid x dimensions")
	}

	return nil
}

type Round2P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	Share *kw.Share[S]
}

func (m *Round2P2P[G, S]) Validate(p *Participant[G, S], _ sharing.ID) error {
	if m == nil || m.Share == nil {
		return ErrVerificationFailed.WithMessage("nil argument")
	}
	if m.Share.ID() != p.SharingID() {
		return ErrVerificationFailed.WithMessage("invalid share sharing id")
	}

	return nil
}

type Round3Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	Psi *batch_schnorr.Response[S]
}

func (m *Round3Broadcast[G, S]) Validate(*Participant[G, S], sharing.ID) error {
	if m == nil || m.Psi == nil {
		return ErrVerificationFailed.WithMessage("nil argument")
	}

	return nil
}
