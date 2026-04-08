package canetti

import (
	"encoding/binary"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr"
)

// Round1Broadcast carries the dealer's commitment digest for round 1.
type Round1Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	V hash_comm.Commitment
}

// Validate checks whether the round 1 broadcast is well formed.
func (m *Round1Broadcast[G, S]) Validate(*Participant[G, S], sharing.ID) error {
	if m == nil {
		return ErrValidationFailed.WithMessage("nil message")
	}
	if m.V == ([hash_comm.DigestSize]byte{}) {
		return ErrValidationFailed.WithMessage("empty commitment")
	}

	return nil
}

// CommitmentMessage contains the dealer material opened in round 2 and later
// used to derive the common challenge and verify the proof of knowledge.
type CommitmentMessage[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	SessionID network.SID
	SharingID sharing.ID
	Rho       []byte
	X         *feldman.VerificationVector[G, S]
	A         *batch_schnorr.Commitment[G, S]
}

func (m *CommitmentMessage[G, S]) Bytes() []byte {
	var data []byte
	data = append(data, m.SessionID[:]...)
	data = binary.LittleEndian.AppendUint64(data, uint64(m.SharingID))
	data = binary.LittleEndian.AppendUint64(data, uint64(len(m.Rho)))
	data = append(data, m.Rho...)
	data = binary.LittleEndian.AppendUint64(data, uint64(len(slices.Collect(m.X.Value().Iter()))))
	for x := range m.X.Value().Iter() {
		data = append(data, x.Bytes()...)
	}
	data = append(data, m.A.Bytes()...)
	return data
}

// Round2Broadcast opens the sender's round 1 commitment.
type Round2Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	Message *CommitmentMessage[G, S]
	U       hash_comm.Witness
}

// Validate checks whether the round 2 broadcast is well formed for the local
// participant configuration.
func (m *Round2Broadcast[G, S]) Validate(p *Participant[G, S], senderID sharing.ID) error {
	if m == nil || m.Message == nil || m.Message.X == nil || m.Message.Rho == nil || m.Message.A == nil {
		return ErrValidationFailed.WithMessage("nil argument")
	}
	if m.U == ([hash_comm.DigestSize]byte{}) {
		return ErrValidationFailed.WithMessage("empty witness")
	}
	if m.Message.SessionID != p.ctx.SessionID() {
		return ErrValidationFailed.WithMessage("invalid session id")
	}
	if m.Message.SharingID != senderID {
		return ErrValidationFailed.WithMessage("invalid sharing id")
	}
	if len(m.Message.Rho) != p.rhoLen {
		return ErrValidationFailed.WithMessage("invalid rho length")
	}
	r, c := m.Message.X.Value().Dimensions()
	if r != int(p.sharingScheme.MSP().D()) || c != 1 {
		return ErrValidationFailed.WithMessage("invalid x dimensions")
	}

	return nil
}

// Round2P2P carries the sender's private share for the receiver.
type Round2P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	Share *kw.Share[S]
}

// Validate checks whether the round 2 unicast targets the local participant.
func (m *Round2P2P[G, S]) Validate(p *Participant[G, S], _ sharing.ID) error {
	if m == nil || m.Share == nil {
		return ErrValidationFailed.WithMessage("nil argument")
	}
	if m.Share.ID() != p.SharingID() {
		return ErrValidationFailed.WithMessage("invalid share sharing id")
	}

	return nil
}

// Round3Broadcast carries the sender's batch Schnorr response.
type Round3Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	Psi *ZKResponse[*batch_schnorr.Commitment[G, S], *batch_schnorr.Response[S]]
}

// Validate checks whether the round 3 broadcast is well formed.
func (m *Round3Broadcast[G, S]) Validate(*Participant[G, S], sharing.ID) error {
	if m == nil || m.Psi == nil {
		return ErrValidationFailed.WithMessage("nil argument")
	}

	return nil
}
