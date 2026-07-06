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

// Round1Broadcast is the first-round message: a hash commitment V_i to the
// party's auxiliary-info contribution (its Paillier and ring-Pedersen public
// keys, the ring-Pedersen well-formedness proof, and its rid share). Committing
// before any opening is revealed stops a rushing adversary from choosing its own
// keys or rid share as a function of the honest parties' values.
type Round1Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	V hashcom.Commitment
}

// Validate is the deserialisation trust boundary for the round-1 message: it
// rejects a nil message or an empty (all-zero) commitment digest.
func (m *Round1Broadcast[P, B, S]) Validate(p *Participant[P, B, S], senderID sharing.ID) error {
	if m == nil {
		return cggmp21.ErrValidationFailed.WithMessage("nil message")
	}
	if m.V == ([hashcom.DigestSize]byte{}) {
		return cggmp21.ErrValidationFailed.WithMessage("empty commitment")
	}

	return nil
}

// CommitmentMessage is the payload committed to in round 1 and opened in round
// 2: the sender's Paillier public key N_i, ring-Pedersen public parameters
// (N̂_i, s_i, t_i), the ring-Pedersen well-formedness proof Psi (Π_prm), and the
// sender's rid share. SessionID and SharingID bind it to the session and sender.
type CommitmentMessage[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	SessionID                 network.SID
	SharingID                 sharing.ID
	PaillierPublicKey         *paillier.PublicKey
	RingPedersenCommitmentKey *intcom.CommitmentKey
	Psi                       compiler.NIZKPoKProof
	Rid                       []byte
}

// Bytes is the canonical encoding hashed by the round-1 commitment and
// re-derived by the verifier when opening it in round 3; the commitment's
// binding rests on it being injective.
func (m *CommitmentMessage[P, B, S]) Bytes() []byte {
	var data []byte
	data = append(data, m.SessionID[:]...)
	data = binary.LittleEndian.AppendUint64(data, uint64(m.SharingID))
	data = binary.LittleEndian.AppendUint64(data, uint64(m.PaillierPublicKey.Group().N().TrueLen()))
	data = append(data, m.PaillierPublicKey.Group().N().BytesBE()...)
	data = binary.LittleEndian.AppendUint64(data, uint64(m.RingPedersenCommitmentKey.Group().Modulus().TrueLen()))
	data = append(data, m.RingPedersenCommitmentKey.Group().Modulus().BytesBE()...)
	data = append(data, m.RingPedersenCommitmentKey.S().Value().BytesBE()...)
	data = append(data, m.RingPedersenCommitmentKey.T().Value().BytesBE()...)
	data = binary.LittleEndian.AppendUint64(data, uint64(len(m.Psi)))
	data = append(data, m.Psi...)
	data = binary.LittleEndian.AppendUint64(data, uint64(len(m.Rid)))
	data = append(data, m.Rid...)
	return data
}

// Round2Broadcast opens the round-1 commitment: it carries the committed
// CommitmentMessage together with the hash-commitment opening witness U. The
// recipient re-derives the digest from these in round 3 and checks it against
// the round-1 V_i, which is what binds the sender to its committed contribution.
type Round2Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Message *CommitmentMessage[P, B, S]
	U       hashcom.Witness
}

// Validate is the deserialisation trust boundary for the opening: it requires a
// non-empty witness and payload, binds the payload to this session and to the
// claimed sender, requires the Paillier and ring-Pedersen keys to be present and
// the Π_prm proof non-empty, and enforces a rid share of exactly κ/8 bytes. The
// keys' deeper structure (Blum modulus, no small factors) is established by the
// proofs verified in rounds 3 and 4, not here.
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
	if len(m.Message.Rid) != p.params.Kappa()/8 {
		return cggmp21.ErrValidationFailed.WithMessage("rid length is %d != kappaBytes = %d", len(m.Message.Rid), p.params.Kappa()/8)
	}
	return nil
}

// Round3P2P is the third-round point-to-point message from a prover to one
// verifier. PsiJI is the no-small-factor proof Π_fac, bound to the recipient's
// ring-Pedersen setup and therefore distinct per verifier; PsiIPrime is the
// Paillier-Blum modulus proof Π_mod, which is verifier-independent and identical
// in every recipient's message (replicated rather than broadcast).
type Round3P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	PsiJI     compiler.NIZKPoKProof
	PsiIPrime compiler.NIZKPoKProof
}

// Validate is the deserialisation trust boundary for the round-3 message: both
// proofs must be present and non-zero. Their cryptographic validity is checked
// by the proof verifications in round 4.
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
