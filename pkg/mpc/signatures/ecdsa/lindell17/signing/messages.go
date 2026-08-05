package signing

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

// Round1OutputP2P carries the primary cosigner's round 1 output.
type Round1OutputP2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigR1Commitment hashcom.Commitment `cbor:"bigR1Commitment"`
}

// Validate checks that the round-1 message came from the unique signing peer.
func (m *Round1OutputP2P[P, B, S]) Validate(cosigner *Cosigner[P, B, S], sender sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round1OutputP2P message")
	}
	if err := validatePeer(cosigner, sender); err != nil {
		return errs.Wrap(err).WithMessage("invalid round-1 sender")
	}
	if m.BigR1Commitment == [hashcom.DigestSize]byte{} {
		return ErrValidation.WithMessage("missing BigR1 commitment in Round1OutputP2P message")
	}
	return nil
}

// Round2OutputP2P carries the secondary cosigner's round 2 output.
type Round2OutputP2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigR2      P                     `cbor:"bigR2"`
	BigR2Proof compiler.NIZKPoKProof `cbor:"bigR2Proof"`
}

// Validate checks the round-2 point at the message boundary. The proof is
// validated by the selected non-interactive verifier in round 3.
func (m *Round2OutputP2P[P, B, S]) Validate(cosigner *Cosigner[P, B, S], sender sharing.ID) error {
	if m == nil || utils.IsNil(m.BigR2) {
		return ErrValidation.WithMessage("missing fields in Round2OutputP2P message")
	}
	if err := validatePeer(cosigner, sender); err != nil {
		return errs.Wrap(err).WithMessage("invalid round-2 sender")
	}
	if m.BigR2.Structure().Name() != cosigner.suite.Curve().Name() {
		return ErrValidation.WithMessage("BigR2 curve does not match cosigner's curve in Round2OutputP2P message")
	}
	if m.BigR2.IsZero() || !m.BigR2.IsTorsionFree() {
		return ErrValidation.WithMessage("invalid BigR2 in Round2OutputP2P message")
	}
	return nil
}

// Round3OutputP2P carries the primary cosigner's round 3 output.
type Round3OutputP2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigR1Opening hashcom.Witness       `cbor:"bigR1Opening"`
	BigR1        P                     `cbor:"bigR1"`
	BigR1Proof   compiler.NIZKPoKProof `cbor:"bigR1Proof"`
}

// Validate checks the round-3 opening and point at the message boundary. The
// proof is validated by the selected non-interactive verifier in round 4.
func (m *Round3OutputP2P[P, B, S]) Validate(cosigner *Cosigner[P, B, S], sender sharing.ID) error {
	if m == nil || utils.IsNil(m.BigR1) {
		return ErrValidation.WithMessage("missing fields in Round3OutputP2P message")
	}
	if err := validatePeer(cosigner, sender); err != nil {
		return errs.Wrap(err).WithMessage("invalid round-3 sender")
	}
	if m.BigR1Opening == [hashcom.DigestSize]byte{} {
		return ErrValidation.WithMessage("missing BigR1 opening in Round3OutputP2P message")
	}
	if m.BigR1.Structure().Name() != cosigner.suite.Curve().Name() {
		return ErrValidation.WithMessage("BigR1 curve does not match cosigner's curve in Round3OutputP2P message")
	}
	if m.BigR1.IsZero() || !m.BigR1.IsTorsionFree() {
		return ErrValidation.WithMessage("invalid BigR1 in Round3OutputP2P message")
	}
	return nil
}

// Round4OutputP2P carries the secondary cosigner's round 4 output.
type Round4OutputP2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	C3 *paillier.Ciphertext `cbor:"c3"`
}

// Validate checks that C3 belongs to the primary's Paillier ciphertext group.
func (m *Round4OutputP2P[P, B, S]) Validate(cosigner *Cosigner[P, B, S], sender sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round4OutputP2P message")
	}
	if err := validatePeer(cosigner, sender); err != nil {
		return errs.Wrap(err).WithMessage("invalid round-4 sender")
	}
	if m.C3 == nil {
		return ErrValidation.WithMessage("missing C3 in Round4OutputP2P message")
	}
	secretKey := cosigner.shard.PaillierSecretKey()
	if secretKey == nil || !secretKey.CiphertextGroup().Contains(m.C3.Value()) {
		return ErrValidation.WithMessage("C3 does not belong to receiver's Paillier ciphertext group in Round4OutputP2P message")
	}
	return nil
}

func validatePeer[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](cosigner *Cosigner[P, B, S], sender sharing.ID) error {
	if cosigner == nil || cosigner.ctx == nil {
		return ErrValidation.WithMessage("missing cosigner context")
	}
	if sender == cosigner.SharingID() || !cosigner.ctx.Quorum().Contains(sender) || cosigner.ctx.Quorum().Size() != 2 {
		return ErrValidation.WithMessage("sender %d is not the unique signing peer", sender)
	}
	return nil
}
