package signing

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/indcpacom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/hjky"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

// Round1Broadcast is the public round 1 signing message.
type Round1Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ZeroR1 *hjky.Round1Broadcast[P, S] `cbor:"zeroR1"`

	BigK *paillier.Ciphertext `cbor:"bigK"`
	BigG *paillier.Ciphertext `cbor:"bigG"`
	BigY *indcpacom.HomomorphicCommitmentKey[
		*elgamal.PublicKey[P, S],
		*elgamal.Plaintext[P, S],
		*elgamal.Nonce[S],
		*elgamal.Ciphertext[P, S],
		S,
	] `cbor:"bigY"`
	BigA *indcpacom.Commitment[*elgamal.Ciphertext[P, S]] `cbor:"bigA"`
	BigB *indcpacom.Commitment[*elgamal.Ciphertext[P, S]] `cbor:"bigB"`
}

// Validate checks a round 1 broadcast against the sender's public parameters.
func (r1b *Round1Broadcast[P, B, S]) Validate(signer *Signer[P, B, S], senderID sharing.ID) error {
	if r1b == nil {
		return cggmp21.ErrNil.WithMessage("round 1 broadcast")
	}
	if r1b.ZeroR1 == nil {
		return cggmp21.ErrNil.WithMessage("round 1 zero broadcast")
	}
	if err := r1b.ZeroR1.Validate(signer.zeroParty, senderID); err != nil {
		return errs.Wrap(err).WithMessage("invalid zero r1 message")
	}
	auxInfo := signer.shard.AuxInfo()
	senderPaillierPublicKey, ok := auxInfo.PaillierPublicKey(senderID)
	if !ok {
		return cggmp21.ErrValidationFailed.WithMessage("missing Paillier public key for sender %d", senderID)
	}
	if err := validatePaillierCiphertext(senderPaillierPublicKey, r1b.BigK, "BigK"); err != nil {
		return err
	}
	if err := validatePaillierCiphertext(senderPaillierPublicKey, r1b.BigG, "BigG"); err != nil {
		return err
	}
	if err := validateElGamalCommitmentKey(r1b.BigY, "BigY"); err != nil {
		return err
	}
	if err := validateElGamalCiphertext(r1b.BigY, r1b.BigA, "BigA"); err != nil {
		return err
	}
	return validateElGamalCiphertext(r1b.BigY, r1b.BigB, "BigB")
}

// Round1P2P is the private round 1 signing message sent to one recipient.
type Round1P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ZeroR1 *hjky.Round1P2P[P, S] `cbor:"zeroR1"`
	Psi0   compiler.NIZKPoKProof `cbor:"psi0"`
	Psi1   compiler.NIZKPoKProof `cbor:"psi1"`
}

// Validate checks a round 1 private message before proof verification.
func (r1u *Round1P2P[P, B, S]) Validate(signer *Signer[P, B, S], senderID sharing.ID) error {
	if r1u == nil {
		return cggmp21.ErrNil.WithMessage("round 1 P2P")
	}
	if r1u.ZeroR1 == nil {
		return cggmp21.ErrNil.WithMessage("round 1 zero P2P")
	}
	if err := r1u.ZeroR1.Validate(signer.zeroParty, senderID); err != nil {
		return errs.Wrap(err).WithMessage("invalid zero r1 message")
	}
	if err := validateProof(r1u.Psi0, "Psi0"); err != nil {
		return err
	}
	return validateProof(r1u.Psi1, "Psi1")
}

// Round2Broadcast is the public round 2 signing message.
type Round2Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigGamma P                     `cbor:"bigGamma"`
	Psi      compiler.NIZKPoKProof `cbor:"psi"`
}

// Validate checks a round 2 broadcast before proof verification.
func (r2b *Round2Broadcast[P, B, S]) Validate(signer *Signer[P, B, S], _ sharing.ID) error {
	if r2b == nil {
		return cggmp21.ErrNil.WithMessage("round 2 broadcast")
	}
	if err := validatePoint(r2b.BigGamma, "BigGamma", false); err != nil {
		return err
	}
	return validateProof(r2b.Psi, "Psi")
}

// Round2P2P is the private round 2 signing message sent to one recipient.
type Round2P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigD    *paillier.Ciphertext  `cbor:"bigD"`
	BigF    *paillier.Ciphertext  `cbor:"bigF"`
	BigDHat *paillier.Ciphertext  `cbor:"bigDHat"`
	BigFHat *paillier.Ciphertext  `cbor:"bigFHat"`
	Psi     compiler.NIZKPoKProof `cbor:"psi"`
	PsiHat  compiler.NIZKPoKProof `cbor:"psiHat"`
}

// Validate checks a round 2 private message before proof verification.
func (r2u *Round2P2P[P, B, S]) Validate(signer *Signer[P, B, S], senderID sharing.ID) error {
	if r2u == nil {
		return cggmp21.ErrNil.WithMessage("round 2 P2P")
	}
	localPaillierPublicKey := signer.shard.AuxInfo().PaillierSecretKey().Public()
	senderPaillierPublicKey, ok := signer.shard.AuxInfo().PaillierPublicKey(senderID)
	if !ok {
		return cggmp21.ErrValidationFailed.WithMessage("missing Paillier public key for sender %d", senderID)
	}
	if err := validatePaillierCiphertext(localPaillierPublicKey, r2u.BigD, "BigD"); err != nil {
		return err
	}
	if err := validatePaillierCiphertext(senderPaillierPublicKey, r2u.BigF, "BigF"); err != nil {
		return err
	}
	if err := validatePaillierCiphertext(localPaillierPublicKey, r2u.BigDHat, "BigDHat"); err != nil {
		return err
	}
	if err := validatePaillierCiphertext(senderPaillierPublicKey, r2u.BigFHat, "BigFHat"); err != nil {
		return err
	}
	if err := validateProof(r2u.Psi, "Psi"); err != nil {
		return err
	}
	return validateProof(r2u.PsiHat, "PsiHat")
}

// Round3Broadcast is the public round 3 signing message.
type Round3Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Delta    S                     `cbor:"delta"`
	BigS     P                     `cbor:"bigS"`
	BigDelta P                     `cbor:"bigDelta"`
	Psi      compiler.NIZKPoKProof `cbor:"psi"`
}

// Validate checks a round 3 broadcast before proof verification.
func (r3b *Round3Broadcast[P, B, S]) Validate(signer *Signer[P, B, S], sender sharing.ID) error {
	if r3b == nil {
		return cggmp21.ErrNil.WithMessage("round 3 broadcast")
	}
	if err := validateScalar(r3b.Delta, "Delta", true); err != nil {
		return err
	}
	if err := validatePoint(r3b.BigS, "BigS", true); err != nil {
		return err
	}
	if err := validatePoint(r3b.BigDelta, "BigDelta", false); err != nil {
		return err
	}
	return validateProof(r3b.Psi, "Psi")
}

// Round4P2P is a private partial-signature message.
type Round4P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	PartialSignature *cggmp21.PartialSignature[P, B, S] `cbor:"partialSignature"`
}

// Validate checks a round 4 private partial-signature message.
func (r4u *Round4P2P[P, B, S]) Validate(signer *Signer[P, B, S], sender sharing.ID) error {
	if r4u == nil || r4u.PartialSignature == nil {
		return cggmp21.ErrNil.WithMessage("round 4 P2P")
	}
	if err := validatePoint(r4u.PartialSignature.Gamma, "Gamma", false); err != nil {
		return err
	}
	return validateScalar(r4u.PartialSignature.Sigma, "Sigma", true)
}

// RedAlertBroadcast is the public red-alert message with revealed Paillier masks and proofs.
type RedAlertBroadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigD map[sharing.ID]*paillier.Ciphertext  `cbor:"bigD"`
	BigF map[sharing.ID]*paillier.Ciphertext  `cbor:"bigF"`
	Phi  compiler.NIZKPoKProof                `cbor:"phi"`
	PhiJ map[sharing.ID]compiler.NIZKPoKProof `cbor:"phiJ"`
}

// Validate checks a red-alert broadcast against the signing state and sender's public parameters.
func (a *RedAlertBroadcast[P, B, S]) Validate(p *RedAlertParticipant[P, B, S], sender sharing.ID) error {
	if a == nil {
		return cggmp21.ErrNil.WithMessage("red alert broadcast")
	}
	if a.BigD == nil || a.BigF == nil || a.PhiJ == nil {
		return cggmp21.ErrNil.WithMessage("red alert broadcast maps")
	}
	if len(a.Phi) == 0 {
		return cggmp21.ErrNil.WithMessage("red alert dec proof")
	}
	signer := p.signer()
	senderPaillierPublicKey, err := paillierPublicKeyFor(signer, sender)
	if err != nil {
		return err
	}
	for recipient := range signer.ctx.AllPartiesOrdered() {
		if recipient == sender {
			continue
		}
		d, ok := a.BigD[recipient]
		if !ok {
			return network.ErrMissing.WithMessage("red alert D for recipient %d", recipient)
		}
		f, ok := a.BigF[recipient]
		if !ok {
			return network.ErrMissing.WithMessage("red alert F for recipient %d", recipient)
		}
		proof, ok := a.PhiJ[recipient]
		if !ok || len(proof) == 0 {
			return network.ErrMissing.WithMessage("red alert aff-g* proof for recipient %d", recipient)
		}
		recipientPaillierPublicKey, err := paillierPublicKeyFor(signer, recipient)
		if err != nil {
			return err
		}
		if err := validatePaillierCiphertext(recipientPaillierPublicKey, d, "red alert BigD"); err != nil {
			return err
		}
		if err := validatePaillierCiphertext(senderPaillierPublicKey, f, "red alert BigF"); err != nil {
			return err
		}
	}

	localID := signer.ctx.HolderID()
	if localID != sender {
		receivedD, receivedF := p.base.receivedCiphertexts()
		expectedD := receivedD[sender]
		expectedF := receivedF[sender]
		if !a.BigD[localID].Equal(expectedD) {
			return cggmp21.ErrValidationFailed.WithMessage("red alert BigD for local recipient differs from round 2")
		}
		if !a.BigF[localID].Equal(expectedF) {
			return cggmp21.ErrValidationFailed.WithMessage("red alert BigF for local recipient differs from round 2")
		}
	}
	return nil
}

func validatePaillierCiphertext(publicKey *paillier.PublicKey, ciphertext *paillier.Ciphertext, name string) error {
	if publicKey == nil {
		return cggmp21.ErrNil.WithMessage("Paillier public key for %s", name)
	}
	if ciphertext == nil {
		return cggmp21.ErrNil.WithMessage("%s", name)
	}
	if !publicKey.CiphertextGroup().Contains(ciphertext.Value()) {
		return cggmp21.ErrValidationFailed.WithMessage("%s is not in the expected Paillier ciphertext group", name)
	}
	return nil
}

func validateElGamalCommitmentKey[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	commitmentKey *indcpacom.HomomorphicCommitmentKey[
		*elgamal.PublicKey[P, S],
		*elgamal.Plaintext[P, S],
		*elgamal.Nonce[S],
		*elgamal.Ciphertext[P, S],
		S,
	],
	name string,
) error {
	if commitmentKey == nil {
		return cggmp21.ErrNil.WithMessage("%s", name)
	}
	value := commitmentKey.EncryptionKey().Value()
	if value.IsZero() || !value.IsTorsionFree() {
		return cggmp21.ErrValidationFailed.WithMessage("invalid %s", name)
	}
	return nil
}

func validateElGamalCiphertext[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	commitmentKey *indcpacom.HomomorphicCommitmentKey[
		*elgamal.PublicKey[P, S],
		*elgamal.Plaintext[P, S],
		*elgamal.Nonce[S],
		*elgamal.Ciphertext[P, S],
		S,
	],
	commitment *indcpacom.Commitment[*elgamal.Ciphertext[P, S]],
	name string,
) error {
	if commitmentKey == nil {
		return cggmp21.ErrNil.WithMessage("ElGamal commitment key for %s", name)
	}
	if commitment == nil {
		return cggmp21.ErrNil.WithMessage("%s", name)
	}
	publicKey := commitmentKey.EncryptionKey()
	ciphertext := commitment.Value()
	if !publicKey.CiphertextGroup().Contains(ciphertext.Value()) {
		return cggmp21.ErrValidationFailed.WithMessage("%s is not in the expected ElGamal ciphertext group", name)
	}
	for _, component := range ciphertext.Value().Components() {
		if !component.IsTorsionFree() {
			return cggmp21.ErrValidationFailed.WithMessage("%s component is not torsion free", name)
		}
	}
	return nil
}

func validatePoint[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](point P, name string, allowZero bool) error {
	if utils.IsNil(point) {
		return cggmp21.ErrNil.WithMessage("%s", name)
	}
	if (!allowZero && point.IsZero()) || !point.IsTorsionFree() {
		return cggmp21.ErrValidationFailed.WithMessage("invalid %s", name)
	}
	return nil
}

func validateScalar[S algebra.PrimeFieldElement[S]](scalar S, name string, allowZero bool) error {
	if utils.IsNil(scalar) {
		return cggmp21.ErrNil.WithMessage("%s", name)
	}
	if !allowZero && scalar.IsZero() {
		return cggmp21.ErrValidationFailed.WithMessage("invalid %s", name)
	}
	return nil
}

func validateProof(proof compiler.NIZKPoKProof, name string) error {
	if len(proof) == 0 {
		return cggmp21.ErrNil.WithMessage("%s proof", name)
	}
	return nil
}
