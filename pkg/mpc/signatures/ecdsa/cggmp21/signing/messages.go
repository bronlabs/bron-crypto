package signing

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/hjky"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

type Round1Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ZeroR1 *hjky.Round1Broadcast[P, S] `cbor:"zeroR1"`

	BigK *paillier.Ciphertext      `cbor:"bigK"`
	BigG *paillier.Ciphertext      `cbor:"bigG"`
	BigY *elgamal.PublicKey[P, S]  `cbor:"bigY"`
	BigA *elgamal.Ciphertext[P, S] `cbor:"bigA"`
	BigB *elgamal.Ciphertext[P, S] `cbor:"bigB"`
}

func (r1b *Round1Broadcast[P, B, S]) Validate(signer *Signer[P, B, S], senderID sharing.ID) error {
	if r1b == nil {
		return cggmp21.ErrNil.WithMessage("round 1 broadcast")
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
	if err := validateElGamalPublicKey(r1b.BigY, "BigY"); err != nil {
		return err
	}
	if err := validateElGamalCiphertext(r1b.BigY, r1b.BigA, "BigA"); err != nil {
		return err
	}
	return validateElGamalCiphertext(r1b.BigY, r1b.BigB, "BigB")
}

type Round1P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ZeroR1 *hjky.Round1P2P[P, S] `cbor:"zeroR1"`
	Psi0   compiler.NIZKPoKProof `cbor:"psi0"`
	Psi1   compiler.NIZKPoKProof `cbor:"psi1"`
}

func (r1u *Round1P2P[P, B, S]) Validate(signer *Signer[P, B, S], senderID sharing.ID) error {
	if r1u == nil {
		return cggmp21.ErrNil.WithMessage("round 1 P2P")
	}
	if err := r1u.ZeroR1.Validate(signer.zeroParty, senderID); err != nil {
		return errs.Wrap(err).WithMessage("invalid zero r1 message")
	}
	return nil
}

type Round2Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigGamma P                     `cbor:"bigGamma"`
	Psi      compiler.NIZKPoKProof `cbor:"psi"`
}

func (r2b *Round2Broadcast[P, B, S]) Validate(signer *Signer[P, B, S], _ sharing.ID) error {
	if r2b == nil {
		return cggmp21.ErrNil.WithMessage("round 2 broadcast")
	}
	return validatePoint(r2b.BigGamma, "BigGamma", false)
}

type Round2P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigD    *paillier.Ciphertext  `cbor:"bigD"`
	BigF    *paillier.Ciphertext  `cbor:"bigF"`
	BigDHat *paillier.Ciphertext  `cbor:"bigDHat"`
	BigFHat *paillier.Ciphertext  `cbor:"bigFHat"`
	Psi     compiler.NIZKPoKProof `cbor:"psi"`
	PsiHat  compiler.NIZKPoKProof `cbor:"psiHat"`
}

func (r2u *Round2P2P[P, B, S]) Validate(signer *Signer[P, B, S], senderID sharing.ID) error {
	if r2u == nil {
		return cggmp21.ErrNil.WithMessage("round 2 P2P")
	}
	localPaillierPublicKey := signer.shard.AuxInfo().PaillierSecretKey().Public()
	if err := validatePaillierCiphertext(localPaillierPublicKey, r2u.BigD, "BigD"); err != nil {
		return err
	}
	if err := validatePaillierCiphertext(localPaillierPublicKey, r2u.BigF, "BigF"); err != nil {
		return err
	}
	if err := validatePaillierCiphertext(localPaillierPublicKey, r2u.BigDHat, "BigDHat"); err != nil {
		return err
	}
	return validatePaillierCiphertext(localPaillierPublicKey, r2u.BigFHat, "BigFHat")
}

type Round3Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Delta    S                     `cbor:"delta"`
	BigS     P                     `cbor:"bigS"`
	BigDelta P                     `cbor:"bigDelta"`
	Psi      compiler.NIZKPoKProof `cbor:"psi"`
}

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
	return validatePoint(r3b.BigDelta, "BigDelta", false)
}

type Round4P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	PartialSignature *cggmp21.PartialSignature[P, B, S] `cbor:"partialSignature"`
}

func (r4u *Round4P2P[P, B, S]) Validate(signer *Signer[P, B, S], sender sharing.ID) error {
	if r4u == nil || r4u.PartialSignature == nil {
		return cggmp21.ErrNil.WithMessage("round 4 P2P")
	}
	if err := validatePoint(r4u.PartialSignature.Gamma, "Gamma", false); err != nil {
		return err
	}
	return validateScalar(r4u.PartialSignature.Sigma, "Sigma", true)
}

func validatePaillierCiphertext(publicKey *paillier.PublicKey, ciphertext *paillier.Ciphertext, name string) error {
	if publicKey == nil || publicKey.Group() == nil {
		return cggmp21.ErrNil.WithMessage("Paillier public key for %s", name)
	}
	if ciphertext == nil || ciphertext.Value() == nil {
		return cggmp21.ErrNil.WithMessage("%s", name)
	}
	if !publicKey.CiphertextGroup().Contains(ciphertext.Value()) {
		return cggmp21.ErrValidationFailed.WithMessage("%s is not in the expected Paillier ciphertext group", name)
	}
	return nil
}

func validateElGamalPublicKey[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](publicKey *elgamal.PublicKey[P, S], name string) error {
	if publicKey == nil || utils.IsNil(publicKey.Value()) {
		return cggmp21.ErrNil.WithMessage("%s", name)
	}
	return validatePoint(publicKey.Value(), name, false)
}

func validateElGamalCiphertext[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	publicKey *elgamal.PublicKey[P, S],
	ciphertext *elgamal.Ciphertext[P, S],
	name string,
) error {
	if publicKey == nil || utils.IsNil(publicKey.Value()) {
		return cggmp21.ErrNil.WithMessage("ElGamal public key for %s", name)
	}
	if ciphertext == nil || ciphertext.Value() == nil {
		return cggmp21.ErrNil.WithMessage("%s", name)
	}
	if !publicKey.CiphertextGroup().Contains(ciphertext.Value()) {
		return cggmp21.ErrValidationFailed.WithMessage("%s is not in the expected ElGamal ciphertext group", name)
	}
	for _, component := range ciphertext.Value().Components() {
		if utils.IsNil(component) {
			return cggmp21.ErrNil.WithMessage("%s component", name)
		}
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
