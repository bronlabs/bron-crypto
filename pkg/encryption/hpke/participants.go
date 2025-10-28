package hpke

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

func EncryptingWithApplicationInfo[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](info []byte) encryption.EncrypterOption[*Encrypter[P, B, S], *PublicKey[P, B, S], Message, Ciphertext, *Capsule[P, B, S]] {
	return func(e *Encrypter[P, B, S]) error {
		e.info = info
		return nil
	}
}

func EncryptingWithAuthentication[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](sk *PrivateKey[S]) encryption.EncrypterOption[*Encrypter[P, B, S], *PublicKey[P, B, S], Message, Ciphertext, *Capsule[P, B, S]] {
	return func(e *Encrypter[P, B, S]) error {
		e.senderPrivateKey = sk
		return nil
	}
}

func EncryptingWithPreSharedKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](pskId []byte, psk *encryption.SymmetricKey) encryption.EncrypterOption[*Encrypter[P, B, S], *PublicKey[P, B, S], Message, Ciphertext, *Capsule[P, B, S]] {
	return func(e *Encrypter[P, B, S]) error {
		e.pskId = pskId
		e.psk = psk
		return nil
	}
}

func EncryptingWithAuthPSK[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](sk *PrivateKey[S], pskId []byte, psk *encryption.SymmetricKey) encryption.EncrypterOption[*Encrypter[P, B, S], *PublicKey[P, B, S], Message, Ciphertext, *Capsule[P, B, S]] {
	return func(e *Encrypter[P, B, S]) error {
		e.senderPrivateKey = sk
		e.pskId = pskId
		e.psk = psk
		return nil
	}
}

type Encrypter[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	suite            *CipherSuite
	senderPrivateKey *PrivateKey[S]
	info             []byte
	pskId            []byte
	psk              *encryption.SymmetricKey
}

func (e *Encrypter[P, B, S]) Mode() ModeID {
	if e.psk != nil && len(e.pskId) > 0 {
		if e.senderPrivateKey != nil {
			return AuthPSk
		}
		return PSk
	}
	if e.senderPrivateKey != nil {
		return Auth
	}
	return Base
}

func (e *Encrypter[P, B, S]) Encrypt(plaintext Message, receiver *PublicKey[P, B, S], prng io.Reader) (Ciphertext, *Capsule[P, B, S], error) {
	return e.Seal(plaintext, receiver, nil, prng)
}

func (e *Encrypter[P, B, S]) Seal(plaintext Message, receiver *PublicKey[P, B, S], aad []byte, prng io.Reader) (Ciphertext, *Capsule[P, B, S], error) {
	if receiver == nil {
		return nil, nil, errs.NewIsNil("receiver public key")
	}
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}

	var ctx *SenderContext[P, B, S]
	var err error
	switch e.Mode() {
	case Base:
		ctx, err = SetupBaseS(e.suite, receiver, e.info, prng)
	case Auth:
		ctx, err = SetupAuthS(e.suite, receiver, e.senderPrivateKey, e.info, prng)
	case PSk:
		ctx, err = SetupPSKS(e.suite, receiver, e.psk.Bytes(), e.pskId, e.info, prng)
	case AuthPSk:
		ctx, err = SetupAuthPSKS(e.suite, receiver, e.senderPrivateKey, e.psk.Bytes(), e.pskId, e.info, prng)
	default:
		return nil, nil, errs.NewType("unsupported mode: %d", e.Mode())
	}
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not setup sender context")
	}

	ct, err := ctx.Seal(plaintext, aad)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not seal plaintext")
	}
	return Ciphertext(ct), ctx.Capsule, nil
}

func DecryptingWithApplicationInfo[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](info []byte) encryption.DecrypterOption[*Decrypter[P, B, S], Message, Ciphertext] {
	return func(d *Decrypter[P, B, S]) error {
		d.info = info
		return nil
	}
}

func DecryptingWithAuthentication[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](pk *PublicKey[P, B, S]) encryption.DecrypterOption[*Decrypter[P, B, S], Message, Ciphertext] {
	return func(d *Decrypter[P, B, S]) error {
		d.senderPublicKey = pk
		return nil
	}
}
func DecryptingWithPreSharedKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](pskId []byte, psk *encryption.SymmetricKey) encryption.DecrypterOption[*Decrypter[P, B, S], Message, Ciphertext] {
	return func(d *Decrypter[P, B, S]) error {
		d.pskId = pskId
		d.psk = psk
		return nil
	}
}
func DecryptingWithAuthPSK[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](pk *PublicKey[P, B, S], pskId []byte, psk *encryption.SymmetricKey) encryption.DecrypterOption[*Decrypter[P, B, S], Message, Ciphertext] {
	return func(d *Decrypter[P, B, S]) error {
		d.senderPublicKey = pk
		d.pskId = pskId
		d.psk = psk
		return nil
	}
}

type Decrypter[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	suite      *CipherSuite
	privateKey *PrivateKey[S]

	senderPublicKey *PublicKey[P, B, S]
	info            []byte
	pskId           []byte
	psk             *encryption.SymmetricKey

	ctx *ReceiverContext
}

func (e *Decrypter[P, B, S]) Mode() ModeID {
	if e.psk != nil && len(e.pskId) > 0 {
		if e.senderPublicKey != nil {
			return AuthPSk
		}
		return PSk
	}
	if e.senderPublicKey != nil {
		return Auth
	}
	return Base
}

func (d *Decrypter[P, B, S]) Decrypt(ciphertext Ciphertext) (Message, error) {
	return d.Open(ciphertext, nil)
}

func (d *Decrypter[P, B, S]) Open(ciphertext Ciphertext, aad []byte) (Message, error) {
	if ciphertext == nil {
		return nil, errs.NewIsNil("ciphertext")
	}
	pt, err := d.ctx.Open([]byte(ciphertext), aad)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get plaintext")
	}
	return Message(pt), nil
}
