package hpke

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

func WithApplicationInfo[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](info []byte) encryption.EncrypterOption[*Encrypter, P, B, S] {
	return func(e *Encrypter[P, B, S]) error {
		e.info = info
		return nil
	}
}

func WithPreSharedKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](pskId []byte, psk *encryption.SymmetricKey) encryption.EncrypterOption[*Encrypter, P, B, S] {
	return func(e *Encrypter[P, B, S]) error {
		e.pskId = pskId
		e.psk = psk
		return nil
	}
}

func WithAuthentication[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](sk *PrivateKey[S]) encryption.EncrypterOption[*Encrypter[P, B, S], P, B, S] {
	return func(e *Encrypter[P, B, S]) error {
		e.senderPrivateKey = sk
		return nil
	}
}

func WithAuthPSK[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](sk *PrivateKey[S], pskId []byte, psk *encryption.SymmetricKey) encryption.EncryptionOption[*Encrypter[P, B, S], P, B, S] {
	return func(e *Encrypter[P, B, S]) error {
		e.senderPrivateKey = sk
		e.pskId = pskId
		e.psk = psk
		return nil
	}
}

func WithPsk[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](pskId []byte, psk *encryption.SymmetricKey) encryption.EncryptionOption[*Encrypter[P, B, S], P, B, S] {
	return func(e *Encrypter[P, B, S]) error {
		e.pskId = pskId
		e.psk = psk
		return nil
	}
}

func WithAuth[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](sk *PrivateKey[S]) encryption.EncryptionOption[*Encrypter[P, B, S], P, B, S] {
	return func(e *Encrypter[P, B, S]) error {
		e.senderPrivateKey = sk
		return nil
	}
}

type Encrypter[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	senderContext    *SenderContext
	capsule          *Capsule[P, B, S]
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

func (e *Encrypter[P, B, S]) Encrypt(plaintext []byte, receiver *PublicKey[P, B, S], prng io.Reader) (Ciphertext, *Capsule[P, B, S], error) {
	if receiver == nil {
		return nil, nil, errs.NewIsNil("receiver public key")
	}
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	var ct []byte
	var err error
	switch e.Mode() {
	case Base:
		ct, err = e.senderContext.Seal(plaintext, nil)
	case PSk:
		ct, err = e.senderContext.Seal(plaintext, nil)
	}
}
