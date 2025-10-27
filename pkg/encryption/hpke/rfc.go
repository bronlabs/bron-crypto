package hpke

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

// These are the actual APIs defined in the RFC.

type SenderContext[S algebra.PrimeFieldElement[S]] struct {
	myPrivateKey *PrivateKey[S]
	c            *context
}

func NewSenderContext[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](mode ModeID, suite *CipherSuite, receiverPublicKey *PublicKey[P, B, S], senderPrivateKey *PrivateKey[S], info, psk, pskId []byte, prng io.Reader) (*SenderContext[S], *PublicKey[P, B, S], error) {
	if suite == nil {
		return nil, nil, errs.NewIsNil("ciphersuite is nil")
	}

	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](receiverPublicKey.Value().Structure())
	kdf, err := NewKDF(suite.KDF)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create KDF scheme")
	}
	kem, err := NewDHKEM(curve, kdf)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create DHKEM scheme")
	}
	var sharedSecret []byte
	var ephemeralPublicKey *PublicKey[P, B, S]
	if mode == Auth || mode == AuthPSk {
		sharedSecret, ephemeralPublicKey, err = kem.AuthEncap(receiverPublicKey, senderPrivateKey, prng)
	} else {
		if senderPrivateKey != nil {
			return nil, nil, errs.NewFailed("sender private key unsupported")
		}

		sharedSecret, ephemeralPublicKey, err = kem.Encap(receiverPublicKey, prng)
	}
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not finish kem.Encap")
	}

	ctx, _, err := keySchedule(SenderRole, suite, mode, sharedSecret, info, psk, pskId)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "key scheduling failed")
	}

	return &SenderContext[S]{
		myPrivateKey: senderPrivateKey,
		c:            ctx,
	}, ephemeralPublicKey, nil
}

func (s *SenderContext[S]) Seal(plaintext, additionalData []byte) (ciphertext []byte, err error) {
	nonce, err := s.c.computeNonce()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute nonce")
	}

	ciphertext = s.c.aead.Seal(nil, nonce, plaintext, additionalData)
	if err := s.c.incrementSeq(); err != nil {
		return nil, errs.WrapFailed(err, "increment sequence failed")
	}

	return ciphertext, nil
}

// Export takes as input a context string exporter_context and a desired length L in bytes, and produces a secret derived from the internal exporter secret using the corresponding KDF Expand function. This is an interface for exporting secrets from the encryption context using a variable-length pseudorandom function (PRF), similar to the TLS 1.3 exporter interface
// https://www.rfc-editor.org/rfc/rfc9180.html#name-secret-export
func (s *SenderContext[S]) Export(exporterContext []byte, L int) ([]byte, error) {
	return s.c.export(exporterContext, L)
}

type ReceiverContext[S algebra.PrimeFieldElement[S]] struct {
	myPrivateKey *PrivateKey[S]
	c            *context
}

func NewReceiverContext[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](mode ModeID, suite *CipherSuite, receiverPrivatekey *PrivateKey[S], ephemeralPublicKey, senderPublicKey *PublicKey[P, B, S], info, psk, pskId []byte) (*ReceiverContext[S], error) {
	if suite == nil {
		return nil, errs.NewIsNil("ciphersuite is nil")
	}

	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](ephemeralPublicKey.Value().Structure())
	kdf, err := NewKDF(suite.KDF)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create KDF scheme")
	}
	kem, err := NewDHKEM(curve, kdf)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create DHKEM scheme")
	}

	var sharedSecret []byte
	if mode == Auth || mode == AuthPSk {
		sharedSecret, err = kem.AuthDecap(receiverPrivatekey, senderPublicKey, ephemeralPublicKey)
	} else {
		if senderPublicKey != nil {
			return nil, errs.NewFailed("sender public key unsupported")
		}

		sharedSecret, err = kem.Decap(receiverPrivatekey, ephemeralPublicKey)
	}
	if err != nil {
		return nil, errs.WrapFailed(err, "could not finish decapsulate")
	}

	ctx, _, err := keySchedule(ReceiverRole, suite, mode, sharedSecret, info, psk, pskId)
	if err != nil {
		return nil, errs.WrapFailed(err, "key scheduling failed")
	}

	return &ReceiverContext[S]{
		myPrivateKey: receiverPrivatekey,
		c:            ctx,
	}, nil
}

func (r *ReceiverContext[S]) Open(ciphertext, additionalData []byte) (plaintext []byte, err error) {
	nonce, err := r.c.computeNonce()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute nonce")
	}

	plaintext, err = r.c.aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not open ciphertext")
	}

	if err := r.c.incrementSeq(); err != nil {
		return nil, errs.WrapFailed(err, "increment sequence failed")
	}

	return plaintext, nil
}

// Export takes as input a context string exporter_context and a desired length L in bytes, and produces a secret derived from the internal exporter secret using the corresponding KDF Expand function. This is an interface for exporting secrets from the encryption context using a variable-length pseudorandom function (PRF), similar to the TLS 1.3 exporter interface
// https://www.rfc-editor.org/rfc/rfc9180.html#name-secret-export
func (r *ReceiverContext[S]) Export(exporterContext []byte, L int) ([]byte, error) {
	return r.c.export(exporterContext, L)
}

// SetupBaseS establishes a context for the sender that can be used to encrypt.
// https://www.rfc-editor.org/rfc/rfc9180.html#name-encryption-to-a-public-key
func SetupBaseS[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPublicKey *PublicKey[P, B, S], info []byte, prng io.Reader) (enc *PublicKey[P, B, S], sender *SenderContext[S], err error) {
	if suite == nil {
		return nil, nil, errs.NewIsNil("ciphersuite is nil")
	}

	sender, enc, err = NewSenderContext(Base, suite, receiverPublicKey, nil, info, nil, nil, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to construct sender context")
	}

	return enc, sender, nil
}

func SealBase[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, additionalData, plaintext []byte, receiverPublicKey *PublicKey[P, B, S], info []byte, prng io.Reader) (ephemeralPublicKey *PublicKey[P, B, S], ciphertext []byte, err error) {
	enc, ctx, err := SetupBaseS(suite, receiverPublicKey, info, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not setup sender")
	}

	ct, err := ctx.Seal(plaintext, additionalData)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not seal plaintext")
	}

	return enc, ct, nil
}

// SetupBaseR establishes a context for the receiver that can be used to decrypt
// https://www.rfc-editor.org/rfc/rfc9180.html#name-encryption-to-a-public-key
func SetupBaseR[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPrivatekey *PrivateKey[S], ephemeralPublicKey *PublicKey[P, B, S], info []byte) (*ReceiverContext[S], error) {
	receiver, err := NewReceiverContext(Base, suite, receiverPrivatekey, ephemeralPublicKey, nil, info, nil, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to construct receiver context")
	}

	return receiver, nil
}

func OpenBase[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, additionalData, ciphertext []byte, receiverPrivatekey *PrivateKey[S], ephemeralPublicKey *PublicKey[P, B, S], info []byte) (plaintext []byte, err error) {
	ctx, err := SetupBaseR(suite, receiverPrivatekey, ephemeralPublicKey, info)
	if err != nil {
		return nil, errs.WrapFailed(err, "Could not construct receiver")
	}

	pt, err := ctx.Open(ciphertext, additionalData)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get plaintext")
	}

	return pt, nil
}

// SetupPSKS establishes a context for the sender that can be used to encrypt. This variant extends the base mechanism by allowing the recipient to authenticate that the sender possessed a given PSK. We assume that both parties have been provisioned with both the PSK value psk and another byte string psk_id that is used to identify which PSK should be used.
// https://www.rfc-editor.org/rfc/rfc9180.html#name-authentication-using-a-pre-
func SetupPSKS[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPublicKey *PublicKey[P, B, S], psk, pskId, info []byte, prng io.Reader) (enc *PublicKey[P, B, S], sender *SenderContext[S], err error) {
	sender, enc, err = NewSenderContext(PSk, suite, receiverPublicKey, nil, info, psk, pskId, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to construct sender context")
	}

	return enc, sender, nil
}

func SealPSK[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, additionalData, plaintext []byte, receiverPublicKey *PublicKey[P, B, S], psk, pskId, info []byte, prng io.Reader) (ephemeralPublicKey *PublicKey[P, B, S], ciphertext []byte, err error) {
	enc, ctx, err := SetupPSKS(suite, receiverPublicKey, psk, pskId, info, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not setup sender")
	}

	ct, err := ctx.Seal(plaintext, additionalData)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not seal plaintext")
	}

	return enc, ct, nil
}

// SetupPSKR establishes a context for the receiver that can be used to decrypt. This variant extends the base mechanism by allowing the recipient to authenticate that the sender possessed a given PSK. We assume that both parties have been provisioned with both the PSK value psk and another byte string psk_id that is used to identify which PSK should be used.
// https://www.rfc-editor.org/rfc/rfc9180.html#name-authentication-using-a-pre-
func SetupPSKR[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPrivatekey *PrivateKey[S], ephemeralPublicKey *PublicKey[P, B, S], psk, pskId, info []byte) (*ReceiverContext[S], error) {
	receiver, err := NewReceiverContext(PSk, suite, receiverPrivatekey, ephemeralPublicKey, nil, info, psk, pskId)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to construct receiver context")
	}

	return receiver, nil
}

func OpenPSK[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, additionalData, ciphertext []byte, receiverPrivatekey *PrivateKey[S], ephemeralPublicKey *PublicKey[P, B, S], psk, pskId, info []byte) (plaintext []byte, err error) {
	ctx, err := SetupPSKR(suite, receiverPrivatekey, ephemeralPublicKey, psk, pskId, info)
	if err != nil {
		return nil, errs.WrapFailed(err, "Could not construct receiver")
	}

	pt, err := ctx.Open(ciphertext, additionalData)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get plaintext")
	}

	return pt, nil
}

// SetupAuthS establishes a context for the sender that can be used to encrypt.This variant extends the base mechanism by allowing the recipient to authenticate that the sender possessed a given KEM private key.
// https://www.rfc-editor.org/rfc/rfc9180.html#name-authentication-using-an-asy
func SetupAuthS[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPublicKey *PublicKey[P, B, S], senderPrivateKey *PrivateKey[S], info []byte, prng io.Reader) (enc *PublicKey[P, B, S], sender *SenderContext[S], err error) {
	sender, enc, err = NewSenderContext(Auth, suite, receiverPublicKey, senderPrivateKey, info, nil, nil, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to construct sender context")
	}

	return enc, sender, nil
}

func SealAuth[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, additionalData, plaintext []byte, receiverPublicKey *PublicKey[P, B, S], senderPrivateKey *PrivateKey[S], info []byte, prng io.Reader) (ephemeralPublicKey *PublicKey[P, B, S], ciphertext []byte, err error) {
	enc, ctx, err := SetupAuthS(suite, receiverPublicKey, senderPrivateKey, info, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not setup sender")
	}

	ct, err := ctx.Seal(plaintext, additionalData)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not seal plaintext")
	}

	return enc, ct, nil
}

// SetupAuthR establishes a context for the receiver that can be used to decrypt.This variant extends the base mechanism by allowing the recipient to authenticate that the sender possessed a given KEM private key.
// https://www.rfc-editor.org/rfc/rfc9180.html#name-authentication-using-an-asy
func SetupAuthR[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPrivatekey *PrivateKey[S], ephemeralPublicKey *PublicKey[P, B, S], senderPublicKey *PublicKey[P, B, S], info []byte) (*ReceiverContext[S], error) {
	receiver, err := NewReceiverContext(Auth, suite, receiverPrivatekey, ephemeralPublicKey, senderPublicKey, info, nil, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to construct receiver context")
	}

	return receiver, nil
}

func OpenAuth[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, additionalData, ciphertext []byte, receiverPrivatekey *PrivateKey[S], ephemeralPublicKey *PublicKey[P, B, S], senderPublicKey *PublicKey[P, B, S], info []byte) (plaintext []byte, err error) {
	ctx, err := SetupAuthR(suite, receiverPrivatekey, senderPublicKey, ephemeralPublicKey, info)
	if err != nil {
		return nil, errs.WrapFailed(err, "Could not construct receiver")
	}

	pt, err := ctx.Open(ciphertext, additionalData)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get plaintext")
	}

	return pt, nil
}

// SetupAuthPSKS establishes a context for the sender that can be used to encrypt. This mode is a straightforward combination of the PSK and authenticated modes. Like the PSK mode, a PSK is provided as input to the key schedule, and like the authenticated mode, authenticated KEM variants are used.
// https://www.rfc-editor.org/rfc/rfc9180.html#name-authentication-using-both-a
func SetupAuthPSKS[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPublicKey *PublicKey[P, B, S], senderPrivateKey *PrivateKey[S], psk, pskId, info []byte, prng io.Reader) (enc *PublicKey[P, B, S], sender *SenderContext[S], err error) {
	sender, enc, err = NewSenderContext(AuthPSk, suite, receiverPublicKey, senderPrivateKey, info, psk, pskId, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to construct sender context")
	}

	return enc, sender, nil
}

func SealAuthPSK[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, additionalData, plaintext []byte, receiverPublicKey *PublicKey[P, B, S], senderPrivateKey *PrivateKey[S], psk, pskId, info []byte, prng io.Reader) (ephemeralPublicKey *PublicKey[P, B, S], ciphertext []byte, err error) {
	enc, ctx, err := SetupAuthPSKS(suite, receiverPublicKey, senderPrivateKey, psk, pskId, info, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not setup sender")
	}

	ct, err := ctx.Seal(plaintext, additionalData)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not seal plaintext")
	}

	return enc, ct, nil
}

// SetupAuthPSKR establishes a context for the receiver that can be used to decrypt. This mode is a straightforward combination of the PSK and authenticated modes. Like the PSK mode, a PSK is provided as input to the key schedule, and like the authenticated mode, authenticated KEM variants are used.
// https://www.rfc-editor.org/rfc/rfc9180.html#name-authentication-using-both-a
func SetupAuthPSKR[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPrivatekey *PrivateKey[S], ephemeralPublicKey *PublicKey[P, B, S], senderPublicKey *PublicKey[P, B, S], psk, pskId, info []byte) (*ReceiverContext[S], error) {
	receiver, err := NewReceiverContext(AuthPSk, suite, receiverPrivatekey, ephemeralPublicKey, senderPublicKey, info, psk, pskId)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to construct receiver context")
	}

	return receiver, nil
}

func OpenAuthPSK[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, additionalData, ciphertext []byte, receiverPrivatekey *PrivateKey[S], ephemeralPublicKey *PublicKey[P, B, S], senderPublicKey *PublicKey[P, B, S], psk, pskId, info []byte) (plaintext []byte, err error) {
	ctx, err := SetupAuthPSKR(suite, receiverPrivatekey, senderPublicKey, ephemeralPublicKey, psk, pskId, info)
	if err != nil {
		return nil, errs.WrapFailed(err, "Could not construct receiver")
	}

	pt, err := ctx.Open(ciphertext, additionalData)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get plaintext")
	}

	return pt, nil
}
