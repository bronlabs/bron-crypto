package hpke

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/encryption/hpke/internal"
)

// func Seal[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *SenderContext, plaintext, aad []byte) (ephemeralPublicKey *PublicKey[P, B, S], ciphertext []byte, err error) {
// 	ct, err := ctx.Seal(plaintext, aad)
// 	if err != nil {
// 		return nil, nil, errs.WrapFailed(err, "could not seal plaintext")
// 	}

// 	return ctx.enc, ct, nil
// }

// func Open[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *ReceiverContext, additionalData, ciphertext []byte) (plaintext []byte, err error) {
// 	pt, err := ctx.Open(ciphertext, additionalData)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "could not get plaintext")
// 	}

// 	return pt, nil
// }

// These are the actual APIs defined in the RFC.

// SetupBaseS establishes a context for the sender that can be used to encrypt.
// https://www.rfc-editor.org/rfc/rfc9180.html#name-encryption-to-a-public-key
func SetupBaseS[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPublicKey *PublicKey[P, B, S], info []byte, prng io.Reader) (sender *SenderContext[P, B, S], err error) {
	sender, err = internal.NewSenderContext(Base, suite, receiverPublicKey, nil, info, nil, nil, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to construct sender context")
	}

	return sender, nil
}

// SetupBaseR establishes a context for the receiver that can be used to decrypt
// https://www.rfc-editor.org/rfc/rfc9180.html#name-encryption-to-a-public-key
func SetupBaseR[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPrivatekey *PrivateKey[S], ephemeralPublicKey *PublicKey[P, B, S], info []byte) (*ReceiverContext, error) {
	receiver, err := internal.NewReceiverContext(Base, suite, receiverPrivatekey, ephemeralPublicKey, nil, info, nil, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to construct receiver context")
	}

	return receiver, nil
}

// SetupPSKS establishes a context for the sender that can be used to encrypt. This variant extends the base mechanism by allowing the recipient to authenticate that the sender possessed a given PSK. We assume that both parties have been provisioned with both the PSK value psk and another byte string psk_id that is used to identify which PSK should be used.
// https://www.rfc-editor.org/rfc/rfc9180.html#name-authentication-using-a-pre-
func SetupPSKS[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPublicKey *PublicKey[P, B, S], psk, pskId, info []byte, prng io.Reader) (sender *SenderContext[P, B, S], err error) {
	sender, err = internal.NewSenderContext(PSk, suite, receiverPublicKey, nil, info, psk, pskId, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to construct sender context")
	}

	return sender, nil
}

func SealPSK[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *SenderContext[P, B, S], additionalData, plaintext []byte) (ciphertext []byte, err error) {
	ct, err := ctx.Seal(plaintext, additionalData)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not seal plaintext")
	}

	return ct, nil
}

// SetupPSKR establishes a context for the receiver that can be used to decrypt. This variant extends the base mechanism by allowing the recipient to authenticate that the sender possessed a given PSK. We assume that both parties have been provisioned with both the PSK value psk and another byte string psk_id that is used to identify which PSK should be used.
// https://www.rfc-editor.org/rfc/rfc9180.html#name-authentication-using-a-pre-
func SetupPSKR[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPrivatekey *PrivateKey[S], ephemeralPublicKey *PublicKey[P, B, S], psk, pskId, info []byte) (*ReceiverContext, error) {
	receiver, err := internal.NewReceiverContext(PSk, suite, receiverPrivatekey, ephemeralPublicKey, nil, info, psk, pskId)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to construct receiver context")
	}

	return receiver, nil
}

// SetupAuthS establishes a context for the sender that can be used to encrypt.This variant extends the base mechanism by allowing the recipient to authenticate that the sender possessed a given KEM private key.
// https://www.rfc-editor.org/rfc/rfc9180.html#name-authentication-using-an-asy
func SetupAuthS[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPublicKey *PublicKey[P, B, S], senderPrivateKey *PrivateKey[S], info []byte, prng io.Reader) (sender *SenderContext[P, B, S], err error) {
	sender, err = internal.NewSenderContext(Auth, suite, receiverPublicKey, senderPrivateKey, info, nil, nil, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to construct sender context")
	}

	return sender, nil
}

// SetupAuthR establishes a context for the receiver that can be used to decrypt.This variant extends the base mechanism by allowing the recipient to authenticate that the sender possessed a given KEM private key.
// https://www.rfc-editor.org/rfc/rfc9180.html#name-authentication-using-an-asy
func SetupAuthR[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPrivatekey *PrivateKey[S], ephemeralPublicKey *PublicKey[P, B, S], senderPublicKey *PublicKey[P, B, S], info []byte) (*ReceiverContext, error) {
	receiver, err := internal.NewReceiverContext(Auth, suite, receiverPrivatekey, ephemeralPublicKey, senderPublicKey, info, nil, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to construct receiver context")
	}

	return receiver, nil
}

// SetupAuthPSKS establishes a context for the sender that can be used to encrypt. This mode is a straightforward combination of the PSK and authenticated modes. Like the PSK mode, a PSK is provided as input to the key schedule, and like the authenticated mode, authenticated KEM variants are used.
// https://www.rfc-editor.org/rfc/rfc9180.html#name-authentication-using-both-a
func SetupAuthPSKS[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPublicKey *PublicKey[P, B, S], senderPrivateKey *PrivateKey[S], psk, pskId, info []byte, prng io.Reader) (sender *SenderContext[P, B, S], err error) {
	sender, err = internal.NewSenderContext(AuthPSk, suite, receiverPublicKey, senderPrivateKey, info, psk, pskId, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to construct sender context")
	}

	return sender, nil
}

// SetupAuthPSKR establishes a context for the receiver that can be used to decrypt. This mode is a straightforward combination of the PSK and authenticated modes. Like the PSK mode, a PSK is provided as input to the key schedule, and like the authenticated mode, authenticated KEM variants are used.
// https://www.rfc-editor.org/rfc/rfc9180.html#name-authentication-using-both-a
func SetupAuthPSKR[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPrivatekey *PrivateKey[S], ephemeralPublicKey *PublicKey[P, B, S], senderPublicKey *PublicKey[P, B, S], psk, pskId, info []byte) (*ReceiverContext, error) {
	receiver, err := internal.NewReceiverContext(AuthPSk, suite, receiverPrivatekey, ephemeralPublicKey, senderPublicKey, info, psk, pskId)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to construct receiver context")
	}

	return receiver, nil
}
