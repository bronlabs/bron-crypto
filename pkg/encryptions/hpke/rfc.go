package hpke

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

// These are the actual APIs defined in the RFC.

type SenderContext = Sender
type ReceiverContext = Receiver

// SetupBaseS establishes a context for the sender that can be used to encrypt.
// https://www.rfc-editor.org/rfc/rfc9180.html#name-encryption-to-a-public-key
func SetupBaseS(suite *CipherSuite, receiverPublicKey PublicKey, info []byte, prng io.Reader) (PublicKey, *SenderContext, error) {
	sender, enc, err := NewSender(Base, suite, receiverPublicKey, nil, info, nil, nil, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to construct sender context")
	}
	return enc, sender, nil
}

func SealBase(suite *CipherSuite, additionalData, plaintext []byte, receiverPublicKey PublicKey, info []byte, prng io.Reader) (ephemeralPublicKey PublicKey, ciphertext []byte, err error) {
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
func SetupBaseR(suite *CipherSuite, receiverPrivatekey *PrivateKey, ephemeralPublicKey PublicKey, info []byte) (*ReceiverContext, error) {
	receiver, err := NewReceiver(Base, suite, receiverPrivatekey, ephemeralPublicKey, nil, info, nil, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to construct receiver context")
	}
	return receiver, nil
}

func OpenBase(suite *CipherSuite, additionalData, ciphertext []byte, receiverPrivatekey *PrivateKey, ephemeralPublicKey PublicKey, info []byte) (plaintext []byte, err error) {
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
func SetupPSKS(suite *CipherSuite, receiverPublicKey PublicKey, psk, pskId, info []byte, prng io.Reader) (PublicKey, *SenderContext, error) {
	sender, enc, err := NewSender(PSk, suite, receiverPublicKey, nil, info, psk, pskId, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to construct sender context")
	}
	return enc, sender, nil
}

func SealPSK(suite *CipherSuite, additionalData, plaintext []byte, receiverPublicKey PublicKey, psk, pskId, info []byte, prng io.Reader) (ephemeralPublicKey PublicKey, ciphertext []byte, err error) {
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
func SetupPSKR(suite *CipherSuite, receiverPrivatekey *PrivateKey, ephemeralPublicKey PublicKey, psk, pskId, info []byte) (*ReceiverContext, error) {
	receiver, err := NewReceiver(PSk, suite, receiverPrivatekey, ephemeralPublicKey, nil, info, psk, pskId)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to construct receiver context")
	}
	return receiver, nil
}

func OpenPSK(suite *CipherSuite, additionalData, ciphertext []byte, receiverPrivatekey *PrivateKey, ephemeralPublicKey PublicKey, psk, pskId, info []byte) (plaintext []byte, err error) {
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
func SetupAuthS(suite *CipherSuite, receiverPublicKey PublicKey, senderPrivateKey *PrivateKey, info []byte, prng io.Reader) (PublicKey, *SenderContext, error) {
	sender, enc, err := NewSender(Auth, suite, receiverPublicKey, senderPrivateKey, info, nil, nil, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to construct sender context")
	}
	return enc, sender, nil
}

func SealAuth(suite *CipherSuite, additionalData, plaintext []byte, receiverPublicKey PublicKey, senderPrivateKey *PrivateKey, info []byte, prng io.Reader) (ephemeralPublicKey PublicKey, ciphertext []byte, err error) {
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
func SetupAuthR(suite *CipherSuite, receiverPrivatekey *PrivateKey, ephemeralPublicKey, senderPublicKey PublicKey, info []byte) (*ReceiverContext, error) {
	receiver, err := NewReceiver(Auth, suite, receiverPrivatekey, ephemeralPublicKey, senderPublicKey, info, nil, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to construct receiver context")
	}
	return receiver, nil
}

func OpenAuth(suite *CipherSuite, additionalData, ciphertext []byte, receiverPrivatekey *PrivateKey, ephemeralPublicKey, senderPublicKey PublicKey, info []byte) (plaintext []byte, err error) {
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
func SetupAuthPSKS(suite *CipherSuite, receiverPublicKey PublicKey, senderPrivateKey *PrivateKey, psk, pskId, info []byte, prng io.Reader) (PublicKey, *SenderContext, error) {
	sender, enc, err := NewSender(AuthPSk, suite, receiverPublicKey, senderPrivateKey, info, psk, pskId, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to construct sender context")
	}
	return enc, sender, nil
}

func SealAuthPSK(suite *CipherSuite, additionalData, plaintext []byte, receiverPublicKey PublicKey, senderPrivateKey *PrivateKey, psk, pskId, info []byte, prng io.Reader) (ephemeralPublicKey PublicKey, ciphertext []byte, err error) {
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
func SetupAuthPSKR(suite *CipherSuite, receiverPrivatekey *PrivateKey, ephemeralPublicKey, senderPublicKey PublicKey, psk, pskId, info []byte) (*ReceiverContext, error) {
	receiver, err := NewReceiver(AuthPSk, suite, receiverPrivatekey, ephemeralPublicKey, senderPublicKey, info, psk, pskId)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to construct receiver context")
	}
	return receiver, nil
}

func OpenAuthPSK(suite *CipherSuite, additionalData, ciphertext []byte, receiverPrivatekey *PrivateKey, ephemeralPublicKey, senderPublicKey PublicKey, psk, pskId, info []byte) (plaintext []byte, err error) {
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
