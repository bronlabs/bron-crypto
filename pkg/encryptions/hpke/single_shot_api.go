package hpke

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

func Seal(mode ModeID, suite *CipherSuite, plaintext, additionalData []byte, receiverPublicKey PublicKey, senderPrivateKey *PrivateKey, info, psk, pskId []byte, prng io.Reader) (ciphertext []byte, ephemeralPublicKey PublicKey, err error) {
	sender, ephemeralPublicKey, err := NewSender(mode, suite, receiverPublicKey, senderPrivateKey, info, psk, pskId, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not construct sender")
	}

	ciphertext, err = sender.Seal(plaintext, additionalData)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not seal plaintext")
	}

	return ciphertext, ephemeralPublicKey, nil
}

func Open(mode ModeID, suite *CipherSuite, ciphertext, additionalData []byte, receiverPrivatekey *PrivateKey, ephemeralPublicKey, senderPublicKey PublicKey, info, psk, pskId []byte) (plaintext []byte, err error) {
	receiver, err := NewReceiver(mode, suite, receiverPrivatekey, ephemeralPublicKey, senderPublicKey, info, psk, pskId)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct receiver")
	}

	plaintext, err = receiver.Open(ciphertext, additionalData)
	if err != nil {
		return nil, errs.WrapFailed(err, "opening failed")
	}

	return plaintext, nil
}
