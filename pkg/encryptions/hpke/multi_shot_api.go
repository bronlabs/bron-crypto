package hpke

import (
	"io"

	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

type Sender struct {
	myPrivateKey *PrivateKey
	c            *context

	_ ds.Incomparable
}

func NewSender(mode ModeID, suite *CipherSuite, receiverPublicKey PublicKey, senderPrivateKey *PrivateKey, info, psk, pskId []byte, prng io.Reader) (*Sender, PublicKey, error) {
	if suite == nil {
		return nil, nil, errs.NewIsNil("ciphersuite is nil")
	}

	kem, exists := kems[suite.KEM]
	if !exists {
		return nil, nil, errs.NewType("no kem constructor found for %v", suite.KEM)
	}

	var sharedSecret []byte
	var enc PublicKey
	var err error
	if mode == Auth || mode == AuthPSk {
		sharedSecret, enc, err = kem.AuthEncap(receiverPublicKey, senderPrivateKey, prng)
	} else {
		if senderPrivateKey != nil {
			return nil, nil, errs.NewFailed("sender private key unsupported")
		}

		sharedSecret, enc, err = kem.Encap(receiverPublicKey, prng)
	}
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not finish kem.Encap")
	}

	ctx, _, err := keySchedule(SenderRole, suite, mode, sharedSecret, info, psk, pskId)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "key scheduling failed")
	}

	return &Sender{
		myPrivateKey: senderPrivateKey,
		c:            ctx,
	}, enc, nil
}

func (s *Sender) Seal(plaintext, additionalData []byte) (ciphertext []byte, err error) {
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
func (s *Sender) Export(exporterContext []byte, L int) ([]byte, error) {
	return s.c.export(exporterContext, L)
}

type Receiver struct {
	myPrivateKey *PrivateKey
	c            *context

	_ ds.Incomparable
}

func NewReceiver(mode ModeID, suite *CipherSuite, receiverPrivatekey *PrivateKey, ephemeralPublicKey, senderPublicKey PublicKey, info, psk, pskId []byte) (*Receiver, error) {
	if suite == nil {
		return nil, errs.NewIsNil("ciphersuite is nil")
	}

	kem, exists := kems[suite.KEM]
	if !exists {
		return nil, errs.NewType("no kem constructor found for %v", suite.KEM)
	}

	var sharedSecret []byte
	var err error
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

	return &Receiver{
		myPrivateKey: receiverPrivatekey,
		c:            ctx,
	}, nil
}

func (r *Receiver) Open(ciphertext, additionalData []byte) (plaintext []byte, err error) {
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
func (r *Receiver) Export(exporterContext []byte, L int) ([]byte, error) {
	return r.c.export(exporterContext, L)
}
