package noise

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type EncryptionContext struct {
	Suite *Suite
	// handshake state
	Hs HandshakeState
	// hash output of the handshake
	H [32]byte
	// cs1 and cs2 are used to encrypt and decrypt messages
	Cs1 CipherState
	Cs2 CipherState
	// round number
	Round uint64
	// flag to indicate if this is the initializer or the responder
	IsInitiator bool
}

func (s *EncryptionContext) Encrypt(payload []byte) (P2PMessage, error) {
	err := s.Suite.Validate()
	if err != nil {
		return P2PMessage{}, errs.WrapType(err, "invalid ciphersuite")
	}
	var csx *CipherState
	if s.IsInitiator {
		csx = &s.Cs1
	} else {
		csx = &s.Cs2
	}
	p2pMessage, err := writeMessageRegular(s.Suite.Curve, s.Suite.GetAeadFunc(), csx, payload)
	if err != nil {
		return P2PMessage{}, errs.WrapFailed(err, "failed to encrypt message")
	}
	return p2pMessage, nil
}

func (s *EncryptionContext) Decrypt(message *P2PMessage) (plaintext []byte, valid bool, err error) {
	err = s.Suite.Validate()
	if err != nil {
		return []byte{}, false, errs.WrapType(err, "invalid ciphersuite")
	}
	var csx *CipherState
	if s.IsInitiator {
		csx = &s.Cs2
	} else {
		csx = &s.Cs1
	}
	plaintext, valid, err = readMessageRegular(s.Suite.GetAeadFunc(), csx, message)
	if err != nil {
		return []byte{}, valid, errs.WrapFailed(err, "failed to decrypt message")
	}
	if !valid {
		return []byte{}, false, errs.WrapFailed(err, "invalid message. Maybe message was out of order")
	}
	if plaintext == nil {
		return []byte{}, valid, nil
	}
	return plaintext, valid, nil
}
