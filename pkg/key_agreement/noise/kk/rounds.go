package kk

import (
	"bytes"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/key_agreement/noise"
)

func (p *Participant) Round1(input *noise.P2PMessage) (*noise.P2PMessage, error) {
	if p.State.Round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", p.State.Round)
	}
	var messageBuffer = input
	var err error
	if p.State.IsInitiator {
		// steps 3.1.x
		messageBuffer, err = p.writeHandshake1(&p.State.Hs, p.HandshakeMessage1)
	} else {
		var plaintext []byte
		// steps 3.2.x
		plaintext, err = p.readHandshake1(&p.State.Hs, messageBuffer)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not complete round 1")
		}
		if !bytes.Equal(plaintext, p.HandshakeMessage1) {
			return nil, errs.NewInvalidArgument("handshake message mismatch")
		}
		// step 3.3.x
		p.State.H, messageBuffer, p.State.Cs1, p.State.Cs2, err = p.writeHandshake2(&p.State.Hs, p.HandshakeMessage2)
		p.State.Hs = noise.HandshakeState{}
	}
	if err != nil {
		return nil, errs.WrapFailed(err, "could not complete round 1")
	}
	p.State.Round++
	return messageBuffer, err
}

func (p *Participant) Round2(input *noise.P2PMessage) (*noise.P2PMessage, error) {
	if p.State.Round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", p.State.Round)
	}
	var messageBuffer = input
	if !p.State.IsInitiator {
		return nil, errs.NewInvalidArgument("responder cannot initiate round 2")
	}
	var plaintext []byte
	var err error
	p.State.H, plaintext, p.State.Cs1, p.State.Cs2, err = p.readHandshake2(&p.State.Hs, input)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not complete round 2")
	}
	if !bytes.Equal(plaintext, p.HandshakeMessage2) {
		return nil, errs.NewInvalidArgument("handshake message mismatch")
	}
	p.State.Hs = noise.HandshakeState{}
	p.State.Round++
	return messageBuffer, nil
}

func (p *Participant) writeHandshake1(hs *noise.HandshakeState, payload []byte) (messageBuffer *noise.P2PMessage, err error) {
	if hs.EphemeralKey.PrivateKey == nil {
		hs.EphemeralKey = noise.NewSigner(p.prng, p.suite.Curve, nil)
	}
	ne := hs.EphemeralKey.PublicKey
	// step 3.1.1
	err = hs.Ss.MixHash(p.suite.GetHashFunc(), ne.ToAffineCompressed())
	if err != nil {
		return messageBuffer, errs.WrapFailed(err, "could not mix hash")
	}
	// step 3.1.2
	hs.Ss.MixKey(p.suite.GetHashFunc(), noise.Dh(p.suite.Curve, hs.EphemeralKey.PrivateKey, hs.OtherPartyStaticPk).Bytes())
	hs.Ss.MixKey(p.suite.GetHashFunc(), noise.Dh(p.suite.Curve, hs.StaticKey.PrivateKey, hs.OtherPartyStaticPk).Bytes())
	// step 3.1.3
	ciphertext, err := noise.EncryptAndHash(p.suite.Curve, p.suite.GetHashFunc(), p.suite.GetAeadFunc(), &hs.Ss, payload)
	if err != nil {
		return messageBuffer, errs.WrapFailed(err, "could not encrypt round 1 message")
	}
	messageBuffer = &noise.P2PMessage{Ne: ne, Ciphertext: ciphertext}
	return messageBuffer, nil
}

func (p *Participant) writeHandshake2(hs *noise.HandshakeState, payload []byte) (H [32]byte, messageBuffer *noise.P2PMessage, cs1, cs2 noise.CipherState, err error) {
	if hs.EphemeralKey.PrivateKey == nil {
		hs.EphemeralKey = noise.NewSigner(p.prng, p.suite.Curve, nil)
	}
	ne := hs.EphemeralKey.PublicKey
	// step 3.3.1
	err = hs.Ss.MixHash(p.suite.GetHashFunc(), ne.ToAffineCompressed())
	if err != nil {
		return hs.Ss.H, messageBuffer, cs1, cs2, errs.WrapFailed(err, "could not mix hash")
	}
	// step 3.3.2
	hs.Ss.MixKey(p.suite.GetHashFunc(), noise.Dh(p.suite.Curve, hs.EphemeralKey.PrivateKey, hs.OtherPartyEphemeralPk).Bytes())
	hs.Ss.MixKey(p.suite.GetHashFunc(), noise.Dh(p.suite.Curve, hs.EphemeralKey.PrivateKey, hs.OtherPartyStaticPk).Bytes())
	// step 3.3.3
	cs1, cs2 = noise.Split(p.suite.GetHashFunc(), &hs.Ss)
	// step 3.3.4
	ciphertext, err := noise.EncryptAndHash(p.suite.Curve, p.suite.GetHashFunc(), p.suite.GetAeadFunc(), &hs.Ss, payload)
	if err != nil {
		return hs.Ss.H, messageBuffer, cs1, cs2, errs.WrapFailed(err, "could not encrypt round 2 message")
	}
	messageBuffer = &noise.P2PMessage{Ne: ne, Ciphertext: ciphertext}
	return hs.Ss.H, messageBuffer, cs1, cs2, nil
}

func (p *Participant) readHandshake1(hs *noise.HandshakeState, message *noise.P2PMessage) (plaintext []byte, err error) {
	hs.OtherPartyEphemeralPk = message.Ne
	// step 3.2.1
	err = hs.Ss.MixHash(p.suite.GetHashFunc(), hs.OtherPartyEphemeralPk.ToAffineCompressed())
	if err != nil {
		return []byte{}, errs.WrapFailed(err, "could not mix hash")
	}
	// step 3.2.2
	hs.Ss.MixKey(p.suite.GetHashFunc(), noise.Dh(p.suite.Curve, hs.StaticKey.PrivateKey, hs.OtherPartyEphemeralPk).Bytes())
	hs.Ss.MixKey(p.suite.GetHashFunc(), noise.Dh(p.suite.Curve, hs.StaticKey.PrivateKey, hs.OtherPartyStaticPk).Bytes())
	// step 3.2.3
	plaintext, valid, err := noise.DecryptAndHash(p.suite.Curve, p.suite.GetHashFunc(), p.suite.GetAeadFunc(), &hs.Ss, message.Ciphertext)
	if err != nil {
		return []byte{}, errs.WrapFailed(err, "could not decrypt round 1 message")
	}
	if !valid {
		return []byte{}, errs.NewInvalidArgument("message invalid")
	}
	return plaintext, nil
}

func (p *Participant) readHandshake2(hs *noise.HandshakeState, message *noise.P2PMessage) (H [32]byte, plaintext []byte, cs1, cs2 noise.CipherState, err error) {
	hs.OtherPartyEphemeralPk = message.Ne
	// step 3.3.1
	err = hs.Ss.MixHash(p.suite.GetHashFunc(), hs.OtherPartyEphemeralPk.ToAffineCompressed())
	if err != nil {
		return hs.Ss.H, plaintext, cs1, cs2, errs.WrapFailed(err, "could not mix hash")
	}
	// step 3.3.2
	hs.Ss.MixKey(p.suite.GetHashFunc(), noise.Dh(p.suite.Curve, hs.EphemeralKey.PrivateKey, hs.OtherPartyEphemeralPk).Bytes())
	hs.Ss.MixKey(p.suite.GetHashFunc(), noise.Dh(p.suite.Curve, hs.StaticKey.PrivateKey, hs.OtherPartyEphemeralPk).Bytes())
	// step 3.3.3
	cs1, cs2 = noise.Split(p.suite.GetHashFunc(), &hs.Ss)
	// step 4.3.4
	plaintext, valid, err := noise.DecryptAndHash(p.suite.Curve, p.suite.GetHashFunc(), p.suite.GetAeadFunc(), &hs.Ss, message.Ciphertext)
	if err != nil {
		return hs.Ss.H, plaintext, cs1, cs2, errs.WrapFailed(err, "could not decrypt round 2 message")
	}
	if !valid {
		return hs.Ss.H, plaintext, cs1, cs2, errs.NewInvalidArgument("message invalid")
	}
	return hs.Ss.H, plaintext, cs1, cs2, nil
}
