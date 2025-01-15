package k

import (
	"bytes"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/key_agreement/noise"
)

func (p *Participant) Round1(input *noise.P2PMessage) (*noise.P2PMessage, error) {
	if p.State.Round != 1 {
		return nil, errs.NewRound("round mismatch %d != 1", p.State.Round)
	}
	var messageBuffer *noise.P2PMessage
	var plaintext []byte
	var err error
	if p.State.IsInitiator {
		// step 2.1.x
		p.State.H, messageBuffer, p.State.Cs1, err = p.writeHandshake(&p.State.Hs, p.HandshakeMessage)
		p.State.Hs = noise.HandshakeState{}
	} else {
		// step 2.2.x
		p.State.H, plaintext, p.State.Cs1, err = p.readHandshake(&p.State.Hs, input)
		p.State.Hs = noise.HandshakeState{}
		if !bytes.Equal(plaintext, p.HandshakeMessage) {
			return nil, errs.NewArgument("handshake message mismatch")
		}
	}
	if err != nil {
		return nil, errs.WrapFailed(err, "could not complete round 1")
	}
	p.State.Round++
	return messageBuffer, err
}

func (p *Participant) writeHandshake(hs *noise.HandshakeState, payload []byte) (H [32]byte, messageBuffer *noise.P2PMessage, cs1 noise.CipherState, err error) {
	var ciphertext []byte
	if hs.EphemeralKey.PrivateKey == nil {
		hs.EphemeralKey = noise.NewSigner(p.prng, p.suite.Curve, nil)
	}
	ne := hs.EphemeralKey.PublicKey
	// step 2.1.1
	err = hs.Ss.MixHash(p.suite.GetHashFunc(), ne.ToAffineCompressed())
	if err != nil {
		return hs.Ss.H, messageBuffer, cs1, errs.WrapFailed(err, "could not mix hash")
	}
	// step 2.1.2
	hs.Ss.MixKey(p.suite.GetHashFunc(), noise.Dh(p.suite.Curve, hs.EphemeralKey.PrivateKey, hs.OtherPartyStaticPk).Bytes())
	hs.Ss.MixKey(p.suite.GetHashFunc(), noise.Dh(p.suite.Curve, hs.StaticKey.PrivateKey, hs.OtherPartyStaticPk).Bytes())

	// step 2.1.3
	ciphertext, err = noise.EncryptAndHash(p.suite.Curve, p.suite.GetHashFunc(), p.suite.GetAeadFunc(), &hs.Ss, payload)
	if err != nil {
		return hs.Ss.H, messageBuffer, cs1, errs.WrapFailed(err, "could not encrypt message")
	}
	messageBuffer = &noise.P2PMessage{Ne: ne, Ciphertext: ciphertext}

	// step 2.1.4
	cs1, _ = noise.Split(p.suite.GetHashFunc(), &hs.Ss)
	return hs.Ss.H, messageBuffer, cs1, nil
}

func (p *Participant) readHandshake(hs *noise.HandshakeState, message *noise.P2PMessage) (H [32]byte, plaintext []byte, cs1 noise.CipherState, err error) {
	hs.OtherPartyEphemeralPk = message.Ne
	// step 2.2.1
	err = hs.Ss.MixHash(p.suite.GetHashFunc(), hs.OtherPartyEphemeralPk.ToAffineCompressed())
	if err != nil {
		return hs.Ss.H, []byte{}, cs1, errs.WrapFailed(err, "could not mix hash")
	}
	// step 2.2.2
	hs.Ss.MixKey(p.suite.GetHashFunc(), noise.Dh(p.suite.Curve, hs.StaticKey.PrivateKey, hs.OtherPartyEphemeralPk).Bytes())
	hs.Ss.MixKey(p.suite.GetHashFunc(), noise.Dh(p.suite.Curve, hs.StaticKey.PrivateKey, hs.OtherPartyStaticPk).Bytes())
	// step 2.2.3
	plaintext, valid, err := noise.DecryptAndHash(p.suite.Curve, p.suite.GetHashFunc(), p.suite.GetAeadFunc(), &hs.Ss, message.Ciphertext)
	if err != nil {
		return hs.Ss.H, []byte{}, cs1, errs.WrapFailed(err, "could not decrypt message")
	}
	if !valid {
		return hs.Ss.H, []byte{}, cs1, errs.NewArgument("message invalid")
	}
	// step 2.2.4
	cs1, _ = noise.Split(p.suite.GetHashFunc(), &hs.Ss)
	return hs.Ss.H, plaintext, cs1, nil
}
