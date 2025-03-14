package k

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curveutils"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/noise"
)

type Participant struct {
	State *noise.EncryptionContext
	suite *noise.Suite
	prng  io.Reader
	// both parties must agree on this. I think it's a good idea to use a hash of the protocol name or sorted party public keys
	HandshakeMessage []byte
}

// step 1.1 and 1.2 if initiator.
func NewInitiator(suite *noise.Suite, prng io.Reader, sessionId []byte, s noise.Signer, rs curves.Point, handshakeMessage []byte) (*Participant, error) {
	return newParticipant(suite, prng, sessionId, s, rs, handshakeMessage, true)
}

// step 1.1 and 1.2 if responder.
func NewResponder(suite *noise.Suite, prng io.Reader, sessionId []byte, s noise.Signer, rs curves.Point, handshakeMessage []byte) (*Participant, error) {
	return newParticipant(suite, prng, sessionId, s, rs, handshakeMessage, false)
}

func newParticipant(suite *noise.Suite, prng io.Reader, sessionId []byte, s noise.Signer, rs curves.Point, handshakeMessage []byte, isInitializer bool) (*Participant, error) {
	err := validate(suite, prng, sessionId, s, rs, handshakeMessage)
	if err != nil {
		if isInitializer {
			return nil, errs.WrapArgument(err, "invalid initializer")
		} else {
			return nil, errs.WrapArgument(err, "invalid responder")
		}
	}
	var session noise.EncryptionContext
	if isInitializer {
		session.Hs, err = noise.InitializeInitiator(suite.Curve, suite.GetHashFunc(), fmt.Sprintf("Noise_K_%s_%s_%s", noise.MapToNoiseCurve(suite.Curve), suite.Aead, suite.Hash), sessionId, s, rs)
	} else {
		session.Hs, err = noise.InitializeResponder(suite.Curve, suite.GetHashFunc(), fmt.Sprintf("Noise_K_%s_%s_%s", noise.MapToNoiseCurve(suite.Curve), suite.Aead, suite.Hash), sessionId, s, rs)
	}
	if err != nil {
		if isInitializer {
			return nil, errs.WrapArgument(err, "invalid initializer")
		} else {
			return nil, errs.WrapArgument(err, "invalid responder")
		}
	}
	session.IsInitiator = isInitializer
	session.Round = 1
	session.Suite = suite
	return &Participant{
		State:            &session,
		HandshakeMessage: handshakeMessage,
		suite:            suite,
		prng:             prng,
	}, nil
}

func validate(suite *noise.Suite, prng io.Reader, sessionId []byte, s noise.Signer, rs curves.Point, message []byte) error {
	err := suite.Validate()
	if err != nil {
		return errs.WrapType(err, "invalid ciphersuite")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	if len(sessionId) == 0 {
		return errs.NewIsNil("sessionId is empty")
	}
	if !s.PublicKey.IsInPrimeSubGroup() {
		return errs.NewValidation("Public Key not in the prime subgroup")
	}
	if s.PublicKey == nil {
		return errs.NewIsNil("s.PublicKey is nil")
	}
	if s.PrivateKey == nil {
		return errs.NewIsNil("s.PrivateKey is nil")
	}
	if rs == nil {
		return errs.NewIsNil("rs is nil")
	}
	if len(message) == 0 {
		return errs.NewIsNil("message is empty")
	}
	if !curveutils.AllOfSameCurve(rs.Curve().Point().Curve(), rs, s.PublicKey, s.PrivateKey) {
		return errs.NewCurve("participants have different curves")
	}
	return nil
}
