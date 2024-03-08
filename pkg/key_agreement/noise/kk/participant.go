package kk

import (
	"bytes"
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/key_agreement/noise"
)

type Participant struct {
	State *noise.EncryptionContext
	suite *noise.Suite
	// both parties must agree HandshakeMessages. Use a hash of the protocol name or sorted party public keys
	HandshakeMessage1 []byte
	HandshakeMessage2 []byte
	prng              io.Reader
}

func NewInitiator(suite *noise.Suite, prng io.Reader, sessionId []byte, s noise.Signer, rs curves.Point, handshakeMessage1, handshakeMessage2 []byte) (*Participant, error) {
	return newParticipant(suite, prng, sessionId, s, rs, handshakeMessage1, handshakeMessage2, true)
}

func NewResponder(suite *noise.Suite, prng io.Reader, sessionId []byte, s noise.Signer, rs curves.Point, handshakeMessage1, handshakeMessage2 []byte) (*Participant, error) {
	return newParticipant(suite, prng, sessionId, s, rs, handshakeMessage1, handshakeMessage2, false)
}

func newParticipant(suite *noise.Suite, prng io.Reader, sessionId []byte, s noise.Signer, rs curves.Point, handshakeMessage1, handshakeMessage2 []byte, isInitializer bool) (*Participant, error) {
	err := validate(suite, prng, sessionId, s, rs, handshakeMessage1, handshakeMessage2)
	if err != nil {
		if isInitializer {
			return nil, errs.WrapArgument(err, "invalid initializer")
		} else {
			return nil, errs.WrapArgument(err, "invalid responder")
		}
	}
	var session noise.EncryptionContext
	if isInitializer {
		session.Hs, err = noise.InitializeInitiator(suite.Curve, suite.GetHashFunc(), fmt.Sprintf("Noise_KK_%s_%s_%s", noise.MapToNoiseCurve(suite.Curve), suite.Aead, suite.Hash), sessionId, s, rs)
	} else {
		session.Hs, err = noise.InitializeResponder(suite.Curve, suite.GetHashFunc(), fmt.Sprintf("Noise_KK_%s_%s_%s", noise.MapToNoiseCurve(suite.Curve), suite.Aead, suite.Hash), sessionId, s, rs)
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
		State:             &session,
		HandshakeMessage1: handshakeMessage1,
		HandshakeMessage2: handshakeMessage2,
		suite:             suite,
		prng:              prng,
	}, nil
}

func validate(suite *noise.Suite, prng io.Reader, sessionId []byte, s noise.Signer, rs curves.Point, handshakeMessage1, handshakeMessage2 []byte) error {
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
	if s.PublicKey == nil {
		return errs.NewIsNil("s.PublicKey is nil")
	}
	if s.PrivateKey == nil {
		return errs.NewIsNil("s.PrivateKey is nil")
	}
	if rs == nil {
		return errs.NewIsNil("rs is nil")
	}
	if len(handshakeMessage1) == 0 {
		return errs.NewIsNil("message is empty")
	}
	if len(handshakeMessage2) == 0 {
		return errs.NewIsNil("message is empty")
	}
	if bytes.Equal(handshakeMessage1, handshakeMessage2) {
		return errs.NewType("handshake message in each round must be different")
	}
	if !curveutils.AllOfSameCurve(rs.Curve().Point().Curve(), rs, s.PublicKey, s.PrivateKey) {
		return errs.NewCurve("participants have different curves")
	}
	return nil
}
