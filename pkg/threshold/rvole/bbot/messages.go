package rvole_bbot

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
)

// Round1P2P carries round 1 peer-to-peer messages.
type Round1P2P[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]] = ecbbot.Round1P2P[GE, SE]

// Round2P2P carries round 2 peer-to-peer messages.
type Round2P2P[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]] = ecbbot.Round2P2P[GE, SE]

// Round3P2P carries round 3 peer-to-peer messages.
type Round3P2P[SE algebra.PrimeFieldElement[SE]] struct {
	ATilde [][]SE `cbor:"aTilde"`
	Eta    []SE   `cbor:"eta"`
	Mu     []byte `cbor:"mu"`
}

// func (m *Round3P2P) Validate(protocol types.Protocol) error {
//	if m == nil {
//		return ErrValidation.WithMessage("missing message")
//	}
//
//	mulProt, ok := protocol.(*mulProtocol)
//	if !ok {
//		return ErrValidation.WithMessage("invalid protocol")
//	}
//
//	if len(m.ATilde) != mulProt.Xi {
//		return ErrValidation.WithMessage("invalid message")
//	}
//	for _, a := range m.ATilde {
//		if len(a) != (mulProt.L + mulProt.Rho) {
//			return ErrValidation.WithMessage("invalid message")
//		}
//		for _, aa := range a {
//			if aa == nil || aa.IsAdditiveIdentity() {
//				return ErrValidation.WithMessage("invalid message")
//			}
//		}
//	}
//
//	if len(m.Eta) != mulProt.Rho {
//		return ErrValidation.WithMessage("invalid message")
//	}
//	for _, e := range m.Eta {
//		if e == nil || e.IsAdditiveIdentity() {
//			return ErrValidation.WithMessage("invalid message")
//		}
//	}
//
//	if len(m.Mu) != (utils.CeilDiv(2*base.ComputationalSecurity, 8)) {
//		return ErrValidation.WithMessage("invalid message")
//	}
//
//	return nil
// }.
