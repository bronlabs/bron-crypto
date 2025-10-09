package rvole_bbot

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
)

type Round1P2P[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]] = ecbbot.Round1P2P[GE, SE]

type Round2P2P[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]] = ecbbot.Round2P2P[GE, SE]

type Round3P2P[SE algebra.PrimeFieldElement[SE]] struct {
	ATilde [][]SE `cbor:"aTilde"`
	Eta    []SE   `cbor:"eta"`
	Mu     []byte `cbor:"mu"`
}

//func (m *Round3P2P) Validate(protocol types.Protocol) error {
//	if m == nil {
//		return errs.NewValidation("missing message")
//	}
//
//	mulProt, ok := protocol.(*mulProtocol)
//	if !ok {
//		return errs.NewValidation("invalid protocol")
//	}
//
//	if len(m.ATilde) != mulProt.Xi {
//		return errs.NewValidation("invalid message")
//	}
//	for _, a := range m.ATilde {
//		if len(a) != (mulProt.L + mulProt.Rho) {
//			return errs.NewValidation("invalid message")
//		}
//		for _, aa := range a {
//			if aa == nil || aa.IsAdditiveIdentity() {
//				return errs.NewValidation("invalid message")
//			}
//		}
//	}
//
//	if len(m.Eta) != mulProt.Rho {
//		return errs.NewValidation("invalid message")
//	}
//	for _, e := range m.Eta {
//		if e == nil || e.IsAdditiveIdentity() {
//			return errs.NewValidation("invalid message")
//		}
//	}
//
//	if len(m.Mu) != (utils.CeilDiv(2*base.ComputationalSecurity, 8)) {
//		return errs.NewValidation("invalid message")
//	}
//
//	return nil
//}
