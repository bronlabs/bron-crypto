package dkls23_bbot

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
)

var (
	_ network.Message[types.Protocol] = (*Round1P2P)(nil)
	_ network.Message[types.Protocol] = (*Round2P2P)(nil)
	_ network.Message[types.Protocol] = (*Round3P2P)(nil)
)

type Round1P2P = ecbbot.Round1P2P

type Round2P2P = ecbbot.Round2P2P

type Round3P2P struct {
	ATilde [][]curves.Scalar
	Eta    []curves.Scalar
	Mu     []byte
}

func (m *Round3P2P) Validate(protocol types.Protocol) error {
	if m == nil {
		return errs.NewValidation("missing message")
	}

	mulProt, ok := protocol.(*mulProtocol)
	if !ok {
		return errs.NewValidation("invalid protocol")
	}

	if len(m.ATilde) != mulProt.Xi {
		return errs.NewValidation("invalid message")
	}
	for _, a := range m.ATilde {
		if len(a) != (mulProt.L + mulProt.Rho) {
			return errs.NewValidation("invalid message")
		}
		for _, aa := range a {
			if aa == nil || aa.IsAdditiveIdentity() {
				return errs.NewValidation("invalid message")
			}
		}
	}

	if len(m.Eta) != mulProt.Rho {
		return errs.NewValidation("invalid message")
	}
	for _, e := range m.Eta {
		if e == nil || e.IsAdditiveIdentity() {
			return errs.NewValidation("invalid message")
		}
	}

	if len(m.Mu) != (utils.CeilDiv(2*base.ComputationalSecurity, 8)) {
		return errs.NewValidation("invalid message")
	}

	return nil
}
