package dkls23_bbot

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
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

func (*Round3P2P) Validate(protocol types.Protocol) error {
	return nil
}
