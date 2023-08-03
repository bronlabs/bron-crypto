package tecdsa

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/dkls23"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17"
)

type Shard struct {
	Main   *dkls23.Shard
	Backup *lindell17.Shard
}

func (s *Shard) SigningKeyShare() *dkls23.SigningKeyShare {
	return s.Main.SigningKeyShare
}
