package paillier

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/num"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/castagnos08"
)

const Type encryption.Type = "paillier"

var (
	_ castagnos08.G[*GElement, *ZkElement]        = (*G)(nil)
	_ castagnos08.GElement[*GElement, *ZkElement] = (*GElement)(nil)

	_ castagnos08.Zk[*ZkElement]        = (*Zk)(nil)
	_ castagnos08.ZkElement[*ZkElement] = (*ZkElement)(nil)

	_ castagnos08.GQuotient[*GQuotientElement]        = (*GQuotient)(nil)
	_ castagnos08.GQuotientElement[*GQuotientElement] = (*GQuotientElement)(nil)
)

type G struct {
	num.Unit[*num.Uint]
}

func (g *G) Dlog(x *GElement) (*ZkElement, error) {
}

type GElement struct {
	num.PlainUnit
}

type Zk = num.Zn

type ZkElement = num.Uint

type GQuotient struct{}

type GQuotientElement struct{}
