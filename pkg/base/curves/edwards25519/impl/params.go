package impl

import (
	"crypto/sha512"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/h2c"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/h2c/mappers/elligator2"
)

var (
	_ h2c.HasherParams     = CurveHasherParams{}
	_ h2c.PointMapper[*Fp] = CurveMapper{}
)

var (
	curveMessageExpander = h2c.NewXMDMessageExpander(sha512.New)
)

type CurveHasherParams struct{}
type CurveMapper = elligator2.Edwards25519PointMapper[*Fp, Fp]

func (CurveHasherParams) L() uint64 {
	return 48
}

func (CurveHasherParams) MessageExpander() h2c.MessageExpander {
	return curveMessageExpander
}
