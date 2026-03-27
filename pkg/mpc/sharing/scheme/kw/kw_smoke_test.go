package kw_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
)

func _[FE algebra.PrimeFieldElement[FE]]() {
	var (
		_ sharing.DealerOutput[*kw.Share[FE]]      = (*kw.DealerOutput[FE])(nil)
		_ sharing.LinearShare[*kw.Share[FE], []FE] = (*kw.Share[FE])(nil)

		_ sharing.LSSS[*kw.Share[FE], []FE, *kw.Secret[FE], FE, *kw.DealerOutput[FE], *kw.DealerFunc[FE]] = (*kw.Scheme[FE])(nil)
	)
}
