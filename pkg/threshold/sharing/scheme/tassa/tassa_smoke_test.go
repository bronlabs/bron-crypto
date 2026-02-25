package tassa_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/tassa"
)

func _[FE algebra.PrimeFieldElement[FE]]() {
	var (
		_ sharing.DealerOutput[*tassa.Share[FE]]        = (*tassa.DealerOutput[FE])(nil)
		_ sharing.LinearShare[*tassa.Share[FE], FE, FE] = (*tassa.Share[FE])(nil)
		_ sharing.PolynomialLSSS[
			*tassa.Share[FE], FE, *tassa.Secret[FE], FE, *tassa.DealerOutput[FE], FE,
			*accessstructures.HierarchicalConjunctiveThreshold,
		] = (*tassa.Scheme[FE])(nil)
	)
}
