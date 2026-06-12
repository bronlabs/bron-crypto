package affgstar_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/affgstar"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func _[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](_ ecdsa.Curve[G, B, S]) {
	var _ sigma.Statement = (*affgstar.Statement[G, B, S])(nil)
	var _ sigma.Witness = (*affgstar.Witness)(nil)
	var _ sigma.State = (*affgstar.State)(nil)
	var _ sigma.Commitment = (*affgstar.Commitment[G, B, S])(nil)
	var _ sigma.Response = (*affgstar.Response)(nil)

	var _ sigma.Protocol[*affgstar.Statement[G, B, S], *affgstar.Witness, *affgstar.Commitment[G, B, S], *affgstar.State, *affgstar.Response] = (*affgstar.Protocol[G, B, S])(nil)
}
