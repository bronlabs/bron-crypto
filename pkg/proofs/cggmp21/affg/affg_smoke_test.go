package affg_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/affg"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func _[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](_ ecdsa.Curve[G, B, S]) {
	var _ sigma.Statement = (*affg.Statement[G, B, S])(nil)
	var _ sigma.Witness = (*affg.Witness)(nil)
	var _ sigma.State = (*affg.State)(nil)
	var _ sigma.Commitment = (*affg.Commitment[G, B, S])(nil)
	var _ sigma.Response = (*affg.Response)(nil)

	var _ sigma.Protocol[*affg.Statement[G, B, S], *affg.Witness, *affg.Commitment[G, B, S], *affg.State, *affg.Response] = (*affg.Protocol[G, B, S])(nil)
}
