package dec_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/dec"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func _[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](_ ecdsa.Curve[G, B, S]) {
	var _ sigma.Statement = (*dec.Statement[G, B, S])(nil)
	var _ sigma.Witness = (*dec.Witness)(nil)
	var _ sigma.State = (*dec.State)(nil)
	var _ sigma.Commitment = (*dec.Commitment[G, B, S])(nil)
	var _ sigma.Response = (*dec.Response)(nil)

	var _ sigma.Protocol[*dec.Statement[G, B, S], *dec.Witness, *dec.Commitment[G, B, S], *dec.State, *dec.Response] = (*dec.Protocol[G, B, S])(nil)
}
