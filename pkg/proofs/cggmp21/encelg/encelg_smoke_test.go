package encelg_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/encelg"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func _[G curves.Point[G, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](_ ecdsa.Curve[G, B, S]) {
	var _ sigma.Statement = (*encelg.Statement[G, B, S])(nil)
	var _ sigma.Witness = (*encelg.Witness[G, S])(nil)
	var _ sigma.State = (*encelg.State[S])(nil)
	var _ sigma.Commitment = (*encelg.Commitment[G, B, S])(nil)
	var _ sigma.Response = (*encelg.Response[S])(nil)

	var _ sigma.Protocol[*encelg.Statement[G, B, S], *encelg.Witness[G, S], *encelg.Commitment[G, B, S], *encelg.State[S], *encelg.Response[S]] = (*encelg.Protocol[G, B, S])(nil)
}
