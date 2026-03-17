package tschnorr_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
)

func _[G algebra.PrimeGroupElement[G, F], F algebra.PrimeFieldElement[F]]() {
	var _ tsig.Shard[*schnorrlike.PublicKey[G, F], *feldman.Share[F], *threshold.Threshold] = (*tschnorr.Shard[G, F])(nil)
	var _ tsig.PublicMaterial[*schnorrlike.PublicKey[G, F], *threshold.Threshold] = (*tschnorr.PublicMaterial[G, F])(nil)
}
