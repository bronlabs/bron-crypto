package tecdsa_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func _[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]]() {
	var _ tsig.Shard[*ecdsa.PublicKey[P, B, S], *feldman.Share[S], *threshold.Threshold] = (*tecdsa.Shard[P, B, S])(nil)
	var _ tsig.PublicMaterial[*ecdsa.PublicKey[P, B, S], *threshold.Threshold] = (*tecdsa.PublicMaterial[P, B, S])(nil)
}
