package schnorr_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	mpcsig "github.com/bronlabs/bron-crypto/pkg/mpc/signatures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
)

func _[G algebra.PrimeGroupElement[G, F], F algebra.PrimeFieldElement[F]]() {
	var _ mpcsig.Shard[*schnorrlike.PublicKey[G, F], *feldman.Share[F]] = (*schnorr.Shard[G, F])(nil)
	var _ mpcsig.PublicMaterial[*schnorrlike.PublicKey[G, F]] = (*schnorr.PublicMaterial[G, F])(nil)
}
