package schnorr_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	tsig "github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
)

func _[G algebra.PrimeGroupElement[G, F], F algebra.PrimeFieldElement[F]]() {
	var _ tsig.Shard[*schnorrlike.PublicKey[G, F], *feldman.Share[F]] = (*schnorr.Shard[G, F])(nil)
	var _ tsig.PublicMaterial[*schnorrlike.PublicKey[G, F]] = (*schnorr.PublicMaterial[G, F])(nil)
}
