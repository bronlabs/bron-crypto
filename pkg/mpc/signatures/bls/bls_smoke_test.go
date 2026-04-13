package bls_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	mpcsig "github.com/bronlabs/bron-crypto/pkg/mpc/signatures"
	mpcbls "github.com/bronlabs/bron-crypto/pkg/mpc/signatures/bls"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
)

func _[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
]() {
	var _ mpcsig.PublicMaterial[*bls.PublicKey[PK, PKFE, SG, SGFE, E, S]] = (*mpcbls.PublicMaterial[PK, PKFE, SG, SGFE, E, S])(nil)
	var _ mpcsig.Shard[*bls.PublicKey[PK, PKFE, SG, SGFE, E, S], *feldman.Share[S]] = (*mpcbls.Shard[PK, PKFE, SG, SGFE, E, S])(nil)
}
