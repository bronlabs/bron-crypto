package bls_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	tsig "github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures"
	tbls "github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/bls"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
)

func _[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
]() {
	var _ tsig.PublicMaterial[*bls.PublicKey[PK, PKFE, SG, SGFE, E, S]] = (*tbls.PublicMaterial[PK, PKFE, SG, SGFE, E, S])(nil)
	var _ tsig.Shard[*bls.PublicKey[PK, PKFE, SG, SGFE, E, S], *feldman.Share[S]] = (*tbls.Shard[PK, PKFE, SG, SGFE, E, S])(nil)
}
