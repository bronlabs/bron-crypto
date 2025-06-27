package boldyreva02

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tbls"
)

type PartialSignature[
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FiniteFieldElement[SigFE],
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FiniteFieldElement[PKFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	SigmaI    *bls.Signature[Sig, SigFE, PK, PKFE, E, S]
	SigmaPopI *bls.Signature[Sig, SigFE, PK, PKFE, E, S]
}

func (ps *PartialSignature[Sig, SigFE, PK, PKFE, E, S]) Equal(other *PartialSignature[Sig, SigFE, PK, PKFE, E, S]) bool {
	if ps == nil || other == nil {
		return ps == other
	}
	return ps.SigmaI.Equal(other.SigmaI) && ps.SigmaPopI.Equal(other.SigmaPopI)
}

func (ps *PartialSignature[Sig, SigFE, PK, PKFE, E, S]) Bytes() []byte {
	buf := ps.SigmaI.Bytes()
	if ps.SigmaPopI != nil {
		buf = append(buf, ps.SigmaPopI.Bytes()...)
	}
	return buf
}

type (
	Shard[
		PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FiniteFieldElement[PKFE],
		SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FiniteFieldElement[SGFE],
		E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
	] = tbls.Shard[PK, PKFE, SG, SGFE, E, S]

	PublicMaterial[
		PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FiniteFieldElement[PKFE],
		SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FiniteFieldElement[SGFE],
		E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
	] = tbls.PublicMaterial[PK, PKFE, SG, SGFE, E, S]
)
