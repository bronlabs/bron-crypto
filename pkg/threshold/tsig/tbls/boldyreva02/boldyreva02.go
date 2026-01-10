package boldyreva02

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tbls"
)

// PartialSignature represents a partial BLS signature produced by a single party
// in the Boldyreva threshold BLS scheme. It contains the partial signature on
// the message (SigmaI) and optionally a proof-of-possession signature (SigmaPopI)
// when using the POP rogue key prevention algorithm.
type PartialSignature[
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	// SigmaI is the partial signature on the message.
	SigmaI *bls.Signature[Sig, SigFE, PK, PKFE, E, S]
	// SigmaPopI is the proof-of-possession signature, present only when using POP algorithm.
	SigmaPopI *bls.Signature[Sig, SigFE, PK, PKFE, E, S]
}

// Equal returns true if two PartialSignature instances are equal.
// Two partial signatures are equal if both their message signatures and POP signatures match.
func (ps *PartialSignature[Sig, SigFE, PK, PKFE, E, S]) Equal(other *PartialSignature[Sig, SigFE, PK, PKFE, E, S]) bool {
	if ps == nil || other == nil {
		return ps == other
	}
	return ps.SigmaI.Equal(other.SigmaI) && ps.SigmaPopI.Equal(other.SigmaPopI)
}

// Bytes returns the byte representation of the partial signature.
// It concatenates the message signature bytes with the POP signature bytes (if present).
func (ps *PartialSignature[Sig, SigFE, PK, PKFE, E, S]) Bytes() []byte {
	buf := ps.SigmaI.Bytes()
	if ps.SigmaPopI != nil {
		buf = append(buf, ps.SigmaPopI.Bytes()...)
	}
	return buf
}

type (
	// Shard is an alias for tbls.Shard, representing a party's secret share
	// in the Boldyreva threshold BLS signature scheme.
	Shard[
		PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
		SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
		E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
	] = tbls.Shard[PK, PKFE, SG, SGFE, E, S]

	// PublicMaterial is an alias for tbls.PublicMaterial, containing the public
	// cryptographic material for the Boldyreva threshold BLS scheme.
	PublicMaterial[
		PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
		SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
		E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
	] = tbls.PublicMaterial[PK, PKFE, SG, SGFE, E, S]
)
