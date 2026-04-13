package boldyreva02

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	mpcbls "github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/bls"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
)

var ErrValidation = errs.New("validation error")

// PartialSignature represents a partial BLS signature produced by a single party
// in the Boldyreva BLS scheme. It contains the partial signature on
// the message (SigmaI) and optionally a proof-of-possession signature (SigmaPopI)
// when using the POP rogue key prevention algorithm.
type PartialSignature[
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	// SigmaI is the partial signature on the message.
	SigmaI []*bls.Signature[Sig, SigFE, PK, PKFE, E, S] `cbor:"sigma_i"`
	// SigmaPopI is the proof-of-possession signature, present only when using POP algorithm.
	SigmaPopI []*bls.Signature[Sig, SigFE, PK, PKFE, E, S] `cbor:"sigma_pop_i"`
}

func (ps *PartialSignature[Sig, SigFE, PK, PKFE, E, S]) Validate(rogueKeyPrevention bls.RogueKeyPreventionAlgorithm) error {
	if ps == nil || len(ps.SigmaI) == 0 {
		return ErrValidation.WithMessage("partial signature cannot be nil or empty")
	}
	for _, sigma := range ps.SigmaI {
		if sigma == nil || sigma.Value().IsOpIdentity() || !sigma.Value().IsTorsionFree() {
			return ErrValidation.WithMessage("partial signature point must be non-identity and torsion-free")
		}
	}
	if rogueKeyPrevention == bls.POP {
		if ps.SigmaPopI == nil {
			return ErrValidation.WithMessage("partial signature POP cannot be nil when using POP algorithm")
		}
		if len(ps.SigmaPopI) != len(ps.SigmaI) {
			return ErrValidation.WithMessage("partial signature POP length must match message signature length")
		}
		for _, sigmaPop := range ps.SigmaPopI {
			if sigmaPop == nil || sigmaPop.Value().IsOpIdentity() || !sigmaPop.Value().IsTorsionFree() {
				return ErrValidation.WithMessage("partial signature POP point must be non-identity and torsion-free")
			}
		}
	}
	return nil
}

// Equal returns true if two PartialSignature instances are equal.
// Two partial signatures are equal if both their message signatures and POP signatures match.
func (ps *PartialSignature[Sig, SigFE, PK, PKFE, E, S]) Equal(other *PartialSignature[Sig, SigFE, PK, PKFE, E, S]) bool {
	if ps == nil || other == nil {
		return ps == other
	}
	if len(ps.SigmaI) != len(other.SigmaI) {
		return false
	}
	for i := range ps.SigmaI {
		if !ps.SigmaI[i].Equal(other.SigmaI[i]) {
			return false
		}
	}
	if len(ps.SigmaPopI) != len(other.SigmaPopI) {
		return false
	}
	for i := range ps.SigmaPopI {
		if !ps.SigmaPopI[i].Equal(other.SigmaPopI[i]) {
			return false
		}
	}
	return true
}

type (
	// Shard is an alias for tbls.Shard, representing a party's secret share
	// in the Boldyreva BLS signature scheme.
	Shard[
		PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
		SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
		E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
	] = mpcbls.Shard[PK, PKFE, SG, SGFE, E, S]

	// PublicMaterial is an alias for tbls.PublicMaterial, containing the public
	// cryptographic material for the Boldyreva BLS scheme.
	PublicMaterial[
		PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
		SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
		E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
	] = mpcbls.PublicMaterial[PK, PKFE, SG, SGFE, E, S]
)
