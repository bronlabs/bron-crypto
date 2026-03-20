package signing

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
)

// Round1Broadcast is the message broadcast in round 1 containing the nonce commitment.
type Round1Broadcast[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message] struct {
	BigRCommitment lindell22.Commitment `cbor:"bigRCommitment"`
}

func (m *Round1Broadcast[GE, S, M]) Validate(cosigner *Cosigner[GE, S, M], _ sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round1Broadcast message")
	}
	if m.BigRCommitment == (lindell22.Commitment{}) {
		return ErrValidation.WithMessage("missing BigR commitment in Round1Broadcast message")
	}
	return nil
}

// Round2Broadcast is the message broadcast in round 2 containing the nonce, its opening, and proof.
type Round2Broadcast[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message] struct {
	BigRProof   compiler.NIZKPoKProof     `cbor:"bigRProof"`
	BigROpening lindell22.Opening         `cbor:"bigROpening"`
	BigR        *schnorr.Statement[GE, S] `cbor:"bigR"`
}

func (m *Round2Broadcast[GE, S, M]) Validate(cosigner *Cosigner[GE, S, M], _ sharing.ID) error {
	if m == nil || m.BigR == nil || utils.IsNil(m.BigR.Value()) {
		return ErrValidation.WithMessage("missing fields in Round2Broadcast message")
	}
	if m.BigR.Value().IsOpIdentity() {
		return ErrValidation.WithMessage("BigR cannot be the identity element in Round2Broadcast message")
	}
	if m.BigROpening == (lindell22.Opening{}) {
		return ErrValidation.WithMessage("missing BigR opening in Round2Broadcast message")
	}
	if ct.SliceIsZero(m.BigRProof) == ct.True {
		return ErrValidation.WithMessage("missing BigR proof in Round2Broadcast message")
	}
	return nil
}
