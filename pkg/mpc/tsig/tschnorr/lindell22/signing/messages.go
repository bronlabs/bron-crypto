package signing

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
)

// Round1Broadcast is the message broadcast in round 1 containing the nonce commitment.
type Round1Broadcast[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message] struct {
	BigRCommitment lindell22.Commitment `cbor:"bigRCommitment"`
}

func (*Round1Broadcast[GE, S, M]) Validate(cosigner *Cosigner[GE, S, M]) error { return nil }

// Round2Broadcast is the message broadcast in round 2 containing the nonce, its opening, and proof.
type Round2Broadcast[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message] struct {
	BigRProof   compiler.NIZKPoKProof     `cbor:"bigRProof"`
	BigROpening lindell22.Opening         `cbor:"bigROpening"`
	BigR        *schnorr.Statement[GE, S] `cbor:"bigR"`
}

func (*Round2Broadcast[GE, S, M]) Validate(cosigner *Cosigner[GE, S, M]) error { return nil }
