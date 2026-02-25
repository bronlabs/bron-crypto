package signing

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

// Round1Broadcast is the message broadcast in round 1 containing the nonce commitment.
type Round1Broadcast struct {
	BigRCommitment lindell22.Commitment `cbor:"bigRCommitment"`
}

// Round2Broadcast is the message broadcast in round 2 containing the nonce, its opening, and proof.
type Round2Broadcast[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	BigRProof   compiler.NIZKPoKProof    `cbor:"bigRProof"`
	BigROpening lindell22.Opening        `cbor:"bigROpening"`
	BigR        *schnorr.Statement[E, S] `cbor:"bigR"`
}
