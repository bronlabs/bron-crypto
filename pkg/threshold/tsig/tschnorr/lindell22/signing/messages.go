package signing

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr/lindell22"
)

type Round1Broadcast struct {
	BigRCommitment lindell22.Commitment `cbor:"bigRCommitment"`
}

func (r *Round1Broadcast) Bytes() []byte {
	if r == nil {
		return nil
	}
	return r.BigRCommitment.Bytes()
}

type Round2Broadcast[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	BigRProof   compiler.NIZKPoKProof                 `cbor:"bigRProof"`
	BigROpening lindell22.Opening                     `cbor:"bigROpening"`
	BigR        *lindell22.PokProtocolStatement[E, S] `cbor:"bigR"`
}

func (r *Round2Broadcast[E, S]) Bytes() []byte {
	//if r == nil {
	//	return nil
	//}
	//return slices.Concat(r.BigRProof.Bytes(), r.BigROpening.Bytes(), r.BigR.Bytes())
	panic("not implemented")
}
