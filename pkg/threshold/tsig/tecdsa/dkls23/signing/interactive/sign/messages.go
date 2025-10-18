package sign

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
	rvole_softspoken "github.com/bronlabs/bron-crypto/pkg/threshold/rvole/softspoken"
)

type Round1P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	OtR1 *ecbbot.Round1P2P[P, S] `cbor:"otR1"`
}

type Round2P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	OtR2 *ecbbot.Round2P2P[P, S] `cbor:"otR2"`
}

type Round3Broadcast struct {
	BigRCommitment hash_comm.Commitment `cbor:"bigRCommitment"`
}

type Round3P2P struct {
	MulR1 *rvole_softspoken.Round1P2P `cbor:"mulR1"`
}

type Round4Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigR        P                 `cbor:"bigR"`
	BigRWitness hash_comm.Witness `cbor:"bigRWitness"`
	Pk          P                 `cbor:"pk"`
}

type Round4P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	MulR2  *rvole_softspoken.Round2P2P[S] `cbor:"mulR2"`
	GammaU P                              `cbor:"gammaU"`
	GammaV P                              `cbor:"gammaV"`
	Psi    S                              `cbor:"psi"`
}
