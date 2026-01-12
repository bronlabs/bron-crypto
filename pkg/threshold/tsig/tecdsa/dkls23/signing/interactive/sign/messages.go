package sign

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
	rvole_softspoken "github.com/bronlabs/bron-crypto/pkg/threshold/rvole/softspoken"
)

// Round1P2P carries round 1 peer-to-peer messages.
type Round1P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	OtR1 *ecbbot.Round1P2P[P, S] `cbor:"otR1"`
}

// Round2P2P carries round 2 peer-to-peer messages.
type Round2P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	OtR2 *ecbbot.Round2P2P[P, S] `cbor:"otR2"`
}

// Round3Broadcast carries round 3 broadcast messages.
type Round3Broadcast struct {
	BigRCommitment hash_comm.Commitment `cbor:"bigRCommitment"`
}

// Round3P2P carries round 3 peer-to-peer messages.
type Round3P2P struct {
	MulR1 *rvole_softspoken.Round1P2P `cbor:"mulR1"`
}

// Round4Broadcast carries round 4 broadcast messages.
type Round4Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigR        P                 `cbor:"bigR"`
	BigRWitness hash_comm.Witness `cbor:"bigRWitness"`
	Pk          P                 `cbor:"pk"`
}

// Round4P2P carries round 4 peer-to-peer messages.
type Round4P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	MulR2  *rvole_softspoken.Round2P2P[S] `cbor:"mulR2"`
	GammaU P                              `cbor:"gammaU"`
	GammaV P                              `cbor:"gammaV"`
	Psi    S                              `cbor:"psi"`
}
