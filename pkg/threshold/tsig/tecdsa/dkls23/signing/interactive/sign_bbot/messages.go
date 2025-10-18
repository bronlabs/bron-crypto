package sign_bbot

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	rvole_bbot "github.com/bronlabs/bron-crypto/pkg/threshold/rvole/bbot"
	przsSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs/setup"
)

type Round1Broadcast struct {
	ZeroSetupR1 *przsSetup.Round1Broadcast `cbor:"zeroSetupR1"`

	BigRCommitment hash_comm.Commitment `cbor:"bigRCommitment"`
}

type Round1P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	MulR1 *rvole_bbot.Round1P2P[P, S] `cbor:"mulR1"`
}

type Round2Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigR        P                 `cbor:"bigR"`
	BigRWitness hash_comm.Witness `cbor:"bigRWitness"`
}

type Round2P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ZeroSetupR2 *przsSetup.Round2P2P        `cbor:"zeroSetupR2"`
	MulR2       *rvole_bbot.Round2P2P[P, S] `cbor:"mulR2"`
}

type Round3Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Pk P `cbor:"pk"`
}

type Round3P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	MulR3 *rvole_bbot.Round3P2P[S] `cbor:"mulR3"`

	GammaU P `cbor:"gammaU"`
	GammaV P `cbor:"gammaV"`
	Psi    S `cbor:"psi"`
}
