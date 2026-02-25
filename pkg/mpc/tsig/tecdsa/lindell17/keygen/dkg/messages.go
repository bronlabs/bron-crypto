package dkg

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lp"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lpdl"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

// Round1Broadcast carries the first-round broadcast data.
type Round1Broadcast struct {
	BigQCommitment hash_comm.Commitment
}

// Round2Broadcast carries the second-round broadcast data.
type Round2Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigQOpening          hash_comm.Witness
	BigQPrime            P
	BigQPrimeProof       compiler.NIZKPoKProof
	BigQDoublePrime      P
	BigQDoublePrimeProof compiler.NIZKPoKProof
}

// Round3Broadcast carries the third-round broadcast data.
type Round3Broadcast struct {
	CKeyPrime         *paillier.Ciphertext
	CKeyDoublePrime   *paillier.Ciphertext
	PaillierPublicKey *paillier.PublicKey
}

// Round4P2P carries round 4 point-to-point data.
type Round4P2P struct {
	LpRound1Output              *lp.Round1Output
	LpdlPrimeRound1Output       *lpdl.Round1Output
	LpdlDoublePrimeRound1Output *lpdl.Round1Output
}

// Round5P2P carries round 5 point-to-point data.
type Round5P2P struct {
	LpRound2Output              *lp.Round2Output
	LpdlPrimeRound2Output       *lpdl.Round2Output
	LpdlDoublePrimeRound2Output *lpdl.Round2Output
}

// Round6P2P carries round 6 point-to-point data.
type Round6P2P struct {
	LpRound3Output              *lp.Round3Output
	LpdlPrimeRound3Output       *lpdl.Round3Output
	LpdlDoublePrimeRound3Output *lpdl.Round3Output
}

// Round7P2P carries round 7 point-to-point data.
type Round7P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	LpRound4Output              *lp.Round4Output
	LpdlPrimeRound4Output       *lpdl.Round4Output[P, B, S]
	LpdlDoublePrimeRound4Output *lpdl.Round4Output[P, B, S]
}
