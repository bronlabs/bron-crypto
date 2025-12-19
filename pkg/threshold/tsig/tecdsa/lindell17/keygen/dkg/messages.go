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

type Round1Broadcast struct {
	BigQCommitment hash_comm.Commitment
}

// Round2Broadcast opens commitments to Q' and Q” with corresponding proofs.
type Round2Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigQOpening          hash_comm.Witness
	BigQPrime            P
	BigQPrimeProof       compiler.NIZKPoKProof
	BigQDoublePrime      P
	BigQDoublePrimeProof compiler.NIZKPoKProof
}

// Round3Broadcast shares Paillier public key and encryptions of split shares.
type Round3Broadcast struct {
	CKeyPrime         *paillier.Ciphertext
	CKeyDoublePrime   *paillier.Ciphertext
	PaillierPublicKey *paillier.PublicKey
}

type Round4P2P struct {
	LpRound1Output              *lp.Round1Output
	LpdlPrimeRound1Output       *lpdl.Round1Output
	LpdlDoublePrimeRound1Output *lpdl.Round1Output
}

type Round5P2P struct {
	LpRound2Output              *lp.Round2Output
	LpdlPrimeRound2Output       *lpdl.Round2Output
	LpdlDoublePrimeRound2Output *lpdl.Round2Output
}

type Round6P2P struct {
	LpRound3Output              *lp.Round3Output
	LpdlPrimeRound3Output       *lpdl.Round3Output
	LpdlDoublePrimeRound3Output *lpdl.Round3Output
}

type Round7P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	LpRound4Output              *lp.Round4Output
	LpdlPrimeRound4Output       *lpdl.Round4Output[P, B, S]
	LpdlDoublePrimeRound4Output *lpdl.Round4Output[P, B, S]
}
