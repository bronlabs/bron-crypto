package signing

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

type Round1OutputP2P struct {
	BigR1Commitment hash_comm.Commitment
}

type Round2OutputP2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigR2      P
	BigR2Proof compiler.NIZKPoKProof
}

type Round3OutputP2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigR1Opening hash_comm.Witness
	BigR1        P
	BigR1Proof   compiler.NIZKPoKProof
}

type Round4OutputP2P struct {
	C3 *paillier.Ciphertext
}
