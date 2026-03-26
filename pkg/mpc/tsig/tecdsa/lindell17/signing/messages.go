package signing

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

// Round1OutputP2P carries the primary cosigner's round 1 output.
type Round1OutputP2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigR1Commitment hash_comm.Commitment
}

func (m *Round1OutputP2P[P, B, S]) Validate(cosigner *Cosigner[P, B, S], _ sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round1OutputP2P message")
	}
	if ct.SliceIsZero(m.BigR1Commitment[:]) == ct.True {
		return ErrValidation.WithMessage("missing BigR1 commitment in Round1OutputP2P message")
	}
	return nil
}

// Round2OutputP2P carries the secondary cosigner's round 2 output.
type Round2OutputP2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigR2      P
	BigR2Proof compiler.NIZKPoKProof
}

func (m *Round2OutputP2P[P, B, S]) Validate(cosigner *Cosigner[P, B, S], _ sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round2OutputP2P message")
	}
	if ct.SliceIsZero(m.BigR2Proof) == ct.True {
		return ErrValidation.WithMessage("missing BigR2 proof in Round2OutputP2P message")
	}
	if m.BigR2.Structure().Name() != cosigner.suite.Curve().Name() {
		return ErrValidation.WithMessage("BigR2 curve does not match cosigner's curve in Round2OutputP2P message")
	}
	if m.BigR2.IsOpIdentity() || !m.BigR2.IsTorsionFree() {
		return ErrValidation.WithMessage("invalid BigR2 in Round2OutputP2P message")
	}
	return nil
}

// Round3OutputP2P carries the primary cosigner's round 3 output.
type Round3OutputP2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigR1Opening hash_comm.Witness
	BigR1        P
	BigR1Proof   compiler.NIZKPoKProof
}

func (m *Round3OutputP2P[P, B, S]) Validate(cosigner *Cosigner[P, B, S], _ sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round3OutputP2P message")
	}
	if ct.SliceIsZero(m.BigR1Opening[:]) == ct.True {
		return ErrValidation.WithMessage("missing BigR1 opening in Round3OutputP2P message")
	}
	if m.BigR1.Structure().Name() != cosigner.suite.Curve().Name() {
		return ErrValidation.WithMessage("BigR1 curve does not match cosigner's curve in Round3OutputP2P message")
	}
	if m.BigR1.IsOpIdentity() || !m.BigR1.IsTorsionFree() {
		return ErrValidation.WithMessage("invalid BigR1 in Round3OutputP2P message")
	}
	if ct.SliceIsZero(m.BigR1Proof) == ct.True {
		return ErrValidation.WithMessage("missing BigR1 proof in Round3OutputP2P message")
	}
	return nil
}

// Round4OutputP2P carries the secondary cosigner's round 4 output.
type Round4OutputP2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	C3 *paillier.Ciphertext
}

func (m *Round4OutputP2P[P, B, S]) Validate(cosigner *Cosigner[P, B, S], sender sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round4OutputP2P message")
	}
	if m.C3 == nil {
		return ErrValidation.WithMessage("missing C3 in Round4OutputP2P message")
	}
	pk := cosigner.shard.PaillierPrivateKey().PublicKey()
	if !pk.CiphertextSpace().Contains(m.C3) {
		return ErrValidation.WithMessage("C3 does not belong to sender's Paillier ciphertext space in Round4OutputP2P message")
	}
	if pk.N2().Nat().Equal(m.C3.N2().Value()) == ct.False {
		return ErrValidation.WithMessage("C3 has incorrect modulus in Round4OutputP2P message")
	}
	return nil
}
