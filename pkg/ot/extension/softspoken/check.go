// This file is the consistency check of SoftSpokenOT (Roy, "SoftSpokenOT:
// Quieter OT Extension from Small-Field Silent VOLE in the Minicrypt Model",
// CRYPTO 2022, eprint 2022/192, Figure 9), specialised as KOS15 Figure 10 does
// to p = q = 2 and the repetition code C = Rep(F_2^κ), so k_C = 1 and n_C = κ.
// In Roy's notation the IKNP03 extension is the subspace VOLE of his Figures 7
// and 8 with
//
//	U = x ∈ F_2^{ℓ'×1},  V = [t¹ | … | t^κ],  W = [q¹ | … | q^κ] = V + U·Δ,
//
// where ℓ' = ℓ + sigma, tⁱ are the receiver's columns t_i⁰ and qⁱ = tⁱ + Δ_i·x
// the sender's. The check applies a linear hash R to every column: the
// receiver sends Ũ = R·U = x̄ and Ṽ = R·V = (t̄¹, …, t̄^κ), and the sender
// verifies R·W = Ṽ + Ũ·Δ, that is q̄ⁱ = t̄ⁱ + Δ_i·x̄ for every i. Any lie of the
// receiver about x in some column then fails with probability 1 − ε, and the
// extra sigma rows of x are discarded afterwards so that x̄ reveals nothing
// about the first ℓ choice bits (Roy's Definition 4.1, F_2^ℓ-hiding).
//
// R is the hash KOS15 give for Figure 10,
//
//	h_χ : F_{2^sigma}^{m+1} → F_{2^sigma},  v̂ ↦ Σ_{j=1}^{m} v̂_j·χ_j + v̂_{m+1},
//
// with m = ℓ/sigma and χ ∈ F_{2^sigma}^m. It is F_2-linear, ε-universal with
// ε = 2^{-sigma} because the χ_j are independent, and F_2^ℓ-hiding because the
// last block v̂_{m+1} is uniform and enters with coefficient 1.
//
// Both papers have the Δ-holder sample χ and send it, costing a message. Here
// χ is derived from the transcript after the receiver's columns u_1..u_κ are
// bound to it, which is the one-message SoftSpokenOT of DKLs23 (Doerner, Kondi,
// Lee, shelat, "Threshold ECDSA in Three Rounds", eprint 2023/765, Section
// 5.1): the check has the shape of a sigma protocol whose simulator extracts
// nothing from it and never rewinds, so the Fiat–Shamir transform with a
// non-programmable global random oracle, χ = H(u_1, …, u_κ), keeps UC
// security. DKLs23 also require that every occurrence of the statistical
// parameter s then be replaced by the computational one, because the receiver
// can brute-force a convenient challenge; that is why sigma is κ = 128 and not
// a smaller s. Hashing the whole transcript rather than only the columns binds
// the session and the base OTs as well, a superset of what they hash.

package softspoken

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/binaryfields/bf128"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

// toBlocks splits an ℓ'-bit packed vector into its ℓ'/sigma blocks as elements
// of F_{2^sigma}, the v̂_1..v̂_{m+1} of the file comment; the same F_2-linear map
// is applied to x, tⁱ and qⁱ, so the correlation qⁱ = tⁱ ⊕ Δ_i·x carries over
// to the blocks and to the hash sums.
func toBlocks(packed []byte) ([]*bf128.FieldElement, error) {
	if len(packed)%sigmaBytes != 0 {
		return nil, ot.ErrInvalidArgument.WithMessage("vector of %d bits is not a multiple of %d", len(packed)*8, sigma)
	}
	field := bf128.NewField()
	blocks := make([]*bf128.FieldElement, len(packed)/sigmaBytes)
	for j := range blocks {
		block, err := field.FromBytes(packed[j*sigmaBytes : (j+1)*sigmaBytes])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot read block %d", j)
		}
		blocks[j] = block
	}
	return blocks, nil
}

// universalHash is the linear hash R of Roy's Figure 9 in KOS15's instantiation,
// h_χ(v̂) = Σ_{j<m} v̂_j·χ_j + v̂_m over F_{2^sigma} with zero-based blocks, applied
// to one column: to x for Ũ and to each tⁱ or qⁱ for Ṽ and R·W.
func universalHash(chi, blocks []*bf128.FieldElement) (*bf128.FieldElement, error) {
	m := len(chi)
	if len(blocks) != m+1 {
		return nil, ot.ErrInvalidArgument.WithMessage("vector has %d blocks, expected %d", len(blocks), m+1)
	}
	acc := blocks[m]
	for j := range m {
		acc = acc.Add(blocks[j].Mul(chi[j]))
	}
	return acc, nil
}

// extractChallenge derives the m challenge elements χ_1..χ_m, the seed of R,
// from the transcript, which at this point binds the IKNP columns u_1..u_κ;
// this is the Fiat–Shamir step of DKLs23 Section 5.1 in place of the message in
// which the papers' Δ-holder sends χ.
func extractChallenge(transcript transcripts.Transcript, m int) ([]*bf128.FieldElement, error) {
	if m <= 0 {
		return nil, ot.ErrInvalidArgument.WithMessage("challenge length must be positive, got %d", m)
	}
	raw, err := transcript.ExtractBytes(chiLabel, uint(m*sigmaBytes))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot extract the challenge from the transcript")
	}
	chi, err := toBlocks(raw)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot parse the challenge")
	}
	return chi, nil
}

// appendResponse binds the receiver's check responses to the transcript.
func appendResponse(transcript transcripts.Transcript, x *bf128.FieldElement, t []*bf128.FieldElement) {
	payload := make([][]byte, 0, len(t)+1)
	payload = append(payload, x.Bytes())
	for _, ti := range t {
		payload = append(payload, ti.Bytes())
	}
	transcript.AppendBytes(responseLabel, payload...)
}
