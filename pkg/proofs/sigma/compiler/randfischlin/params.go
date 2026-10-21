package randfischlin

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
)

const (
	// Lambda is the computational security parameter in bits.
	Lambda = base.ComputationalSecurityBits
	// LambdaLog2 is the ceiling of log2(Lambda).
	LambdaLog2 = base.ComputationalSecurityLog2Ceil
	// R is the number of parallel repetitions.
	R = 16
)

// params are the transform parameters derived from the sigma protocol by newParams.
// They are not carried in the proof: prover and verifier derive them independently
// from the same sigma protocol.
type params struct {
	// r is the number of parallel repetitions.
	r int
	// l is the random oracle output length in bits, i.e. the per-repetition difficulty.
	l uint
	// lBytes is ceil(l / 8), the number of digest bytes inspected by the hash check.
	lBytes int
	// tBytes is the number of uniformly random bytes in every challenge; the challenge
	// space is {0,1}^t with t = 8 * tBytes, embedded in the sigma protocol's challenge.
	tBytes int
}

// newParams derives (r, l, t) for a sigma protocol with the given special soundness n
// and challenge length in bytes.
//
// [KS22] (Figure 9, Theorem 6.4) fixes r * l = lambda and t = ceil(log2 lambda) * l for
// strongly 2-special sound protocols: a prover without a witness holds at most one
// accepting transcript per repetition, which hashes to zero with probability 2^-l.
// Against an n-special sound protocol a cheating prover can prepare n - 1 accepting
// transcripts per repetition (each a separate oracle query) without enabling extraction,
// so the per-repetition success probability grows to (n - 1) * 2^-l and the soundness
// condition becomes r * (l - log2(n - 1)) >= lambda, as in the n-special soundness
// extension of the standard transform ([CL24], Section 5.1). r stays fixed and l grows
// by ceil(log2(n - 1)); for n = 2 this reproduces the fixed parameters of [KS22].
//
// t governs completeness only: the prover must not exhaust {0,1}^t before a hit, for
// which [KS22] needs 2^t >= lambda * 2^l. We keep the (larger) rule of Figure 9, rounded
// up to whole bytes, and require the challenge to fit the sigma protocol's challenge
// length. Soundness and zero knowledge do not depend on t.
func newParams(specialSoundness uint, challengeBytesLength int) (params, error) {
	if specialSoundness < 2 {
		return params{}, proofs.ErrInvalidArgument.WithMessage("sigma protocol must be at least 2-special sound (got %d)", specialSoundness)
	}
	l := uint(mathutils.CeilDiv(Lambda, R)) + uint(mathutils.CeilLog2(int(specialSoundness)-1))
	lBytes := mathutils.CeilDiv(int(l), 8)
	tBytes := mathutils.CeilDiv(LambdaLog2*int(l), 8)
	if tBytes > challengeBytesLength {
		return params{}, proofs.ErrInvalidArgument.WithMessage(
			"sigma protocol challenge length (%d bytes) is shorter than the %d-byte challenge required by %d-special soundness",
			challengeBytesLength, tBytes, specialSoundness)
	}
	return params{
		r:      R,
		l:      l,
		lBytes: lBytes,
		tBytes: tBytes,
	}, nil
}

// hash evaluates the l-bit random oracle on the index-and-length-prefixed inputs: the
// first ceil(l / 8) bytes of SHA3-256 with the bits above l cleared in the last byte.
func (p *params) hash(data ...[]byte) ([]byte, error) {
	result, err := hashing.HashIndexLengthPrefixed(randomOracle, data...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot hash values")
	}

	digest := result[:p.lBytes]
	if rem := p.l % 8; rem != 0 {
		digest[p.lBytes-1] &= byte(1<<rem) - 1
	}
	return digest, nil
}

// sample draws a challenge uniformly from {0,1}^t without replacement: the first tBytes
// bytes are random and the remaining bytes of the sigma protocol's challenge are zero.
// The caller records the challenges it has already tried in tried.
func (p *params) sample(tried map[string]struct{}, length int, prng io.Reader) ([]byte, error) {
	for {
		ei := make([]byte, length)
		_, err := io.ReadFull(prng, ei[:p.tBytes])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot read from PRNG")
		}

		if _, seen := tried[string(ei[:p.tBytes])]; !seen {
			return ei, nil
		}
	}
}
