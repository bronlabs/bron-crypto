package znstar

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
)

// SamplePedersenParameters generates a full ring-Pedersen setup for the
// CGGMP21 ZK proofs (Π^{prm}, Π^{enc}, Π^{aff-g}, range proofs, …).
// Concretely it:
//
//  1. Samples a safe-prime RSA group (Z/N̂Z)* with N̂ = p·q, p = 2p' + 1
//     and q = 2q' + 1. QR_{N̂} is then cyclic of prime order p'·q', which
//     is what makes the discrete-log assumption in QR_{N̂} plausibly hard
//     and the Π^{prm} proof sound.
//  2. Draws t uniformly from QR_{N̂}. Since QR_{N̂} has prime order, a
//     uniformly random QR is a generator except with probability
//     ≈ 2^{-|p|+1}; the gcd(t-1, N̂) = 1 guard rejects the rare case of
//     landing on a non-generator (which would collapse ⟨t⟩ to a proper
//     subgroup and leak information about p, q).
//  3. Samples λ ∈ [1, φ(N̂)/4) uniformly. φ(N̂)/4 = p'·q' is exactly the
//     order of QR_{N̂}, so s := t^λ is uniformly distributed over ⟨t⟩ =
//     QR_{N̂}.
//  4. Returns s, t as elements of the unknown-order view of the group;
//     external callers see only the public parameters. The raw primes
//     p, q and the trapdoor λ are returned alongside for callers that own
//     the setup and need them to accelerate their own proofs.
//
// SECURITY: the returned p, q, λ triple fully reveals the factorisation
// of N̂ and the ring-Pedersen trapdoor. Any party given these values can
// open arbitrary Pedersen commitments; they must be kept secret from
// every other protocol participant and zeroised as soon as they are no
// longer needed.
func SamplePedersenParameters(keyLen uint, prng io.Reader) (NHat *num.NatPlus, s, t *RSAGroupElementUnknownOrder, p, q, lambda *num.NatPlus, err error) { //nolint:gocritic // intentionally returning too many results.
	if prng == nil {
		return nil, nil, nil, nil, nil, nil, ErrIsNil.WithMessage("prng")
	}
	rsaGroup, err := SampleSafeRSAGroup(keyLen, prng)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, errs.Wrap(err).WithMessage("failed to sample RSA group with safe primes")
	}
	NHat = rsaGroup.n
	p, err = num.NPlus().FromNatCT(rsaGroup.arith.Params.PNat)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, errs.Wrap(err).WithMessage("failed to create NatPlus from p")
	}
	q, err = num.NPlus().FromNatCT(rsaGroup.arith.Params.QNat)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, errs.Wrap(err).WithMessage("failed to create NatPlus from q")
	}
	var tKnownOrder, sKnownOrder *RSAGroupElementKnownOrder
	for {
		tKnownOrder, err = rsaGroup.RandomQuadraticResidue(prng)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, errs.Wrap(err).WithMessage("failed to sample t")
		}
		// Check that t is a generator of QR(NHat). The probability of it not being one is ~2^{-|p|+1}.
		if tKnownOrder.Value().Decrement().Nat().Coprime(NHat.Nat()) {
			break
		}
	}
	phiNHat, err := num.NPlus().FromModulusCT(rsaGroup.arith.Phi)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, errs.Wrap(err).WithMessage("failed to create NatPlus from phi(NHat)")
	}
	four, err := num.NPlus().FromUint64(4)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, errs.Wrap(err).WithMessage("failed to create 4 in NatPlus")
	}
	phiNHatOver4, err := phiNHat.TryDiv(four)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, errs.Wrap(err).WithMessage("failed to compute phi(NHat)/4")
	}
	lambda, err = num.NPlus().Random(num.NPlus().One(), phiNHatOver4, prng)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, errs.Wrap(err).WithMessage("failed to sample lambda")
	}
	sKnownOrder = tKnownOrder.Exp(lambda.Nat())
	return NHat, sKnownOrder.ForgetOrder(), tKnownOrder.ForgetOrder(), p, q, lambda, nil
}
