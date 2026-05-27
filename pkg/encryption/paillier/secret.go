package paillier

import (
	"io"

	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/internal/gift"
)

// SampleSecretKey generates a fresh Paillier key pair with a keyLen-bit modulus
// N = p·q from two random primes. The factorisation (p, q) is the decryption
// trapdoor and stays secret; prng must be a cryptographically secure source.
func SampleSecretKey(keyLen uint, prng io.Reader) (*SecretKey, error) {
	group, err := znstar.SamplePaillierGroup(keyLen, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample Paillier group")
	}
	out, err := NewSecretKey(group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create secret key from group")
	}
	return out, nil
}

// SampleBlumSecretKey is like SampleSecretKey but draws a Blum modulus (p ≡ q ≡ 3
// mod 4), as required by several zero-knowledge proofs over a Paillier modulus
// (e.g. Paillier-Blum modulus / square-freeness proofs).
func SampleBlumSecretKey(keyLen uint, prng io.Reader) (*SecretKey, error) {
	group, err := znstar.SamplePaillierBlumGroup(keyLen, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample Paillier Blum group")
	}
	out, err := NewSecretKey(group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create secret key from group")
	}
	return out, nil
}

// SampleSafeSecretKey is like SampleSecretKey but uses safe primes (p = 2p′+1,
// q = 2q′+1), which some protocols require so that QR_N is cyclic of prime-ish
// order for their soundness/setup assumptions.
func SampleSafeSecretKey(keyLen uint, prng io.Reader) (*SecretKey, error) {
	group, err := znstar.SampleSafePaillierGroup(keyLen, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample safe Paillier group")
	}
	out, err := NewSecretKey(group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create secret key from group")
	}
	return out, nil
}

// NewSecretKey builds a secret key from a Paillier group with known factorisation,
// precomputing the CRT decryption constants. The factorisation is the secret
// trapdoor that enables Decrypt and Open.
func NewSecretKey(group *znstar.PaillierGroupKnownOrder) (*SecretKey, error) {
	if group == nil {
		return nil, encryption.ErrIsNil.WithMessage("group must not be nil")
	}
	sk := &SecretKey{ //nolint:exhaustruct // other fields are lazily computed.
		PublicKey: PublicKey{group: group.ForgetOrder()},
		group:     group,
	}
	if err := sk.precompute(); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to precompute secret key values")
	}
	return sk, nil
}

// SecretKey is a Paillier private key. It embeds the PublicKey and additionally
// holds the modulus factorisation (the known-order group) and precomputed CRT
// constants. The factorisation is secret — it allows decryption of every ciphertext
// and recovery of the encryption nonce (Open). Use Public to obtain the shareable
// public key.
type SecretKey struct {
	PublicKey

	group *znstar.PaillierGroupKnownOrder

	nonceGroup  *znstar.RSAGroupKnownOrder
	negQInvModP numct.Nat
	negPInvModQ numct.Nat
	qInvModPhiP numct.Nat
	pInvModPhiQ numct.Nat
}

type secretKeyDTO struct {
	Group *znstar.PaillierGroupKnownOrder `cbor:"group"`
}

// Public returns the public key (the modulus N only), dropping the secret
// factorisation so it can be shared.
func (sk *SecretKey) Public() *PublicKey {
	return &PublicKey{
		group: sk.group.ForgetOrder(),
	}
}

// Decrypt recovers the plaintext m ∈ Z_N from a ciphertext using the secret
// factorisation, via the CRT / Fermat-quotient decryption (the Jost et al.
// optimisation). It requires the decryption trapdoor and validates that the
// ciphertext lies in Z*_{N²}.
func (sk *SecretKey) Decrypt(ciphertext *Ciphertext) (*Plaintext, error) {
	if ciphertext == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext must not be nil")
	}
	if !sk.group.ForgetOrder().Contains(ciphertext.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("ciphertext must be in ciphertext group")
	}
	// mp = -L_p(c)*q^-1 mod p && mq = -L_q(c)*p^-1 mod q
	var lp, lq numct.Nat
	sk.group.Arithmetic().FermatQuotient(&lp, &lq, ciphertext.Value().Value().Value())
	var mp, mq numct.Nat
	sk.group.Arithmetic().P.Factor.ModMul(&mp, &lp, &sk.negQInvModP)
	sk.group.Arithmetic().Q.Factor.ModMul(&mq, &lq, &sk.negPInvModQ)
	m, err := num.NewUintGivenModulus(
		sk.group.Arithmetic().CrtModN.Params.Recombine(&mp, &mq),
		sk.group.Arithmetic().CrtModN.Modulus(),
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create plaintext from decrypted value")
	}
	return &Plaintext{p: m}, nil
}

// Open recovers BOTH the plaintext m and the encryption nonce r from a ciphertext
// using the trapdoor: it decrypts m, computes r^N = c·(1+N)^{−m} mod N², then takes
// the N-th root via CRT. This is the OpeningKey capability — possessing it lets the
// holder fully de-randomise any ciphertext, which is exactly what makes
// encryption-based commitments extractable.
func (sk *SecretKey) Open(ciphertext *Ciphertext) (*Plaintext, *Nonce, error) {
	// c = (1+N)^m * r^N mod N^2 =>
	// r^N mod n^2 = c * (1+N)^(-m) mod N^2 = c * (1-mN) mod N^2 = r^pq mod N^2
	// We do CRT, for p (q is similar):
	// p = 1 mod (p-1) => r^N mod p = r^q mod p => r mod p = (r^q)^(q^-1 mod (p-1)) mod p
	if ciphertext == nil {
		return nil, nil, encryption.ErrIsNil.WithMessage("ciphertext must not be nil")
	}
	m, err := sk.Decrypt(ciphertext)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not decrypt ciphertext")
	}

	// (1-mN) mod N^2
	var gMInv numct.Nat
	sk.group.Arithmetic().ModMul(&gMInv, m.p.Value(), sk.group.N().Value())
	sk.group.Arithmetic().Modulus().ModSub(&gMInv, numct.NatOne(), &gMInv)

	// y = r^N mod N^2 = c * (1-mN) mod N^2
	var y numct.Nat
	sk.group.Arithmetic().ModMul(&y, ciphertext.Value().Value().Value(), &gMInv)

	// rp = (y mod p)^(q^-1 mod (p-1)) mod p
	// rq = (y mod q)^(p^-1 mod (q-1)) mod q
	var rp, rq numct.Nat
	var eg errgroup.Group
	eg.Go(func() error {
		sk.group.Arithmetic().P.Factor.Mod(&rp, &y)
		sk.group.Arithmetic().P.Factor.ModExp(&rp, &rp, &sk.qInvModPhiP)
		return nil
	})
	eg.Go(func() error {
		sk.group.Arithmetic().Q.Factor.Mod(&rq, &y)
		sk.group.Arithmetic().Q.Factor.ModExp(&rq, &rq, &sk.pInvModPhiQ)
		return nil
	})
	if err := eg.Wait(); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not compute r mod p and q")
	}

	nonceValue, err := num.NPlus().FromNatCT(
		sk.group.Arithmetic().CrtModN.Params.Recombine(&rp, &rq),
	)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create nonce value from CRT recombination")
	}
	nonce, err := NewNonce(sk.group, nonceValue)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create nonce from nonce value")
	}
	return m, nonce, nil
}

// EncryptWithNonce encrypts under the embedded public parameters; identical in
// result to PublicKey.EncryptWithNonce, with the same fresh-secret-nonce
// requirement.
func (sk *SecretKey) EncryptWithNonce(p *Plaintext, n *Nonce) (*Ciphertext, error) {
	if p == nil || n == nil {
		return nil, encryption.ErrIsNil.WithMessage("plaintext and nonce must not be nil")
	}
	if !sk.PlaintextGroup().Contains(p.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("plaintext must be in plaintext group")
	}
	if !sk.NonceGroup().Contains(n.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("nonce must be in nonce group")
	}
	out, err := gift.Encrypt(sk, p, n)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not encrypt message with nonce")
	}
	return out, nil
}

// Representative encodes m as (1+N)^m mod N², the noiseless ciphertext; see
// PublicKey.Representative.
func (sk *SecretKey) Representative(p *Plaintext) (*Ciphertext, error) {
	if p == nil {
		return nil, encryption.ErrIsNil.WithMessage("plaintext must not be nil")
	}
	if !sk.PlaintextGroup().Contains(p.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("plaintext must be in plaintext group")
	}
	gm, err := sk.group.Representative(p.Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute representative")
	}
	return &Ciphertext{c: gm.ForgetOrder()}, nil
}

// IdentityNoise returns r^N mod N², an encryption of 0 with nonce r; see
// PublicKey.IdentityNoise.
func (sk *SecretKey) IdentityNoise(n *Nonce) (*Ciphertext, error) {
	if n == nil {
		return nil, encryption.ErrIsNil.WithMessage("nonce must not be nil")
	}
	if !sk.NonceGroup().Contains(n.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("nonce must be in nonce group")
	}
	embeddedNonce, err := sk.group.EmbedRSA(n.Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not embed nonce into group")
	}
	rn, err := sk.group.NthResidue(embeddedNonce)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute nth residue of embedded nonce")
	}
	return &Ciphertext{c: rn.ForgetOrder()}, nil
}

// NonceOp multiplies nonces in Z*_N using the known group order for efficiency; the
// result equals PublicKey.NonceOp.
func (sk *SecretKey) NonceOp(first, second *Nonce, rest ...*Nonce) (*Nonce, error) { //nolint:dupl // similar to CiphertextOp. Helper would be too complicated.
	if first == nil || second == nil {
		return nil, encryption.ErrIsNil.WithMessage("first and second nonce cannot be nil")
	}
	firstValue, err := first.Value().LearnOrder(sk.nonceGroup)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of first nonce value")
	}
	secondValue, err := second.Value().LearnOrder(sk.nonceGroup)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of second nonce value")
	}
	restValues, err := sliceutils.MapOrError(rest, func(w *Nonce) (*znstar.RSAGroupElementKnownOrder, error) {
		if utils.IsNil(w) {
			return nil, encryption.ErrIsNil.WithMessage("object must not be nil")
		}
		out, err := w.Value().LearnOrder(sk.nonceGroup)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not learn order of nonce value")
		}
		return out, nil
	})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid nonce in rest nonces")
	}
	outValue, err := algebrautils.OpValues(sk.nonceGroup, firstValue, secondValue, restValues...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine nonce values")
	}
	return &Nonce{r: outValue.ForgetOrder()}, nil
}

// NonceOpInv inverts a nonce in Z*_N using the known group order; see
// PublicKey.NonceOpInv.
func (sk *SecretKey) NonceOpInv(n *Nonce) (*Nonce, error) {
	if n == nil {
		return nil, encryption.ErrIsNil.WithMessage("nonce must not be nil")
	}
	if !sk.NonceGroup().Contains(n.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("nonce must be in nonce group")
	}
	value, err := n.Value().LearnOrder(sk.nonceGroup)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of nonce value")
	}
	return &Nonce{r: value.OpInv().ForgetOrder()}, nil
}

// NonceScalarOp raises a nonce to the integer scalar power in Z*_N using the known
// group order; see PublicKey.NonceScalarOp.
func (sk *SecretKey) NonceScalarOp(n *Nonce, scalar *num.Int) (*Nonce, error) {
	if n == nil || scalar == nil {
		return nil, encryption.ErrIsNil.WithMessage("nonce and scalar must not be nil")
	}
	if !sk.NonceGroup().Contains(n.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("nonce must be in nonce group")
	}
	value, err := n.Value().LearnOrder(sk.nonceGroup)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of nonce value")
	}
	return &Nonce{r: value.ScalarOp(scalar).ForgetOrder()}, nil
}

// CiphertextOp multiplies ciphertexts in Z*_{N²} using the known group order for
// efficiency; the result equals PublicKey.CiphertextOp.
func (sk *SecretKey) CiphertextOp(first, second *Ciphertext, rest ...*Ciphertext) (*Ciphertext, error) { //nolint:dupl // similar to NonceOp. Helper would be too complicated.
	if first == nil || second == nil {
		return nil, encryption.ErrIsNil.WithMessage("first and second ciphertext cannot be nil")
	}
	firstValue, err := first.Value().LearnOrder(sk.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of first ciphertext value")
	}
	secondValue, err := second.Value().LearnOrder(sk.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of second ciphertext value")
	}
	restValues, err := sliceutils.MapOrError(rest, func(w *Ciphertext) (*znstar.PaillierGroupElementKnownOrder, error) {
		if utils.IsNil(w) {
			return nil, encryption.ErrIsNil.WithMessage("object must not be nil")
		}
		out, err := w.Value().LearnOrder(sk.group)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not learn order of ciphertext value")
		}
		return out, nil
	})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid ciphertext in rest ciphertexts")
	}
	outValue, err := algebrautils.OpValues(sk.group, firstValue, secondValue, restValues...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine ciphertext values")
	}
	return &Ciphertext{c: outValue.ForgetOrder()}, nil
}

// CiphertextOpInv inverts a ciphertext in Z*_{N²} using the known group order; see
// PublicKey.CiphertextOpInv.
func (sk *SecretKey) CiphertextOpInv(c *Ciphertext) (*Ciphertext, error) {
	if c == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext must not be nil")
	}
	if !sk.group.ForgetOrder().Contains(c.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("ciphertext must be in ciphertext group")
	}
	value, err := c.Value().LearnOrder(sk.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of ciphertext value")
	}
	return &Ciphertext{c: value.OpInv().ForgetOrder()}, nil
}

// CiphertextScalarOp raises a ciphertext to the integer scalar in Z*_{N²} using the
// known group order; see PublicKey.CiphertextScalarOp.
func (sk *SecretKey) CiphertextScalarOp(c *Ciphertext, scalar *num.Int) (*Ciphertext, error) {
	if c == nil || scalar == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext and scalar must not be nil")
	}
	if !sk.group.ForgetOrder().Contains(c.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("ciphertext must be in ciphertext group")
	}
	value, err := c.Value().LearnOrder(sk.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of ciphertext value")
	}
	return &Ciphertext{c: value.ScalarOp(scalar).ForgetOrder()}, nil
}

// ReRandomise blinds a ciphertext into a fresh, unlinkable encryption of the same
// plaintext using the secret-key fast path; see PublicKey.ReRandomise.
func (sk *SecretKey) ReRandomise(c *Ciphertext, n *Nonce) (*Ciphertext, error) {
	if c == nil || n == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext and nonce must not be nil")
	}
	if !sk.group.ForgetOrder().Contains(c.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("ciphertext must be in ciphertext group")
	}
	if !sk.NonceGroup().Contains(n.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("nonce must be in nonce group")
	}
	out, err := gift.ReRandomise(sk, c, n)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not re-randomise ciphertext")
	}
	return out, nil
}

// Shift adds m to the encrypted plaintext via Representative(m); see
// PublicKey.Shift. The randomness is unchanged.
func (sk *SecretKey) Shift(c *Ciphertext, m *Plaintext) (*Ciphertext, error) {
	if c == nil || m == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext and plaintext must not be nil")
	}
	if !sk.group.ForgetOrder().Contains(c.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("ciphertext must be in ciphertext group")
	}
	if !sk.PlaintextGroup().Contains(m.Value()) {
		return nil, encryption.ErrSubGroupMembership.WithMessage("plaintext must be in plaintext group")
	}
	out, err := gift.Shift(sk, c, m)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not shift ciphertext")
	}
	return out, nil
}

// Group returns the known-order Paillier group, which encodes the secret
// factorisation of N.
func (sk *SecretKey) Group() *znstar.PaillierGroupKnownOrder {
	return sk.group
}

func (sk *SecretKey) precompute() error {
	arith := sk.group.Arithmetic()
	p := arith.P.Factor
	q := arith.Q.Factor
	phiP := arith.P.PhiFactor
	phiQ := arith.Q.PhiFactor

	var eg errgroup.Group
	eg.Go(func() error {
		if ok := p.ModInv(&sk.negQInvModP, q.Nat()); ok == ct.False {
			return encryption.ErrFailed.WithMessage("could not compute modular inverse of q mod p, p and q might not be coprime")
		}
		p.ModNeg(&sk.negQInvModP, &sk.negQInvModP)
		return nil
	})
	eg.Go(func() error {
		if ok := q.ModInv(&sk.negPInvModQ, p.Nat()); ok == ct.False {
			return encryption.ErrFailed.WithMessage("could not compute modular inverse of p mod q, p and q might not be coprime")
		}
		q.ModNeg(&sk.negPInvModQ, &sk.negPInvModQ)
		return nil
	})
	eg.Go(func() error {
		if ok := phiP.ModInv(&sk.qInvModPhiP, q.Nat()); ok == ct.False {
			return encryption.ErrFailed.WithMessage("could not compute modular inverse of q mod phi(p), q and phi(p) might not be coprime")
		}
		return nil
	})
	eg.Go(func() error {
		if ok := phiQ.ModInv(&sk.pInvModPhiQ, p.Nat()); ok == ct.False {
			return encryption.ErrFailed.WithMessage("could not compute modular inverse of p mod phi(q), p and phi(q) might not be coprime")
		}
		return nil
	})
	eg.Go(func() error {
		pNatPlus, err := num.NPlus().FromNatCT(p.Nat())
		if err != nil {
			return errs.Wrap(err).WithMessage("could not convert p to NatPlus")
		}
		qNatPlus, err := num.NPlus().FromNatCT(q.Nat())
		if err != nil {
			return errs.Wrap(err).WithMessage("could not convert q to NatPlus")
		}
		sk.nonceGroup, err = znstar.NewRSAGroup(pNatPlus, qNatPlus)
		if err != nil {
			return errs.Wrap(err).WithMessage("could not create nonce group")
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		return errs.Wrap(err).WithMessage("could not create nonce group")
	}
	return nil
}

// Equal reports whether two secret keys share the same modulus and factorisation,
// treating nil as equal only to nil.
func (sk *SecretKey) Equal(other *SecretKey) bool {
	if sk == nil || other == nil {
		return sk == other
	}
	return sk.group.Equal(other.group)
}

// HashCode returns a non-cryptographic hash of the key (of N) for use as a map key.
func (sk *SecretKey) HashCode() base.HashCode {
	return sk.group.Modulus().HashCode()
}

// MarshalCBOR encodes the known-order Paillier group, i.e. the factorisation. The
// output contains the decryption trapdoor and must be protected as secret material.
func (sk *SecretKey) MarshalCBOR() ([]byte, error) {
	dto := &secretKeyDTO{
		Group: sk.group,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal secret key to CBOR")
	}
	return out, nil
}

// UnmarshalCBOR decodes a secret key (the factorised group) and re-validates it via
// NewSecretKey, re-deriving the CRT constants. This is a deserialization trust
// boundary handling secret material.
func (sk *SecretKey) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*secretKeyDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal secret key from CBOR")
	}
	skNew, err := NewSecretKey(dto.Group)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create secret key from unmarshaled group")
	}
	*sk = *skNew
	return nil
}
