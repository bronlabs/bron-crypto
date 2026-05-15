package paillier

import (
	"io"

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
	"github.com/bronlabs/errs-go/errs"
	"golang.org/x/sync/errgroup"
)

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

func NewSecretKey(group *znstar.PaillierGroupKnownOrder) (*SecretKey, error) {
	if group == nil {
		return nil, encryption.ErrIsNil.WithMessage("group must not be nil")
	}
	sk := &SecretKey{
		PublicKey: PublicKey{group: group.ForgetOrder()},
		group:     group,
	}
	if err := sk.precompute(); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to precompute secret key values")
	}
	return sk, nil
}

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

func (sk *SecretKey) Public() *PublicKey {
	return &PublicKey{
		group: sk.group.ForgetOrder(),
	}
}

func (sk *SecretKey) Decrypt(ciphertext *Ciphertext) (*Plaintext, error) {
	if ciphertext == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext must not be nil")
	}
	//mp = -L_p(c)*q^-1 mod p && mq = -L_q(c)*p^-1 mod q
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

func (sk *SecretKey) EncryptWithNonce(p *Plaintext, n *Nonce) (*Ciphertext, error) {
	if p == nil || n == nil {
		return nil, encryption.ErrIsNil.WithMessage("plaintext and nonce must not be nil")
	}
	out, err := gift.Encrypt(sk, p, n)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not encrypt message with nonce")
	}
	return out, nil
}

func (sk *SecretKey) Representative(p *Plaintext) (*Ciphertext, error) {
	if p == nil {
		return nil, encryption.ErrIsNil.WithMessage("plaintext must not be nil")
	}
	gm, err := sk.group.Representative(p.Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute representative")
	}
	return &Ciphertext{c: gm.ForgetOrder()}, nil
}

func (sk *SecretKey) IdentityNoise(n *Nonce) (*Ciphertext, error) {
	if n == nil {
		return nil, encryption.ErrIsNil.WithMessage("nonce must not be nil")
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

func (sk *SecretKey) NonceOp(first, second *Nonce, rest ...*Nonce) (*Nonce, error) {
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
	outValue, err := algebrautils.OpValues(firstValue, secondValue, restValues...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine nonce values")
	}
	return &Nonce{r: outValue.ForgetOrder()}, nil
}

func (sk *SecretKey) NonceOpInv(n *Nonce) (*Nonce, error) {
	if n == nil {
		return nil, encryption.ErrIsNil.WithMessage("nonce must not be nil")
	}
	value, err := n.Value().LearnOrder(sk.nonceGroup)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of nonce value")
	}
	return &Nonce{r: value.OpInv().ForgetOrder()}, nil
}

func (sk *SecretKey) NonceScalarOp(n *Nonce, scalar *num.Int) (*Nonce, error) {
	if n == nil || scalar == nil {
		return nil, encryption.ErrIsNil.WithMessage("nonce and scalar must not be nil")
	}
	value, err := n.Value().LearnOrder(sk.nonceGroup)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of nonce value")
	}
	return &Nonce{r: value.ScalarOp(scalar).ForgetOrder()}, nil
}

func (sk *SecretKey) CiphertextOp(first, second *Ciphertext, rest ...*Ciphertext) (*Ciphertext, error) {
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
	outValue, err := algebrautils.OpValues(firstValue, secondValue, restValues...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine ciphertext values")
	}
	return &Ciphertext{c: outValue.ForgetOrder()}, nil
}

func (sk *SecretKey) CiphertextOpInv(c *Ciphertext) (*Ciphertext, error) {
	if c == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext must not be nil")
	}
	value, err := c.Value().LearnOrder(sk.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of ciphertext value")
	}
	return &Ciphertext{c: value.OpInv().ForgetOrder()}, nil
}

func (sk *SecretKey) CiphertextScalarOp(c *Ciphertext, scalar *num.Int) (*Ciphertext, error) {
	if c == nil || scalar == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext and scalar must not be nil")
	}
	value, err := c.Value().LearnOrder(sk.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of ciphertext value")
	}
	return &Ciphertext{c: value.ScalarOp(scalar).ForgetOrder()}, nil
}

func (sk *SecretKey) ReRandomise(c *Ciphertext, n *Nonce) (*Ciphertext, error) {
	if c == nil || n == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext and nonce must not be nil")
	}
	out, err := gift.ReRandomise(sk, c, n)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not re-randomise ciphertext")
	}
	return out, nil
}

func (sk *SecretKey) Shift(c *Ciphertext, m *Plaintext) (*Ciphertext, error) {
	if c == nil || m == nil {
		return nil, encryption.ErrIsNil.WithMessage("ciphertext and plaintext must not be nil")
	}
	out, err := gift.Shift(sk, c, m)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not shift ciphertext")
	}
	return out, nil
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

func (sk *SecretKey) Equal(other *SecretKey) bool {
	if sk == nil || other == nil {
		return sk == other
	}
	return sk.group.Equal(other.group)
}

func (sk *SecretKey) HashCode() base.HashCode {
	return sk.group.Modulus().HashCode()
}

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
