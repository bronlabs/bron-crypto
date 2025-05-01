package castagnos08

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/groups"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
)

type G[C GElement[C, M], M ZkElement[M]] interface {
	groups.MultiplicativeGroup[C]
	groups.FiniteAbelianGroup[C, M]
	algebra.MultiplicativeModule[C, M]
	algebra.CyclicSemiGroup[C]

	Dlog(C) (M, error)
}

type GElement[C interface {
	groups.MultiplicativeGroupElement[C]
	groups.FiniteAbelianGroupElement[C, M]
	algebra.MultiplicativeModuleElement[C, M]
	algebra.CyclicSemiGroupElement[C]
}, M ZkElement[M]] interface {
	groups.MultiplicativeGroupElement[C]
	groups.FiniteAbelianGroupElement[C, M]
	algebra.MultiplicativeModuleElement[C, M]
	algebra.CyclicSemiGroupElement[C]
}

type Zk[E ZkElement[E]] algebra.ZnLike[E]
type ZkElement[E algebra.UintLike[E]] algebra.UintLike[E]

type GQuotient[N GQuotientElement[N]] interface {
	groups.MultiplicativeGroup[N]
	algebra.FiniteStructure[N]
}
type GQuotientElement[E groups.MultiplicativeGroupElement[E]] groups.MultiplicativeGroupElement[E]

type PrivateKey[C GElement[C, S], S ZkElement[S], N GQuotientElement[N]] struct {
	Lambda  S
	Mu      S
	Factors []S
	Public  *PublicKey[C, S, N]
}

type PublicKey[C GElement[C, M], M ZkElement[M], N GQuotientElement[N]] struct {
	G         G[C, M]
	Zk        Zk[M]
	GQuotient GQuotient[N]
	K         M
}

type EncrypterTrait[M ZkElement[M], C GElement[C, M], N GQuotientElement[N]] struct{}

func (e *EncrypterTrait[M, C, N]) EncryptWithNonce(plaintext M, receiver *PublicKey[C, M, N], nonce N, _ any) (C, error) {
	g := receiver.G.Generator()
	gm := g.ScalarExp(plaintext)
	rhoK := g.ScalarExp(receiver.K)
	c := gm.Mul(rhoK)
	return c, nil
}

func (e *EncrypterTrait[M, C, N]) Encrypt(plaintext M, receiver *PublicKey[C, M, N], prng types.PRNG, _ any) (C, N, error) {
	if prng == nil {
		return *new(C), *new(N), errs.NewIsNil("prng")
	}
	nonce, err := receiver.GQuotient.Random(prng)
	if err != nil {
		return *new(C), *new(N), errs.WrapRandomSample(err, "failed to generate nonce value")
	}
	ciphertext, err := e.EncryptWithNonce(plaintext, receiver, nonce, nil)
	if err != nil {
		return *new(C), *new(N), errs.WrapFailed(err, "failed to encrypt plaintext")
	}
	return ciphertext, nonce, nil
}

type DecrypterTrait[M ZkElement[M], C GElement[C, M], N GQuotientElement[N]] struct {
	Sk *PrivateKey[C, M, N]
}

func (d *DecrypterTrait[M, C, N]) Decrypt(ciphertext C, _ any) (M, error) {
	cLambda := ciphertext.ScalarExp(d.Sk.Lambda)
	LcLambda, err := d.Sk.Public.G.Dlog(cLambda)
	if err != nil {
		return *new(M), errs.WrapFailed(err, "failed to compute LcLambda")
	}
	m := LcLambda.Mul(d.Sk.Mu)
	return m, nil
}
