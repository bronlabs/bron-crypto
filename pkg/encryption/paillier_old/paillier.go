package paillier

// import (
// 	"io"
// 	"sync"

// 	"github.com/bronlabs/bron-crypto/pkg/base/ct"
// 	"github.com/bronlabs/bron-crypto/pkg/base/errs"
// 	"github.com/bronlabs/bron-crypto/pkg/base/nt"
// 	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
// 	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
// 	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
// )

// type KeyGenerator struct{}

// func (kg *KeyGenerator) Generate(prng io.Reader) (*PrivateKey, *PublicKey, error) {
// 	if prng == nil {
// 		return nil, nil, errs.NewIsNil("prng")
// 	}
// 	pNum, qNum, err := nt.GeneratePrimePair(num.NPlus(), 2048, prng)
// 	if err != nil {
// 		return nil, nil, errs.WrapFailed(err, "failed to generate prime pair")
// 	}
// 	p := pNum.Value()
// 	q := qNum.Value()

// 	// Verify that the primes are actually prime and coprime
// 	if p.IsProbablyPrime() != ct.True {
// 		return nil, nil, errs.NewFailed("p is not prime")
// 	}
// 	if q.IsProbablyPrime() != ct.True {
// 		return nil, nil, errs.NewFailed("q is not prime")
// 	}
// 	if p.Coprime(q) != ct.True {
// 		return nil, nil, errs.NewFailed("p and q are not coprime")
// 	}

// 	// Create OddPrimeSquareFactors which now correctly clones p and q internally
// 	exp, ok := modular.NewOddPrimeSquareFactors(p, q)
// 	if ok == ct.False {
// 		return nil, nil, errs.NewFailed("failed to create OddPrimeSquareFactors")
// 	}

// 	// Get lambda from OddPrimeSquareFactors
// 	lambda := exp.LambdaN

// 	// Compute μ = λ^(-1) mod n
// 	var mu numct.Nat
// 	if ok := exp.N.ModInv(&mu, lambda); ok != ct.True {
// 		return nil, nil, errs.NewFailed("failed to compute mu = λ^(-1) mod n")
// 	}

// 	var hp, hq numct.Nat
// 	exp.P.Factor.ModInv(&hp, exp.Q.Factor.Nat())
// 	exp.P.Factor.ModNeg(&hp, &hp)
// 	exp.Q.Factor.ModInv(&hq, exp.P.Factor.Nat())
// 	exp.Q.Factor.ModNeg(&hq, &hq)

// 	sk := &PrivateKey{
// 		M:      exp,
// 		Lambda: lambda,
// 		Mu:     &mu,
// 		N:      exp.N,
// 		NNat:   exp.N.Nat(),
// 		N2:     exp.N2,
// 		Hp:     &hp,
// 		Hq:     &hq,
// 	}
// 	pk := &PublicKey{NN: exp.N2, N: exp.N, NNat: exp.N.Nat()}
// 	return sk, pk, nil
// }

// type Encrypter struct{}

// func (e *Encrypter) Encrypt(plaintext *Plaintext, receiver *PublicKey, prng io.Reader) (*Ciphertext, *Nonce, error) {
// 	nonceValue, err := receiver.N.Random(prng)
// 	if err != nil {
// 		return nil, nil, errs.WrapRandomSample(err, "failed to generate nonce")
// 	}
// 	nonce := &Nonce{V: nonceValue}
// 	ciphertext, err := e.EncryptWithNonce(plaintext, receiver, nonce)
// 	if err != nil {
// 		return nil, nil, errs.WrapFailed(err, "failed to encrypt with nonce")
// 	}
// 	return ciphertext, nonce, nil
// }

// func (e *Encrypter) EncryptWithNonce(plaintext *Plaintext, receiver *PublicKey, nonce *Nonce) (*Ciphertext, error) {
// 	var rn numct.Nat
// 	rToN(&rn, receiver, nonce, false)

// 	phi := receiver.Phi(plaintext)

// 	// c = g^m * r^n mod n^2
// 	var out numct.Nat
// 	receiver.NN.ModMul(&out, phi, &rn)

// 	// Ensure the result is in range [0, n^2)
// 	receiver.NN.Mod(&out, &out)

// 	return &Ciphertext{V: &out}, nil
// }

// func (e *Encrypter) EncryptAdic(plaintext *Plaintext, receiver *PublicKey, prng io.Reader) (*Ciphertext, *Nonce, error) {
// 	nonceValue, err := receiver.N.Random(prng)
// 	if err != nil {
// 		return nil, nil, errs.WrapRandomSample(err, "failed to generate nonce")
// 	}
// 	nonce := &Nonce{V: nonceValue}
// 	ciphertext, err := e.EncryptWithNonceAdic(plaintext, receiver, nonce)
// 	if err != nil {
// 		return nil, nil, errs.WrapFailed(err, "failed to encrypt with nonce")
// 	}
// 	return ciphertext, nonce, nil
// }

// func (e *Encrypter) EncryptWithNonceAdic(plaintext *Plaintext, receiver *PublicKey, nonce *Nonce) (*Ciphertext, error) {
// 	var rn numct.Nat
// 	rToN(&rn, receiver, nonce, true)
// 	phi := receiver.Phi(plaintext)

// 	// c = g^m * r^n mod n^2
// 	var out numct.Nat
// 	receiver.NN.ModMul(&out, phi, &rn)

// 	// Ensure the result is in range [0, n^2)
// 	receiver.NN.Mod(&out, &out)

// 	return &Ciphertext{V: &out}, nil
// }

// type Decrypter struct {
// 	sk *PrivateKey
// }

// func (d *Decrypter) VanillaDecrypt(ciphertext *Ciphertext) (*Plaintext, error) {
// 	// Compute c^λ mod n²
// 	var cLambda numct.Nat
// 	d.sk.N2.ModExp(&cLambda, ciphertext.V, d.sk.Lambda)

// 	// L(c^λ) = (c^λ - 1) / n
// 	cLambda.Decrement()
// 	var LcLambda numct.Nat
// 	if ok := LcLambda.DivCap(&cLambda, d.sk.NNat, -1); ok != ct.True {
// 		// This shouldn't happen if gcd check passed
// 		return nil, errs.NewFailed("failed to compute L(c^λ) = (c^λ - 1) / n")
// 	}

// 	// m = L(c^λ) * μ mod n
// 	var plaintext numct.Nat
// 	d.sk.N.ModMul(&plaintext, &LcLambda, d.sk.Mu)

// 	return &Plaintext{V: &plaintext}, nil
// }

// func (d *Decrypter) Decrypt(ciphertext *Ciphertext) (*Plaintext, error) {
// 	var mp, mq numct.Nat
// 	var wg sync.WaitGroup
// 	wg.Add(2)
// 	go func() {
// 		defer wg.Done()
// 		d.sk.M.P.Squared.ModExp(&mp, ciphertext.V, d.sk.M.P.PhiFactor.Nat())
// 		d.lp(&mp)
// 		d.sk.M.P.Factor.ModMul(&mp, &mp, d.sk.Hp)
// 	}()
// 	go func() {
// 		defer wg.Done()
// 		d.sk.M.Q.Squared.ModExp(&mq, ciphertext.V, d.sk.M.Q.PhiFactor.Nat())
// 		d.lq(&mq)
// 		d.sk.M.Q.Factor.ModMul(&mq, &mq, d.sk.Hq)
// 	}()
// 	wg.Wait()

// 	// CRT recombine into modulo n = p*q.
// 	return &Plaintext{V: d.sk.M.CrtModN.Recombine(&mp, &mq)}, nil
// }

// func (d *Decrypter) lp(x *numct.Nat) {
// 	d.sk.M.P.Squared.ModSub(x, x, numct.NatOne())
// 	d.sk.M.P.Factor.Quo(x, x)
// }

// func (d *Decrypter) lq(x *numct.Nat) {
// 	d.sk.M.Q.Squared.ModSub(x, x, numct.NatOne())
// 	d.sk.M.Q.Factor.Quo(x, x)
// }

// type PrivateKey struct {
// 	M      *modular.OddPrimeSquareFactors
// 	Lambda *numct.Nat // λ = lcm(p-1, q-1)
// 	Mu     *numct.Nat // μ = λ^(-1) mod n
// 	N      *numct.ModulusOdd
// 	NNat   *numct.Nat
// 	N2     *numct.ModulusOdd
// 	Hp     *numct.Nat
// 	Hq     *numct.Nat
// }

// func (sk *PrivateKey) PublicKey() *PublicKey {
// 	return &PublicKey{NN: sk.N2, N: sk.N, EXP: sk.M, NNat: sk.NNat}
// }

// type PublicKey struct {
// 	NN   numct.Modulus
// 	N    numct.Modulus
// 	NNat *numct.Nat
// 	EXP  *modular.OddPrimeSquareFactors
// }

// func (pk *PublicKey) Phi(plaintext *Plaintext) *numct.Nat {
// 	var out numct.Nat
// 	pk.NN.ModMul(&out, plaintext.V, pk.NNat)
// 	out.Increment()
// 	return &out
// }

// func (pk *PublicKey) PhiInto(out *numct.Nat, plaintext *Plaintext) {
// 	pk.NN.ModMul(out, plaintext.V, pk.NNat)
// 	out.Increment()
// }

// type Ciphertext struct {
// 	V *numct.Nat
// }

// type Nonce struct {
// 	V *numct.Nat
// }

// type Plaintext struct {
// 	V *numct.Nat
// }

// func rToN(out *numct.Nat, receiver *PublicKey, nonce *Nonce, adic bool) {
// 	if receiver.EXP != nil {
// 		if adic {
// 			receiver.EXP.ExpToN(out, nonce.V)
// 		} else {
// 			receiver.EXP.ModExp(out, nonce.V, receiver.NNat)
// 		}
// 	}
// 	// Compute r^n mod n²
// 	receiver.NN.ModExp(out, nonce.V, receiver.NNat)
// }
