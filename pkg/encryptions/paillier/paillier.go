// Package paillier contains Paillier's cryptosystem (1999) [P99].
// Public-Key Cryptosystems Based on Composite Degree Residuosity Class.
// http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.112.4035&rep=rep1&type=pdf
// All routines here from pseudocode §2.5. Fig 1: The Paillier Cryptosystem.
//
// This module provides APIs for:
//
//   - generating a safe keypair,
//   - encryption and decryption,
//   - adding two encrypted values, Enc(a) and Enc(b), and obtaining Enc(a + b), and
//   - multiplying a plain value, a, and an encrypted value Enc(b), and obtaining Enc(a * b).
//
// The encrypted values are represented as saferith.Nat and are serializable. This module also provides
// JSON serialisation for the PublicKey and the SecretKey.
package paillier

import (
	crand "crypto/rand"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/primes"
)

type (
	// PublicKey is a Paillier public key: N = P*Q; for safe primes P,Q.
	PublicKey struct {
		N  *saferith.Modulus // N = PQ
		N2 *saferith.Modulus // N² computed and cached to prevent re-computation.
	}

	// SecretKey is a Paillier secret key.
	SecretKey struct {
		PublicKey
		Lambda  *saferith.Nat // Lcm(P - 1, Q - 1)
		Totient *saferith.Nat // Euler's totient: (P - 1) * (Q - 1)
		U       *saferith.Nat // L((N + 1)^λ(N) mod N²)−1 mod N
	}

	// CipherText in Pailler's cryptosystem: a value $c \in Z_{N²}$ .
	CipherText struct {
		C *saferith.Nat
	}

	Decryptor struct {
		secretKey *SecretKey
	}
)

// NewKeys generates Paillier keys with `bits` sized primes.
func NewKeys(bits uint) (*PublicKey, *SecretKey, error) {
	publicKey, secretKey, err := keyGenerator(primes.GeneratePrimePair, bits)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot generate keys pair")
	}

	return publicKey, secretKey, nil
}

func NewKeysWithPrimePairGenerator(primePairGen func(uint) (*saferith.Nat, *saferith.Nat, error), bits uint) (*PublicKey, *SecretKey, error) {
	if primePairGen == nil {
		return nil, nil, errs.NewIsNil("primePairGen is nil")
	}
	publicKey, secretKey, err := keyGenerator(primePairGen, bits)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot generate keys pair")
	}

	return publicKey, secretKey, nil
}

// NewSecretKey computes intermediate values based on safe primes p, q.
func NewSecretKey(p, q *saferith.Nat) (*SecretKey, error) {
	if p == nil || q == nil {
		return nil, errs.NewIsNil("p or q is nil")
	}
	if (p.EqZero() | q.EqZero()) != 0 {
		return nil, errs.NewIsZero("p or q is zero")
	}

	// Pre-compute necessary values.
	one := new(saferith.Nat).SetUint64(1)
	pMinusOne := new(saferith.Nat).Sub(p, one, p.AnnouncedLen())        // P - 1
	qMinusOne := new(saferith.Nat).Sub(q, one, p.AnnouncedLen())        // Q - 1
	n := new(saferith.Nat).Mul(p, q, p.AnnouncedLen()+q.AnnouncedLen()) // N = PQ
	nSquared := new(saferith.Nat).Mul(n, n, 2*n.AnnouncedLen())         // N²
	lambda, err := Lcm(pMinusOne, qMinusOne)                            // λ(N) = Lcm(P-1, Q-1)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate least common multiple of p and q")
	}
	totient := new(saferith.Nat).Mul(pMinusOne, qMinusOne, p.AnnouncedLen()+q.AnnouncedLen()) // 𝝋(N) = (P-1)(Q-1)
	publicKey := PublicKey{
		N:  saferith.ModulusFromNat(n),
		N2: saferith.ModulusFromNat(nSquared),
	}

	// (N+1)^λ(N) mod N²
	t := new(saferith.Nat).Add(n, one, n.AnnouncedLen())
	t = new(saferith.Nat).Exp(t, lambda, publicKey.N2)

	// L((N+1)^λ(N) mod N²)
	u, err := publicKey.L(t)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate L")
	}
	// L((N+1)^λ(N) mod N²)^-1 mod N
	u = new(saferith.Nat).ModInverse(u, publicKey.N)

	return &SecretKey{publicKey, lambda, totient, u}, nil
}

// NewPublicKey initialises a Paillier public key with a given n.
func NewPublicKey(n *saferith.Nat) (*PublicKey, error) {
	if n == nil {
		return nil, errs.NewIsNil("n is nil")
	}
	return &PublicKey{
		N:  saferith.ModulusFromNat(n),
		N2: saferith.ModulusFromNat(new(saferith.Nat).Mul(n, n, 2*n.AnnouncedLen())), // Compute and cache N²
	}, nil
}

func NewDecryptor(secretKey *SecretKey) (*Decryptor, error) {
	if secretKey == nil {
		return nil, errs.NewIsNil("secretKey is nil")
	}
	return &Decryptor{secretKey: secretKey}, nil
}

func (decryptor *Decryptor) Validate(recomputeCached bool) error {
	if decryptor == nil {
		return errs.NewIsNil("nil receiver")
	}
	if err := decryptor.secretKey.Validate(recomputeCached); err != nil {
		return errs.WrapValidation(err, "secret key")
	}
	return nil
}

func (secretKey *SecretKey) Validate(recomputeCached bool) error {
	if secretKey == nil {
		return errs.NewIsNil("nil receiver")
	}
	if err := secretKey.PublicKey.Validate(recomputeCached); err != nil {
		return errs.WrapValidation(err, "public key")
	}
	if secretKey.Lambda == nil {
		return errs.NewIsNil("lambda")
	}
	if secretKey.Totient == nil {
		return errs.NewIsNil("totient")
	}
	if secretKey.U == nil {
		return errs.NewIsNil("U")
	}
	return nil
}

func (publicKey *PublicKey) Validate(recomputeCached bool) error {
	if publicKey == nil {
		return errs.NewIsNil("nil receiver")
	}
	n := publicKey.N
	n2 := publicKey.N2
	if n == nil {
		return errs.NewIsNil("N")
	}
	if n2 == nil {
		return errs.NewIsNil("N2")
	}
	if recomputeCached {
		nSquared := new(saferith.Nat).Mul(n.Nat(), n.Nat(), 2*n.Nat().AnnouncedLen())
		if nSquared.Eq(n2.Nat()) != 1 {
			return errs.NewFailed("invalid N2 cache")
		}
	}
	return nil
}

func (ct *CipherText) Validate(publicKey *PublicKey) error {
	if ct == nil {
		return errs.NewIsNil("nil receiver")
	}
	if ct.C == nil {
		return errs.NewIsNil("C")
	}
	if ct.C.EqZero() == 1 {
		return errs.NewIsZero("ciphertext")
	}
	if _, _, ok := ct.C.CmpMod(publicKey.N2); ok == 0 {
		return errs.NewValue("ciphertext range")
	}
	return nil
}

// L computes a residuosity class of n^2: (x - 1) / n.
// Where it is the quotient x - 1 divided by n not modular multiplication of x - 1 times
// the modular multiplicative inverse of n. The function name comes from [P99].
func (publicKey *PublicKey) L(x *saferith.Nat) (*saferith.Nat, error) {
	if x == nil {
		return nil, errs.NewIsNil("x is nil")
	}

	if ok := publicKey.N.Nat().EqZero(); ok != 0 {
		return nil, errs.NewIsZero("n cannot be zero")
	}

	// Ensure x = 1 mod N
	one := new(saferith.Nat).SetUint64(1)
	if new(saferith.Nat).Mod(x, publicKey.N).Eq(one) == 0 {
		return nil, errs.NewFailed("invalid residue, should be 1")
	}

	// Ensure x ∈ Z_N²
	if _, _, ok := x.CmpMod(publicKey.N2); ok == 0 {
		return nil, errs.NewFailed("invalid value of x")
	}

	// (x - 1) / n
	b := new(saferith.Nat).Sub(x, one, x.AnnouncedLen())
	return b.Div(b, publicKey.N, (b.AnnouncedLen()+1)/2), nil
}

// Add combines two Paillier cipher texts.
func (publicKey *PublicKey) Add(lhsCipherText, rhsCipherText *CipherText) (*CipherText, error) {
	if lhsCipherText == nil || rhsCipherText == nil || lhsCipherText.C == nil || rhsCipherText.C == nil {
		return nil, errs.NewIsNil("one of the cipher texts in nil")
	}

	// Ensure lhsCipherText, rhsCipherText ∈ Z_N²
	if err := lhsCipherText.Validate(publicKey); err != nil {
		return nil, errs.WrapArgument(err, "lhs")
	}
	if err := rhsCipherText.Validate(publicKey); err != nil {
		return nil, errs.WrapArgument(err, "rhs")
	}

	c := new(saferith.Nat).ModMul(lhsCipherText.C, rhsCipherText.C, publicKey.N2)
	return &CipherText{C: c}, nil
}

// SubPlain subtract homomorphically plain integer from cipher text.
func (publicKey *PublicKey) SubPlain(lhsCipherText *CipherText, rhsPlain *saferith.Nat) (*CipherText, error) {
	if lhsCipherText == nil || lhsCipherText.C == nil || rhsPlain == nil {
		return nil, errs.NewIsNil("one of the cipher texts in nil")
	}
	// Ensure lhsCipherText ∈ Z_N², rhsCipherText ∈ Z_N
	if _, _, ok := rhsPlain.CmpMod(publicKey.N); ok == 0 {
		return nil, errs.NewArgument("plaintext divisible by N")
	}
	if err := lhsCipherText.Validate(publicKey); err != nil {
		return nil, errs.WrapArgument(err, "cipher text")
	}

	one := new(saferith.Nat).SetUint64(1)
	y := new(saferith.Nat).ModNeg(rhsPlain, publicKey.N)
	g := new(saferith.Nat).Add(publicKey.N.Nat(), one, publicKey.N.BitLen())
	rhs := new(saferith.Nat).Exp(g, y, publicKey.N2)
	c := new(saferith.Nat).ModMul(lhsCipherText.C, rhs, publicKey.N2)
	return &CipherText{C: c}, nil
}

// Mul is equivalent to adding two Paillier exponents.
func (publicKey *PublicKey) Mul(factor *saferith.Nat, cipherText *CipherText) (*CipherText, error) {
	if factor == nil || cipherText == nil || cipherText.C == nil {
		return nil, errs.NewIsNil("factor or cipherText is nil")
	}

	// Ensure factor ∈ Z_N
	if _, _, ok := factor.CmpMod(publicKey.N); ok == 0 {
		return nil, errs.NewArgument("invalid factor")
	}
	// Ensure cipherText ∈ Z_N²
	if err := cipherText.Validate(publicKey); err != nil {
		return nil, errs.WrapArgument(err, "lhs")
	}

	c := new(saferith.Nat).Exp(cipherText.C, factor, publicKey.N2)
	return &CipherText{C: c}, nil
}

// Encrypt produces a ciphertext on input message (using big.Int to support gcd).
func (publicKey *PublicKey) Encrypt(message *saferith.Nat) (*CipherText, *saferith.Nat, error) {
	if publicKey.N == nil || publicKey.N2 == nil {
		return nil, nil, errs.NewIsNil("N is nil")
	}

	// generate a nonce: r \in Z**_N that r and N are coprime
	var nonce *big.Int
	for {
		nonceCandidate, err := crand.Int(crand.Reader, publicKey.N.Big())
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot generate nonce")
		}
		gcd := new(big.Int).GCD(nil, nil, nonceCandidate, publicKey.N.Big())
		if (gcd.Cmp(big.NewInt(1)) != 0) || (nonceCandidate.Cmp(big.NewInt(0)) == 0) {
			continue
		}
		nonce = nonceCandidate
		break
	}

	// Generate and return the ciphertext
	r := new(saferith.Nat).SetBig(nonce, publicKey.N.BitLen())
	cipherText, err := publicKey.EncryptWithNonce(message, r)
	if err != nil {
		return nil, nil, errs.NewFailed("encryption failed")
	}
	return cipherText, r, nil
}

// EncryptWithNonce produces a ciphertext on input a message and nonce.
func (publicKey *PublicKey) EncryptWithNonce(message, r *saferith.Nat) (*CipherText, error) {
	if message == nil || r == nil {
		return nil, errs.NewIsNil("message or nonce is nil")
	}

	// Ensure message ∈ Z_N
	if _, _, ok := message.CmpMod(publicKey.N); ok == 0 {
		return nil, errs.NewArgument("invalid message")
	}

	// Ensure r ∈ Z^*_N: we use the method proved in docs/[EL20]
	// ensure r ∈ Z^_N-{0}
	if _, _, ok := r.CmpMod(publicKey.N); ok == 0 {
		return nil, errs.NewArgument("invalid nonce")
	}
	if r.EqZero() != 0 {
		return nil, errs.NewIsZero("nonce is zero")
	}

	one := new(saferith.Nat).SetUint64(1)
	// Compute the ciphertext components: alpha, beta
	// alpha = (N+1)^m (mod N²)
	g := new(saferith.Nat).Add(publicKey.N.Nat(), one, publicKey.N.BitLen()+1)
	alpha := new(saferith.Nat).Exp(g, message, publicKey.N2)
	beta := new(saferith.Nat).Exp(r, publicKey.N.Nat(), publicKey.N2) // beta = r^N (mod N²)

	// ciphertext = alpha*beta = (N+1)^m * r^N  (mod N²)
	c := new(saferith.Nat).ModMul(alpha, beta, publicKey.N2)
	return &CipherText{C: c}, nil
}

// Decrypt is the reverse operation of Encrypt.
func (decryptor *Decryptor) Decrypt(cipherText *CipherText) (*saferith.Nat, error) {
	if cipherText == nil || cipherText.C == nil {
		return nil, errs.NewIsNil("cipherText is nil")
	}

	// Ensure C ∈ Z_N²
	_, _, isLess := cipherText.C.Cmp(decryptor.secretKey.N2.Nat())
	if isLess == 0 {
		return nil, errs.NewArgument("cipherText is invalid")
	}

	// Compute the msg in components
	// alpha ≡ cipherText^{λ(N)} mod N²
	alpha := new(saferith.Nat).Exp(cipherText.C, decryptor.secretKey.Lambda, decryptor.secretKey.N2)

	// l = L(alpha, N)
	ell, err := decryptor.secretKey.L(alpha)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute L")
	}

	// Compute the msg
	// message ≡ lu = L(alpha)*u = L(cipherText^{λ(N)})*u	mod N
	message := new(saferith.Nat).ModMul(ell, decryptor.secretKey.U, decryptor.secretKey.N)
	return message, nil
}

// Lcm calculates the least common multiple.
func Lcm(x, y *saferith.Nat) (*saferith.Nat, error) {
	if x == nil || y == nil {
		return nil, errs.NewIsNil("p or q is nil")
	}
	// fallback to big.Int

	xBig := x.Big()
	yBig := y.Big()
	gcd := new(big.Int).GCD(nil, nil, xBig, yBig)
	if gcd.Sign() == 0 {
		return new(saferith.Nat).SetUint64(0), nil
	}
	// Compute least common multiple: https://en.wikipedia.org/wiki/Least_common_multiple#Calculation .
	b := new(big.Int)
	lcm := b.Abs(b.Mul(b.Div(xBig, gcd), yBig))
	return new(saferith.Nat).SetBig(lcm, x.AnnouncedLen()+y.AnnouncedLen()), nil
}

// keyGenerator generates Paillier keys with `bits` sized safe primes using function
// `genSafePrime` to generate the safe primes.
func keyGenerator(primePairGen func(uint) (*saferith.Nat, *saferith.Nat, error), bits uint) (*PublicKey, *SecretKey, error) {
	p, q, err := primePairGen(bits)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot generate same primes")
	}

	// Assemble the secret/public key pair.
	sk, err := NewSecretKey(p, q)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot assemble secret/public key pair")
	}
	return &sk.PublicKey, sk, nil
}
