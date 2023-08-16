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
// The encrypted values are represented as big.Int and are serializable. This module also provides
// JSON serialisation for the PublicKey and the SecretKey.
package paillier

import (
	"encoding/json"
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/core"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

type (
	// PublicKey is a Paillier public key: N = P*Q; for safe primes P,Q.
	PublicKey struct {
		N  *big.Int // N = PQ
		N2 *big.Int // N² computed and cached to prevent re-computation.
	}

	// PublicKeyJson encapsulates the data that is serialised to JSON.
	// It is used internally and not for external use. Public so other pieces
	// can use for serialisation.
	PublicKeyJson struct {
		N *big.Int
	}

	// SecretKey is a Paillier secret key.
	SecretKey struct {
		PublicKey
		Lambda  *big.Int // Lcm(P - 1, Q - 1)
		Totient *big.Int // Euler's totient: (P - 1) * (Q - 1)
		U       *big.Int // L((N + 1)^λ(N) mod N²)−1 mod N
	}

	// SecretKeyJson encapsulates the data that is serialised to JSON.
	// It is used internally and not for external use. Public so other pieces
	// can use for serialisation.
	SecretKeyJson struct {
		N, Lambda, Totient, U *big.Int
	}

	// CipherText in Pailler's cryptosystem: a value $c \in Z_{N²}$ .
	CipherText *big.Int
)

// NewKeys generates Paillier keys with `bits` sized safe primes.
func NewKeys(bits uint) (*PublicKey, *SecretKey, error) {
	publicKey, secretKey, err := keyGenerator(core.GenerateSafePrime, bits)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot generate keys pair")
	}

	return publicKey, secretKey, nil
}

func NewKeysWithSafePrimeGenerator(genSafePrime func(uint) (*big.Int, error), bits uint) (*PublicKey, *SecretKey, error) {
	publicKey, secretKey, err := keyGenerator(genSafePrime, bits)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot generate keys pair")
	}

	return publicKey, secretKey, nil
}

// keyGenerator generates Paillier keys with `bits` sized safe primes using function
// `genSafePrime` to generate the safe primes.
func keyGenerator(genSafePrime func(uint) (*big.Int, error), bits uint) (*PublicKey, *SecretKey, error) {
	values := make(chan *big.Int, 2)
	errors := make(chan error, 2)

	var p, q *big.Int

	for p == q {
		for range []int{1, 2} {
			go func() {
				value, err := genSafePrime(bits)
				values <- value
				errors <- err
			}()
		}

		for _, err := range []error{<-errors, <-errors} {
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot generate same primes")
			}
		}

		p, q = <-values, <-values
	}

	// Assemble the secret/public key pair.
	sk, err := NewSecretKey(p, q)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot assemble secret/public key pair")
	}
	return &sk.PublicKey, sk, nil
}

// NewSecretKey computes intermediate values based on safe primes p, q.
func NewSecretKey(p, q *big.Int) (*SecretKey, error) {
	if p == nil || q == nil {
		return nil, errs.NewIsNil("p or q is nil")
	}
	// Pre-compute necessary values.
	pMinusOne := new(big.Int).Sub(p, core.One) // P - 1
	qMinusOne := new(big.Int).Sub(q, core.One) // Q - 1
	n := new(big.Int).Mul(p, q)                // N = PQ
	nSquared := new(big.Int).Mul(n, n)         // N²
	lambda, err := Lcm(pMinusOne, qMinusOne)   // λ(N) = Lcm(P-1, Q-1)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate least common multiple of p and q")
	}
	totient := new(big.Int).Mul(pMinusOne, qMinusOne) // 𝝋(N) = (P-1)(Q-1)
	publicKey := PublicKey{
		N:  n,
		N2: nSquared,
	}

	// (N+1)^λ(N) mod N²
	t := new(big.Int).Add(n, core.One)
	t.Exp(t, lambda, nSquared)

	// L((N+1)^λ(N) mod N²)
	u, err := publicKey.L(t)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot calculate L")
	}
	// L((N+1)^λ(N) mod N²)^-1 mod N
	u.ModInverse(u, n)

	return &SecretKey{publicKey, lambda, totient, u}, nil
}

// MarshalJSON converts the public key into json format.
func (publicKey *PublicKey) MarshalJSON() ([]byte, error) {
	data := PublicKeyJson{publicKey.N}
	marshalled, err := json.Marshal(data)
	if err != nil {
		return nil, errs.WrapSerializationFailed(err, "json marshal failed")
	}
	return marshalled, nil
}

// UnmarshalJSON converts the json data into this public key.
func (publicKey *PublicKey) UnmarshalJSON(bytes []byte) error {
	data := new(PublicKeyJson)
	if err := json.Unmarshal(bytes, data); err != nil {
		return errs.WrapDeserializationFailed(err, "cannot deserialize PublicKey")
	}
	if data.N == nil {
		return errs.NewIsNil("n is nil")
	}
	publicKey.N = data.N
	publicKey.N2 = new(big.Int).Mul(data.N, data.N)
	return nil
}

// Lcm calculates the least common multiple.
func Lcm(x, y *big.Int) (*big.Int, error) {
	if x == nil || y == nil {
		return nil, errs.NewIsNil("p or q is nil")
	}
	gcd := new(big.Int).GCD(nil, nil, x, y)
	if core.ConstantTimeEq(gcd, core.Zero) {
		return core.Zero, nil
	}
	// Compute least common multiple: https://en.wikipedia.org/wiki/Least_common_multiple#Calculation .
	b := new(big.Int)
	return b.Abs(b.Mul(b.Div(x, gcd), y)), nil
}

// L computes a residuosity class of n^2: (x - 1) / n.
// Where it is the quotient x - 1 divided by n not modular multiplication of x - 1 times
// the modular multiplicative inverse of n. The function name comes from [P99].
func (publicKey *PublicKey) L(x *big.Int) (*big.Int, error) {
	if x == nil {
		return nil, errs.NewIsNil("x is nil")
	}

	if core.ConstantTimeEq(publicKey.N, core.Zero) {
		return nil, errs.NewIsZero("n cannot be zero")
	}

	// Ensure x = 1 mod N
	if !core.ConstantTimeEq(new(big.Int).Mod(x, publicKey.N), core.One) {
		return nil, errs.NewFailed("invalid residue, should be 1")
	}

	// Ensure x ∈ Z_N²
	if err := core.In(x, publicKey.N2); err != nil {
		return nil, errs.NewFailed("invalid value of x")
	}

	// (x - 1) / n
	b := new(big.Int).Sub(x, core.One)
	return b.Div(b, publicKey.N), nil
}

// NewPublicKey initialises a Paillier public key with a given n.
func NewPublicKey(n *big.Int) (*PublicKey, error) {
	if n == nil {
		return nil, errs.NewIsNil("n is nil")
	}
	return &PublicKey{
		N:  n,
		N2: new(big.Int).Mul(n, n), // Compute and cache N²
	}, nil
}

// Add combines two Paillier cipher texts.
func (publicKey *PublicKey) Add(lhsCipherText, rhsCipherText CipherText) (CipherText, error) {
	if lhsCipherText == nil || rhsCipherText == nil {
		return nil, errs.NewIsNil("one of the cipher texts in nil")
	}

	// Ensure lhsCipherText, rhsCipherText ∈ Z_N²
	if err := core.In(lhsCipherText, publicKey.N2); err != nil {
		return nil, errs.NewIsNil("lhs is nil")
	}
	if err := core.In(rhsCipherText, publicKey.N2); err != nil {
		return nil, errs.NewIsNil("rhs is nil")
	}

	ctxt, err := core.Mul(lhsCipherText, rhsCipherText, publicKey.N2)
	if err != nil {
		return nil, errs.WrapFailed(err, "multiplication failed")
	}
	return ctxt, nil
}

// SubPlain subtract homomorphically plain integer from cipher text.
func (publicKey *PublicKey) SubPlain(lhsCipherText, rhsPlain *big.Int) (CipherText, error) {
	if lhsCipherText == nil || rhsPlain == nil {
		return nil, errs.NewIsNil("one of the cipher texts in nil")
	}
	y := new(big.Int).Sub(publicKey.N, rhsPlain)

	// Ensure lhsCipherText ∈ Z_N², y ∈ Z_N
	if err := core.In(lhsCipherText, publicKey.N2); err != nil {
		return nil, errs.NewIsNil("lhs is nil")
	}
	if err := core.In(y, publicKey.N); err != nil {
		return nil, errs.NewIsNil("rhs is nil")
	}

	g := new(big.Int).Add(publicKey.N, core.One)
	rhs := new(big.Int).Exp(g, y, publicKey.N2)
	ctxt, err := core.Mul(lhsCipherText, rhs, publicKey.N2)
	if err != nil {
		return nil, errs.WrapFailed(err, "multiplication failed")
	}
	return ctxt, nil
}

// Mul is equivalent to adding two Paillier exponents.
func (publicKey *PublicKey) Mul(factor *big.Int, cipherText CipherText) (CipherText, error) {
	if factor == nil || cipherText == nil {
		return nil, errs.NewIsNil("factor or cipherText is nil")
	}

	// Ensure factor ∈ Z_N
	err := core.In(factor, publicKey.N)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid factor")
	}
	// Ensure cipherText ∈ Z_N²
	err = core.In(cipherText, publicKey.N2)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid cipherText")
	}

	return new(big.Int).Exp(cipherText, factor, publicKey.N2), nil
}

// Encrypt produces a ciphertext on input message.
func (publicKey *PublicKey) Encrypt(message *big.Int) (CipherText, *big.Int, error) {
	// generate a nonce: r \in Z**_N that r and N are coprime
	var r *big.Int
	for {
		rand, err := core.Rand(publicKey.N)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot generate nonce")
		}
		if new(big.Int).GCD(nil, nil, rand, publicKey.N).Cmp(core.One) != 0 {
			continue
		}
		r = rand
		break
	}

	// Generate and return the ciphertext
	cipherText, err := publicKey.EncryptWithNonce(message, r)
	return cipherText, r, err
}

// EncryptWithNonce produces a ciphertext on input a message and nonce.
func (publicKey *PublicKey) EncryptWithNonce(message, r *big.Int) (CipherText, error) {
	if message == nil || r == nil {
		return nil, errs.NewIsNil("message or nonce is nil")
	}

	// Ensure message ∈ Z_N
	if err := core.In(message, publicKey.N); err != nil {
		return nil, errs.NewInvalidArgument("invalid message")
	}

	// Ensure r ∈ Z^*_N: we use the method proved in docs/[EL20]
	// ensure r ∈ Z^_N-{0}
	if err := core.In(r, publicKey.N); err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid nonce")
	}
	if core.ConstantTimeEq(r, core.Zero) {
		return nil, errs.NewIsZero("nonce is zero")
	}

	// Compute the ciphertext components: alpha, beta
	// alpha = (N+1)^m (mod N²)
	alpha := new(big.Int).Add(publicKey.N, core.One)
	alpha.Exp(alpha, message, publicKey.N2)
	beta := new(big.Int).Exp(r, publicKey.N, publicKey.N2) // beta = r^N (mod N²)

	// ciphertext = alpha*beta = (N+1)^m * r^N  (mod N²)
	cipherText, err := core.Mul(alpha, beta, publicKey.N2)
	if err != nil {
		return nil, errs.WrapFailed(err, "multiplication failed")
	}
	return cipherText, nil
}

// Decrypt is the reverse operation of Encrypt.
func (secretKey *SecretKey) Decrypt(cipherText CipherText) (*big.Int, error) {
	if cipherText == nil {
		return nil, errs.NewIsNil("cipherText is nil")
	}

	// Ensure C ∈ Z_N²
	if err := core.In(cipherText, secretKey.N2); err != nil {
		return nil, errs.WrapInvalidArgument(err, "cipherText is invalid")
	}

	// Compute the msg in components
	// alpha ≡ cipherText^{λ(N)} mod N²
	alpha := new(big.Int).Exp(cipherText, secretKey.Lambda, secretKey.N2)

	// l = L(alpha, N)
	ell, err := secretKey.L(alpha)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute L")
	}

	// Compute the msg
	// message ≡ lu = L(alpha)*u = L(cipherText^{λ(N)})*u	mod N
	message, err := core.Mul(ell, secretKey.U, secretKey.N)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute message")
	}
	return message, nil
}

// MarshalJSON converts the secret key into json format.
func (secretKey *SecretKey) MarshalJSON() ([]byte, error) {
	data := SecretKeyJson{
		secretKey.N,
		secretKey.Lambda,
		secretKey.Totient,
		secretKey.U,
	}

	marshalled, err := json.Marshal(data)
	if err != nil {
		return nil, errs.WrapFailed(err, "json marshalling failed")
	}
	return marshalled, nil
}

// UnmarshalJSON converts the json data into this secret key.
func (secretKey *SecretKey) UnmarshalJSON(bytes []byte) error {
	data := new(SecretKeyJson)
	if err := json.Unmarshal(bytes, data); err != nil {
		return errs.WrapDeserializationFailed(err, "cannot deserialize secret key")
	}

	if data.N != nil {
		secretKey.N = data.N
		secretKey.N2 = new(big.Int).Mul(data.N, data.N)
	}
	secretKey.U = data.U
	secretKey.Totient = data.Totient
	secretKey.Lambda = data.Lambda
	return nil
}
