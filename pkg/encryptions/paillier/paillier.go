package paillier

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/primes"
)

var natOne = new(saferith.Nat).SetUint64(1).Resize(1)

type PlainText = saferith.Nat

type CipherText struct {
	C *saferith.Nat
}

func (c *CipherText) Validate(pk *PublicKey) error {
	nnMod := pk.GetNNModulus()
	if c == nil || c.C == nil || c.C.EqZero() == 1 || c.C.IsUnit(nnMod) != 1 {
		return errs.NewValidation("invalid cipher text")
	}

	_, _, less := c.C.Cmp(nnMod.Nat())
	if less != 1 {
		return errs.NewValidation("invalid cipher text")
	}

	return nil
}

func KeyGenWithPrimeGenerator(bits int, prng io.Reader, primeGen func(bits int, prng io.Reader) (p, q *saferith.Nat, err error)) (*PublicKey, *SecretKey, error) {
	p, q, err := primeGen(bits, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "keygen failed")
	}

func (publicKey *PublicKey) EncryptManyWithNonce(messages, rs []*saferith.Nat) ([]*CipherText, error) {
	if len(messages) != len(rs) {
		return nil, errs.NewIsNil("message or nonce mismatch")
	}

	// Ensure message ∈ Z_N
	for _, message := range messages {
		if _, _, ok := message.CmpMod(publicKey.N); ok == 0 {
			return nil, errs.NewArgument("invalid message")
		}
	}

	// Ensure r ∈ Z^*_N: we use the method proved in docs/[EL20]
	// ensure r ∈ Z^_N-{0}
	for _, r := range rs {
		if _, _, ok := r.CmpMod(publicKey.N); ok == 0 {
			return nil, errs.NewArgument("invalid nonce")
		}
		if r.IsUnit(publicKey.N) != 1 {
			return nil, errs.NewArgument("invalid nonce")
		}
		if r.EqZero() != 0 {
			return nil, errs.NewIsZero("nonce is zero")
		}
	}

	one := new(saferith.Nat).SetUint64(1)
	g := new(saferith.Nat).Add(publicKey.N.Nat(), one, publicKey.N.BitLen()+1)

	// Compute the ciphertext components: alpha, beta
	// alpha = (N+1)^m (mod N²)
	alphas := bignum.FastFixedBaseMultiExp(g, messages, publicKey.N2.Nat())
	betas := bignum.FastFixedExponentMultiExp(rs, publicKey.N.Nat(), publicKey.N2.Nat())

	cs := make([]*CipherText, len(messages))
	for i := range messages {
		cs[i] = &CipherText{C: new(saferith.Nat).ModMul(alphas[i], betas[i], publicKey.N2)}
	}

	return cs, nil
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
	alpha := bignum.FastExp(cipherText.C, decryptor.secretKey.Lambda, decryptor.secretKey.N2.Nat())

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
		return nil, nil, errs.WrapFailed(err, "keygen failed")
	}

	return &sk.PublicKey, sk, nil
}

func KeyGen(bits int, prng io.Reader) (*PublicKey, *SecretKey, error) {
	return KeyGenWithPrimeGenerator(bits, prng, primes.GeneratePrimePair)
}
