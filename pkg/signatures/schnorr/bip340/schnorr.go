package bip340

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/curveutils"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/merlin"
)

type PrivateKey struct {
	a curves.Scalar
	PublicKey
}

type PublicKey struct {
	Curve curves.Curve
	Y     curves.Point
}

type Signature struct {
	R curves.Scalar
	S curves.Scalar
}

const (
	AUX_SIZE = 32
	A_SIZE   = 32
)

var (
	auxHashLabel       = "BIP0340/aux"
	nonceHashLabel     = "BIP0340/nonce"
	challengeHashLabel = "BIP0340/challenge"
	tagHashFunc        = sha256.New
)

func (s *Signature) UnmarshalJSON(data []byte) error {
	var err error
	var parsed struct {
		R json.RawMessage
		S json.RawMessage
	}

	if err := json.Unmarshal(data, &parsed); err != nil {
		return errs.WrapDeserializationFailed(err, "couldn't extract C and S field from input")
	}

	s.R, err = curveutils.NewScalarFromJSON(parsed.R)
	if err != nil {
		return errs.WrapDeserializationFailed(err, "couldn't deserialize R")
	}
	s.S, err = curveutils.NewScalarFromJSON(parsed.S)
	if err != nil {
		return errs.WrapDeserializationFailed(err, "couldn't deserialize S")
	}
	return nil
}

type Signer struct {
	PublicKey  *PublicKey
	privateKey *PrivateKey
}

func NewSigner(cipherSuite *integration.CipherSuite, secret curves.Scalar) (*Signer, error) {
	if err := cipherSuite.Validate(); err != nil {
		return nil, errs.WrapInvalidArgument(err, "ciphersuite is invalid")
	}
	privateKey, err := KeyGen(cipherSuite.Curve, secret)
	if err != nil {
		return nil, errs.WrapFailed(err, "key generation failed")
	}
	if cipherSuite.Curve.Name() != k256.Name {
		return nil, errs.NewInvalidArgument("only secp256k1 is supported")
	}

	return &Signer{
		PublicKey:  &privateKey.PublicKey,
		privateKey: privateKey,
	}, nil
}

// Sign takes a message `m` and returns a signature using the private key of the
// `Signer` object.
func (s *Signer) Sign(m, aux []byte) (*Signature, error) {
	// 1. Let d' = int(sk)
	dPrime := s.privateKey.a
	// 2. Fail if d' = 0 or d' ≥ n
	if dPrime.IsZero() {
		return nil, errs.NewInvalidArgument("secret is invalid")
	}
	// 3. Let P = d'G
	P := s.PublicKey.Y
	// 4. Let d = d' if has_even_y(P), otherwise let d = n - d' .
	d := getEvenKey(dPrime, P)
	var kPrime curves.Scalar
	var err error
	if len(aux) == 0 {
		aux = make([]byte, AUX_SIZE)
	}
	hashedAux, err := taggedHash(auxHashLabel, aux)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to hash aux")
	}
	// 5. Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(a).
	t, err := bitstring.XorBytes(d.Bytes(), hashedAux)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to xor bytes")
	}
	// 6. Let rand = hashBIP0340/nonce(t || bytes(P) || m).
	// 7. Let k' = int(rand) mod n.
	hashedNonce, err := taggedHash(nonceHashLabel, bytes.Join([][]byte{t, P.ToAffineCompressed()[1:], m}, nil))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to hash nonce")
	}
	kPrime, err = s.PublicKey.Curve.Scalar().SetBytes(hashedNonce)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to unmarshal random bytes")
	}
	if kPrime.IsZero() { // 8. Fail if k' = 0.
		return nil, errs.NewFailed("k' is invalid")
	}
	// 9. Let R = k'⋅G.
	R := s.PublicKey.Curve.ScalarBaseMult(kPrime)
	// 10. Let k = k' if has_even_y(R), otherwise let k = n - k' .
	k := getEvenKey(kPrime, R)
	// 11. Let e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n.
	e, err := GenerateChallenge(s.PublicKey.Curve, R.ToAffineCompressed()[1:], P.ToAffineCompressed()[1:], m)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get e")
	}

	// 12. Let sig = bytes(R) || bytes((k + ed) mod n).
	// instead of merging into one byte slice, we store the values separately
	signatureR, err := s.PublicKey.Curve.Scalar().SetBytes(R.ToAffineCompressed()[1:])
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to marshal signature R")
	}
	sig := Signature{
		R: signatureR,
		S: e.Mul(d).Add(k),
	}
	// 13. If Verify(bytes(P), m, sig) (see below) returns failure, abort[14].
	if err := Verify(s.PublicKey, m, &sig); err != nil {
		return nil, errs.WrapFailed(err, "failed to verify signature")
	}
	// 14. Return the signature sig.
	return &sig, nil
}

// GenerateChallenge returns the challenge value based on the provided inputs.
func GenerateChallenge(curve curves.Curve, r, p, m []byte) (curves.Scalar, error) {
	hashedChallenge, err := taggedHash(challengeHashLabel, bytes.Join([][]byte{r, p, m}, nil))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to hash challenge")
	}
	rand, err := curve.Scalar().SetBytes(hashedChallenge)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to unmarshal random bytes")
	}
	return rand, nil
}

// getEventKey returns the even key based on the provided point.
func getEvenKey(prime curves.Scalar, P curves.Point) curves.Scalar {
	if !hasEvenY(P) {
		return prime.Neg()
	} else {
		return prime
	}
}

func KeyGen(curve curves.Curve, secret curves.Scalar) (*PrivateKey, error) {
	if curve == nil {
		return nil, errs.NewIsNil("curve is nil")
	}
	if secret == nil {
		return nil, errs.NewIsNil("secret is nil")
	}
	publicKey := curve.ScalarBaseMult(secret)

	return &PrivateKey{
		a: secret,
		PublicKey: PublicKey{
			Curve: curve,
			Y:     publicKey,
		},
	}, nil
}

// Verify takes a message `m`, a public key `pk`, and a signature `sig` and
// returns an error if the signature is invalid.
func Verify(publicKey *PublicKey, m []byte, signature *Signature) error {
	curve := publicKey.Curve
	if signature.R == nil || signature.S == nil || signature.R.IsZero() || signature.S.IsZero() {
		return errs.NewInvalidArgument("some signature elements are nil/zero")
	}
	if !publicKey.Y.IsOnCurve() {
		return errs.NewInvalidArgument("public key is not on curve")
	}
	ec, err := curveutils.ToEllipticCurve(curve)
	if err != nil {
		return errs.WrapFailed(err, "failed to convert curve to elliptic curve")
	}
	// 1. Let P = lift_x(int(pk)); fail if that fails.
	// The lift_x algorithm is a function that takes an x coordinate as input and returns a point on the secp256k1 curve that has that x coordinate and an even y coordinate
	P, err := curve.Point().FromAffineCompressed(append([]byte{0x02}, publicKey.Y.ToAffineCompressed()[1:]...))
	if err != nil {
		return errs.WrapFailed(err, "failed to lift x")
	}
	// 2. Let r = int(sig[0:32]); fail if r ≥ p.
	if signature.R.BigInt().Cmp(ec.Params().P) >= 0 {
		return errs.NewVerificationFailed("signature is invalid")
	}
	// 3. Let s = int(sig[32:64]); fail if s ≥ n. This step is implicit
	// 4. Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
	e, err := GenerateChallenge(curve, signature.R.Bytes(), P.ToAffineCompressed()[1:], m)
	if err != nil {
		return errs.WrapFailed(err, "failed to get e")
	}
	sG := curve.ScalarBaseMult(signature.S)
	eP := P.Mul(e)
	// 5. Let R = s⋅G - e⋅P.
	bigR := sG.Sub(eP)
	// 6. Fail if is_infinite(R).
	// 7. Fail if not has_even_y(R).
	// 8. Fail if bytes(R) ≠ r.
	if bigR.IsIdentity() || !hasEvenY(bigR) || signature.R.BigInt().Cmp(new(big.Int).SetBytes(bigR.ToAffineCompressed()[1:])) != 0 {
		return errs.NewVerificationFailed("signature is invalid")
	}
	return nil
}

// BatchVerify verifies the validity of a batch of signatures using a given cipher suite, public keys,
// messages, and signatures.
func BatchVerify(transcript transcripts.Transcript, cipherSuite *integration.CipherSuite, publickeys []*PublicKey, messages [][]byte, signatures []*Signature) error {
	curve := cipherSuite.Curve
	if transcript == nil {
		transcript = merlin.NewTranscript("BIP0340")
	}
	ec, err := curveutils.ToEllipticCurve(curve)
	if err != nil {
		return errs.WrapFailed(err, "failed to convert curve to elliptic curve")
	}
	size := len(publickeys)
	if size != len(messages) || size != len(signatures) {
		return errs.NewInvalidArgument("length of publickeys, messages and signatures must be equal")
	}
	left := curve.Scalar().Zero()
	rightScalars := make([]curves.Scalar, 2*size)
	rightPoints := make([]curves.Point, 2*size)
	for i, publicKey := range publickeys {
		// 1. Generate u-1 random integers a2...u in the range 1...n-1.
		transcript.AppendMessages("batch-verify", publickeys[i].Y.ToAffineCompressed(), messages[i], signatures[i].R.Bytes(), signatures[i].S.Bytes())
		a, err := curve.Scalar().SetBytes(transcript.ExtractBytes("batch-verify", A_SIZE))
		if err != nil {
			return errs.WrapFailed(err, "failed to set bytes for a_i")
		}
		// 2. Let Pi = lift_x(int(pki)); fail if it fails.
		// The lift_x algorithm is a function that takes an x coordinate as input and returns a point on the secp256k1 curve that has that x coordinate and an even y coordinate
		P, err := curve.Point().FromAffineCompressed(append([]byte{0x02}, publicKey.Y.ToAffineCompressed()[1:]...))
		if err != nil {
			return errs.WrapFailed(err, "failed to lift publicKey.Y")
		}
		// 3. Let ri = int(sigi[0:32]); fail if ri ≥ p.
		r := signatures[i].R
		if r.BigInt().Cmp(ec.Params().P) >= 0 {
			return errs.NewInvalidArgument("r is invalid")
		}
		// 4. Let si = int(sigi[32:64]); fail if si ≥ n.
		// the check is implicit
		s := signatures[i].S
		// 5. Let ei = int(hashBIP0340/challenge(bytes(ri) || bytes(Pi) || mi)) mod n.
		e, err := GenerateChallenge(curve, r.Bytes(), P.ToAffineCompressed()[1:], messages[i])
		if err != nil {
			return errs.WrapFailed(err, "failed to get e")
		}
		// 6. Let Ri = lift_x(ri); fail if lift_x(ri) fails.
		R, err := curve.Point().FromAffineCompressed(append([]byte{0x02}, r.Bytes()...))
		if err != nil {
			return errs.WrapFailed(err, "failed to lift r")
		}
		if i == 0 {
			// 7.1 add s1 to left
			left = left.Add(s)

			// 7.2 store a_i in right for multiScalaMult later
			rightScalars[i] = curve.Scalar().One()
			rightScalars[size+i] = e
		} else {
			// 7.3 add a_i*s_i to left
			left = left.Add(s.Mul(a))

			// 7.4 store a_i*e_1 in right for multiScalaMult later
			rightScalars[i] = a
			rightScalars[size+i] = e.Mul(a)
		}

		// 7.5 store R and P in right for multiScalaMult later
		rightPoints[i] = R
		rightPoints[size+i] = P
	}
	// calculate left: (s1 + a2s2 + ... + ausu)⋅G ≠ R1
	leftG := curve.ScalarBaseMult(left)
	// calculate right: R1 + a2⋅R2 + ... + au⋅Ru + e1⋅P1 + (a2e2)⋅P2 + ... + (aueu)⋅Pu.
	right, err := curve.MultiScalarMult(rightScalars, rightPoints)
	if err != nil {
		return errs.WrapFailed(err, "failed to multiply scalars and points")
	}
	// 7. Fail if (s1 + a2s2 + ... + ausu)⋅G ≠ R1 + a2⋅R2 + ... + au⋅Ru + e1⋅P1 + (a2e2)⋅P2 + ... + (aueu)⋅Pu.
	if !leftG.Equal(right) {
		return errs.NewVerificationFailed("signature is invalid")
	}
	return nil
}

// hasEvenY returns whether or not the y-coordinate of P is even.
func hasEvenY(P curves.Point) bool {
	return P.ToAffineCompressed()[0] == 0x02
}

// hash (name) returns the 32-byte hash SHA256(SHA256(tag) || SHA256(tag) || x),
// where tag is the UTF-8 encoding of name.
func taggedHash(tag string, x []byte) ([]byte, error) {
	hashTag, err := hashing.Hash(tagHashFunc, []byte(tag))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to hash tag")
	}
	hashed, err := hashing.Hash(tagHashFunc, hashTag, hashTag, x)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to combine hash tag")
	}
	return hashed, nil
}
