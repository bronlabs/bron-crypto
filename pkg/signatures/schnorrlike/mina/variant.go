package mina

import (
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
)

// VariantType identifies this as the Mina Schnorr variant.
const VariantType schnorrlike.VariantType = "mina"

var (
	_ schnorrlike.Variant[*GroupElement, *Scalar, *Message]         = (*Variant)(nil)
	_ tschnorr.MPCFriendlyVariant[*GroupElement, *Scalar, *Message] = (*Variant)(nil)
)

// NewDeterministicVariant creates a Mina variant with deterministic nonce derivation.
// The nonce is derived from the private key, public key, and network ID using Blake2b,
// following the legacy Mina/o1js implementation.
func NewDeterministicVariant(nid NetworkId, privateKey *PrivateKey) (*Variant, error) {
	if privateKey == nil {
		return nil, errs.NewIsNil("private key is nil")
	}
	return &Variant{
		nid: nid,
		sk:  privateKey,
	}, nil
}

// NewRandomisedVariant creates a Mina variant with random nonce generation.
// This is used for MPC/threshold signing where nonces are collaboratively generated.
func NewRandomisedVariant(nid NetworkId, prng io.Reader) (*Variant, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	return &Variant{
		nid:  nid,
		prng: prng,
	}, nil
}

// Variant implements Mina-specific signing behavior.
// It handles deterministic or random nonce generation, Poseidon-based challenge
// computation, and the even-y constraint on the nonce commitment.
type Variant struct {
	nid  NetworkId   // Network ID for domain separation (MainNet, TestNet, or custom)
	sk   *PrivateKey // Private key for deterministic nonce derivation (nil for random)
	prng io.Reader   // PRNG for random nonce generation (nil for deterministic)
}

// Type returns the variant identifier "mina".
func (*Variant) Type() schnorrlike.VariantType {
	return VariantType
}

// HashFunc returns the Poseidon hash function constructor for challenge computation.
func (*Variant) HashFunc() func() hash.Hash {
	return hashFunc
}

// IsDeterministic returns true if this variant uses deterministic nonce derivation.
func (v *Variant) IsDeterministic() bool {
	return v.sk != nil
}

// deriveNonceLegacy computes a deterministic nonce using the legacy Mina/o1js algorithm.
// The nonce is derived as:
//  1. Pack (pk.x, pk.y, scalar, networkId) into ROInput
//  2. Convert packed fields to little-endian bytes
//  3. Hash with Blake2b-256
//  4. Clear top 2 bits (to ensure result < field modulus)
//
// Reference: https://github.com/o1-labs/o1js/blob/fdc94dd8d3735d01c232d7d7af49763e044b738b/src/mina-signer/src/signature.ts#L249
func (v *Variant) deriveNonceLegacy() (*Scalar, error) {
	pkx, err := v.sk.PublicKey().V.AffineX()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to get public key X coordinate")
	}
	pky, err := v.sk.PublicKey().V.AffineY()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to get public key Y coordinate")
	}

	// Get scalar and network ID in LE format
	scalarBytesLE := reversedBytes(v.sk.Value().Bytes())
	scalarBits := bytesToBits(scalarBytesLE)

	id, bitLength := getNetworkIdHashInput(v.nid)
	idBits := networkIdToBits(id, bitLength)

	// Use ROInput to properly structure the data
	input := new(ROInput).Init()
	input.AddFields(pkx, pky)
	input.AddBits(scalarBits...)
	input.AddBits(idBits...)

	// Pack to fields
	packed := input.PackToFields()

	// Convert packed fields to LE bytes for blake2b
	var allBytes []byte
	for _, field := range packed {
		fieldBytesLE := reversedBytes(field.Bytes())
		allBytes = append(allBytes, fieldBytesLE...)
	}

	digest := blake2b.Sum256(allBytes)

	// Blake2b digest as BE (interpret as-is)
	// Drop top two bits
	digest[0] &= 0x3f

	k, err := sf.FromBytes(digest[:])
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to create scalar from bytes")
	}
	return k, nil
}

// ComputeNonceCommitment generates the nonce k and commitment R = k·G.
// Uses deterministic derivation if a private key was provided, otherwise uses PRNG.
// The nonce is adjusted to ensure R has an even y-coordinate.
func (v *Variant) ComputeNonceCommitment() (*GroupElement, *Scalar, error) {
	var k *Scalar
	var err error
	if v.IsDeterministic() {
		k, err = v.deriveNonceLegacy()
	} else {
		k, err = algebrautils.RandomNonIdentity(sf, v.prng)
	}
	if err != nil {
		return nil, nil, errs.WrapSerialisation(err, "failed to create scalar from bytes")
	}
	R := group.ScalarBaseMul(k)

	// Ensure R has an even y-coordinate (same as BIP340)
	ry, err := R.AffineY()
	if err != nil {
		return nil, nil, errs.WrapSerialisation(err, "cannot get y coordinate")
	}
	if ry.IsOdd() {
		// Negate k to flip the y-coordinate parity
		k = k.Neg()
		R = group.ScalarBaseMul(k)
	}

	return R, k, nil
}

// ComputeChallenge computes the Mina Fiat-Shamir challenge using Poseidon hashing.
// The challenge is: e = Poseidon(prefix || message || pk.x || pk.y || R.x)
// where prefix is the network-specific signature prefix.
//
// Reference: https://github.com/o1-labs/o1js/blob/885b50e60ead596cdcd8dc944df55fd3a4467a0a/src/mina-signer/src/signature.ts#L242
func (v *Variant) ComputeChallenge(nonceCommitment, publicKeyValue *GroupElement, message *Message) (*Scalar, error) {
	if nonceCommitment == nil || publicKeyValue == nil || message == nil {
		return nil, errs.NewIsNil("nonceCommitment, publicKeyValue and message must not be nil")
	}
	input := message.Clone()
	pkx, err := publicKeyValue.AffineX()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot get x")
	}
	pky, err := publicKeyValue.AffineY()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot get y")
	}
	ncx, err := nonceCommitment.AffineX()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot get x")
	}
	input.AddFields(pkx, pky, ncx)
	prefix := SignaturePrefix(v.nid)
	e, err := hashWithPrefix(prefix, input.PackToFields()...)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to compute challenge")
	}
	return e, nil
}

// ComputeResponse computes the Mina signature response: s = k + e·x mod n.
func (v *Variant) ComputeResponse(privateKeyValue, nonce, challenge *Scalar) (*Scalar, error) {
	if privateKeyValue == nil || nonce == nil || challenge == nil {
		return nil, errs.NewIsNil("privateKeyValue, nonce and challenge must not be nil")
	}
	return nonce.Add(challenge.Mul(privateKeyValue)), nil
}

// SerializeSignature encodes the signature to 64 bytes in Mina's little-endian format.
func (v *Variant) SerializeSignature(signature *Signature) ([]byte, error) {
	return SerializeSignature(signature)
}

// ============ MPC Methods ============.
//
// These methods support threshold/MPC Schnorr signing with Mina.
// Mina requires R to have an even y-coordinate, similar to BIP-340.

// CorrectAdditiveSecretShareParity is a no-op for Mina since no parity correction
// is needed for secret shares (only for nonce commitments).
func (v *Variant) CorrectAdditiveSecretShareParity(publicKey *PublicKey, share *additive.Share[*Scalar]) (*additive.Share[*Scalar], error) {
	// no changes needed
	return share, nil
}

// CorrectPartialNonceParity adjusts a partial nonce for Mina's even-y requirement.
// If the aggregate nonce commitment R has odd y, each party must negate their
// partial nonce k_i to ensure the final signature is valid.
func (v *Variant) CorrectPartialNonceParity(aggregatedNonceCommitments *GroupElement, localNonce *Scalar) (*GroupElement, *Scalar, error) {
	if aggregatedNonceCommitments == nil || localNonce == nil {
		return nil, nil, errs.NewIsNil("nonce commitment or k is nil")
	}
	correctedK := localNonce.Clone()
	ancy, err := aggregatedNonceCommitments.AffineY()
	if err != nil {
		return nil, nil, errs.WrapSerialisation(err, "cannot get y")
	}
	if ancy.IsOdd() {
		// If the nonce commitment is odd, we need to negate k to ensure that the parity is correct.
		correctedK = correctedK.Neg()
	}
	correctedR := group.ScalarBaseOp(correctedK)
	return correctedR, correctedK, nil
}
