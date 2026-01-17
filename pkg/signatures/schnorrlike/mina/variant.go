package mina

import (
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
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
		return nil, ErrInvalidArgument.WithMessage("private key is nil")
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
		return nil, ErrInvalidArgument.WithMessage("prng is nil")
	}
	return &Variant{
		nid:  nid,
		prng: prng,
	}, nil
}

// Variant implements Mina-specific signing behaviour.
// It handles deterministic or random nonce generation, Poseidon-based challenge
// computation, and the even-y constraint on the nonce commitment.
type Variant struct {
	nid  NetworkId   // Network ID for domain separation (MainNet, TestNet, or custom)
	sk   *PrivateKey // Private key for deterministic nonce derivation (nil for random)
	prng io.Reader   // PRNG for random nonce generation (nil for deterministic)
	msg  *Message    // Message being signed (needed for deterministic nonce derivation)
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

// fieldTo255Bits converts a field element to 255 bits in LSB-first order.
// This matches o1js's Field.toBits() which returns 255 bits.
//
// IMPORTANT: o1js uses little-endian byte order for field elements,
// so we need to reverse the byte order from our big-endian representation.
func fieldTo255Bits(field *pasta.PallasBaseFieldElement) []bool {
	bytesLE := reversedBytes(field.Bytes()) // Convert big-endian to little-endian
	bits := make([]bool, 255)
	// o1js bytesToBits: extracts LSB-first per byte, starting from bytes[0]
	for i := range 255 {
		byteIdx := i / 8
		bitIdx := i % 8
		bits[i] = (bytesLE[byteIdx]>>bitIdx)&1 == 1
	}
	return bits
}

// bitsToBytes converts a slice of bits to bytes using LSB-first ordering per byte.
// This matches o1js's bitsToBytes function.
func bitsToBytes(bits []bool) []byte {
	numBytes := (len(bits) + 7) / 8
	bytes := make([]byte, numBytes)
	for i, bit := range bits {
		if bit {
			byteIdx := i / 8
			bitIdx := i % 8
			bytes[byteIdx] |= 1 << bitIdx
		}
	}
	return bytes
}

// deriveNonceLegacy computes a deterministic nonce using the legacy Mina/o1js algorithm.
// The nonce is derived as:
//  1. Build HashInputLegacy with message fields + [pk.x, pk.y], and bits + scalarBits + idBits
//  2. Convert to bits using inputToBitsLegacy: fields→255 bits each, then raw bits
//  3. Convert bits to bytes (LSB-first per byte)
//  4. Hash with Blake2b-256
//  5. Clear top 2 bits of last byte (to ensure result < field modulus)
//
// Reference: https://github.com/o1-labs/o1js/blob/fdc94dd8d3735d01c232d7d7af49763e044b738b/src/mina-signer/src/signature.ts#L249
func (v *Variant) deriveNonceLegacy() (*Scalar, error) {
	if v.msg == nil {
		return nil, ErrInvalidArgument.WithMessage("message is nil for deterministic nonce derivation")
	}

	pkx, err := v.sk.PublicKey().V.AffineX()
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to get public key X coordinate")
	}
	pky, err := v.sk.PublicKey().V.AffineY()
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to get public key Y coordinate")
	}

	// Convert private key to bits using Scalar.toBits()
	// In o1js: let scalarBits = Scalar.toBits(privateKey)
	scalarBits := scalarTo255Bits(v.sk.Value())

	// Get network ID as bits
	// In o1js: let idBits = bytesToBits([Number(id)])
	// For mainnet id=1, testnet id=0, converted to 8 bits LSB-first
	id, _ := getNetworkIdHashInput(v.nid)
	idByte := byte(id.Uint64())
	idBits := make([]bool, 8)
	for i := range 8 {
		idBits[i] = (idByte>>i)&1 == 1
	}

	// Get message fields and bits separately
	// o1js: let input = HashInputLegacy.append(message, { fields: [x, y], bits: [...scalarBits, ...idBits] })
	msgFields := v.msg.Fields()
	msgBits := v.msg.Bits()

	// Build all bits using inputToBitsLegacy logic:
	// fields.flatMap(f => f.toBits()) ++ bits
	var allBits []bool

	// 1. Convert message fields to 255 bits each
	for _, field := range msgFields {
		allBits = append(allBits, fieldTo255Bits(field)...)
	}

	// 2. Convert additional fields [pk.x, pk.y] to 255 bits each
	allBits = append(allBits, fieldTo255Bits(pkx)...)
	allBits = append(allBits, fieldTo255Bits(pky)...)

	// 3. Append raw message bits
	allBits = append(allBits, msgBits...)

	// 4. Append scalar bits (private key)
	allBits = append(allBits, scalarBits...)

	// 5. Append network ID bits
	allBits = append(allBits, idBits...)

	// Convert bits to bytes (LSB-first per byte)
	// This matches: bitsToBytes(inputBits)
	inputBytes := bitsToBytes(allBits)

	digest := blake2b.Sum256(inputBytes)

	// Drop top two bits of last byte
	// Reference: bytes[bytes.length - 1] &= 0x3f in o1js
	digest[len(digest)-1] &= 0x3f

	// Scalar.fromBytes interprets bytes as little-endian in o1js
	// Our sf.FromBytes expects big-endian, so we need to reverse
	digestBE := reversedBytes(digest[:])
	k, err := sf.FromBytes(digestBE)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to create scalar from bytes")
	}
	return k, nil
}

// scalarTo255Bits converts a scalar to 255 bits in LSB-first order.
// This matches o1js's Scalar.toBits() which returns 255 bits.
func scalarTo255Bits(scalar *Scalar) []bool {
	bytesLE := reversedBytes(scalar.Bytes()) // Convert big-endian to little-endian
	bits := make([]bool, 255)
	for i := range 255 {
		byteIdx := i / 8
		bitIdx := i % 8
		bits[i] = (bytesLE[byteIdx]>>bitIdx)&1 == 1
	}
	return bits
}

// ComputeNonceCommitment generates the nonce k and commitment R = k·G.
// Uses deterministic derivation if a private key was provided, otherwise uses PRNG.
// The nonce is adjusted to ensure R has an even y-coordinate.
func (v *Variant) ComputeNonceCommitment() (R *GroupElement, k *Scalar, err error) {
	if v.IsDeterministic() {
		k, err = v.deriveNonceLegacy()
	} else {
		k, err = algebrautils.RandomNonIdentity(sf, v.prng)
	}
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("failed to create scalar from bytes")
	}
	R = group.ScalarBaseMul(k)

	// Ensure R has an even y-coordinate (same as BIP340)
	ry, err := R.AffineY()
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot get y coordinate")
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
		return nil, ErrInvalidArgument.WithMessage("nonceCommitment, publicKeyValue and message must not be nil")
	}
	input := message.Clone()
	pkx, err := publicKeyValue.AffineX()
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot get x")
	}
	pky, err := publicKeyValue.AffineY()
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot get y")
	}
	ncx, err := nonceCommitment.AffineX()
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot get x")
	}
	input.AddFields(pkx, pky, ncx)
	prefix := SignaturePrefix(v.nid)
	e, err := hashWithPrefix(prefix, input.PackToFields()...)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to compute challenge")
	}
	return e, nil
}

// ComputeResponse computes the Mina signature response: s = k + e·x mod n.
func (v *Variant) ComputeResponse(privateKeyValue, nonce, challenge *Scalar) (*Scalar, error) {
	if privateKeyValue == nil || nonce == nil || challenge == nil {
		return nil, ErrInvalidArgument.WithMessage("privateKeyValue, nonce and challenge must not be nil")
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
func (v *Variant) CorrectPartialNonceParity(aggregatedNonceCommitments *GroupElement, localNonce *Scalar) (correctedR *GroupElement, correctedK *Scalar, err error) {
	if aggregatedNonceCommitments == nil || localNonce == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("nonce commitment or k is nil")
	}
	correctedK = localNonce.Clone()
	ancy, err := aggregatedNonceCommitments.AffineY()
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot get y")
	}
	if ancy.IsOdd() {
		// If the nonce commitment is odd, we need to negate k to ensure that the parity is correct.
		correctedK = correctedK.Neg()
	}
	correctedR = group.ScalarBaseOp(correctedK)
	return correctedR, correctedK, nil
}
