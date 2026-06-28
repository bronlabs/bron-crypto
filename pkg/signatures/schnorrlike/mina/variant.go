package mina

import (
	"hash"
	"io"
	"math/big"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/hashing/poseidon"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	mpcschnorr "github.com/bronlabs/bron-crypto/pkg/mpc/signatures/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
)

// VariantType identifies this as the Mina Schnorr variant.
const VariantType schnorrlike.VariantType = "mina"

// signatureFlavor selects the nonce derivation and Poseidon parameters used by
// a Mina signature variant. Its zero value preserves the legacy behaviour.
type signatureFlavor uint8

const (
	signatureFlavorLegacy signatureFlavor = iota
	signatureFlavorModern
)

// packedInput represents one value in o1js's [value, bitLength] packed input.
type packedInput struct {
	value  *big.Int
	bitLen int
}

var (
	_ schnorrlike.Variant[*GroupElement, *Scalar, *Message]           = (*Variant)(nil)
	_ mpcschnorr.MPCFriendlyVariant[*GroupElement, *Scalar, *Message] = (*Variant)(nil)
)

// NewDeterministicVariant creates a Mina variant with deterministic nonce derivation.
// The nonce is derived from the private key, public key, and network ID using Blake2b,
// following the legacy Mina/o1js implementation.
func NewDeterministicVariant(nid NetworkID, privateKey *PrivateKey) (*Variant, error) {
	if privateKey == nil {
		return nil, signatures.ErrInvalidArgument.WithMessage("private key is nil")
	}
	return &Variant{
		nid:    nid,
		sk:     privateKey,
		prng:   nil,
		msg:    nil,
		flavor: signatureFlavorLegacy,
	}, nil
}

// NewModernDeterministicVariant creates a Mina variant with deterministic nonce derivation.
// The nonce is derived from the private key, public key, and network ID using Blake2b,
// following the modern Mina/o1js implementation.
func NewModernDeterministicVariant(nid NetworkID, privateKey *PrivateKey) (*Variant, error) {
	if privateKey == nil {
		return nil, signatures.ErrInvalidArgument.WithMessage("private key is nil")
	}
	return &Variant{
		nid:    nid,
		sk:     privateKey,
		prng:   nil,
		msg:    nil,
		flavor: signatureFlavorModern,
	}, nil
}

// NewRandomisedVariant creates a Mina variant with random nonce generation.
// This is used for MPC/threshold signing where nonces are collaboratively generated.
func NewRandomisedVariant(nid NetworkID, prng io.Reader) (*Variant, error) {
	if prng == nil {
		return nil, signatures.ErrInvalidArgument.WithMessage("prng is nil")
	}
	return &Variant{
		nid:    nid,
		sk:     nil,
		prng:   prng,
		msg:    nil,
		flavor: signatureFlavorLegacy,
	}, nil
}

// NewModernRandomisedVariant creates a Mina variant with random nonce generation.
// The variant uses the modern Mina/o1js Poseidon parameters for challenge computation.
func NewModernRandomisedVariant(nid NetworkID, prng io.Reader) (*Variant, error) {
	if prng == nil {
		return nil, signatures.ErrInvalidArgument.WithMessage("prng is nil")
	}
	return &Variant{
		nid:    nid,
		sk:     nil,
		prng:   prng,
		msg:    nil,
		flavor: signatureFlavorModern,
	}, nil
}

// Variant implements Mina-specific signing behaviour.
// It handles deterministic or random nonce generation, Poseidon-based challenge
// computation, and the even-y constraint on the nonce commitment.
type Variant struct {
	nid  NetworkID   // Network ID for domain separation (MainNet, TestNet, or custom)
	sk   *PrivateKey // Private key for deterministic nonce derivation (nil for random)
	prng io.Reader   // PRNG for random nonce generation (nil for deterministic)
	msg  *Message    // Message being signed (needed for deterministic nonce derivation)

	flavor signatureFlavor
}

// Type returns the variant identifier "mina".
func (*Variant) Type() schnorrlike.VariantType {
	return VariantType
}

// HashFunc returns the Poseidon hash function constructor for challenge computation.
func (v *Variant) HashFunc() func() hash.Hash {
	if v.flavor == signatureFlavorModern {
		return modernHashFunc
	}
	return hashFunc
}

// newPoseidon creates the Poseidon instance selected by the signature flavor.
func (v *Variant) newPoseidon() *poseidon.Poseidon {
	if v.flavor == signatureFlavorModern {
		return poseidon.NewKimchi()
	}
	return poseidon.NewLegacy()
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
		return nil, signatures.ErrInvalidArgument.WithMessage("message is nil for deterministic nonce derivation")
	}

	pkx, err := v.sk.PublicKey().V.AffineX()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to get public key X coordinate")
	}
	pky, err := v.sk.PublicKey().V.AffineY()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to get public key Y coordinate")
	}

	// Convert private key to bits using Scalar.toBits()
	// In o1js: let scalarBits = Scalar.toBits(privateKey)
	scalarBits := scalarTo255Bits(v.sk.Value())

	// Get network ID as bits
	// In o1js: let idBits = bytesToBits([Number(id)])
	// For mainnet id=1, testnet id=0, converted to 8 bits LSB-first
	id, _ := getNetworkIDHashInput(v.nid)
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
		return nil, errs.Wrap(err).WithMessage("failed to create scalar from bytes")
	}
	return k, nil
}

// packToFieldsModern converts an ROInput to field elements using o1js's modern
// chunked HashInput packing. Existing message bits are represented as one-bit
// packed values, while extraPacked contains complete values such as network ID.
//
// The packing algorithm:
//  1. Preserve all directly-added field elements.
//  2. Accumulate packed values from left to right while the total size is below 255 bits.
//  3. Start a new field before a packed value would reach or cross the 255-bit boundary.
//  4. Append the final packed field, including a zero-valued field when packed input exists.
//
// Reference: https://github.com/o1-labs/o1js/blob/cda4bce423960d877fe4f6c04feb32036a2e34b5/src/mina-signer/src/poseidon-bigint.ts
func packToFieldsModern(input *ROInput, extraPacked ...packedInput) ([]*pasta.PallasBaseFieldElement, error) {
	if input == nil {
		return nil, signatures.ErrInvalidArgument.WithMessage("input is nil")
	}

	fields := input.Fields()
	current := new(big.Int)
	currentSize := 0
	hasPacked := false

	appendField := func(value *big.Int) error {
		if value.Sign() < 0 || value.BitLen() > pasta.NewPallasBaseField().BitLen() {
			return signatures.ErrInvalidArgument.WithMessage("packed value does not fit in base field")
		}
		encoded := value.FillBytes(make([]byte, pasta.NewPallasBaseField().ElementSize()))
		field, err := pasta.NewPallasBaseField().FromBytes(encoded)
		if err != nil {
			return errs.Wrap(err).WithMessage("failed to convert packed value to field element")
		}
		fields = append(fields, field)
		return nil
	}

	appendPacked := func(value *big.Int, bitLen int) error {
		if value == nil || bitLen <= 0 || value.Sign() < 0 || value.BitLen() > bitLen {
			return signatures.ErrInvalidArgument.WithMessage("invalid packed input")
		}
		hasPacked = true
		currentSize += bitLen
		if currentSize < 255 {
			// Concatenate the next packed value on the right, matching o1js:
			// currentPackedField * 2^bitLen + value.
			current.Lsh(current, uint(bitLen))
			current.Add(current, value)
			return nil
		}

		// Packed values are atomic. Flush the current field instead of splitting
		// the value across the 255-bit boundary.
		if err := appendField(current); err != nil {
			return err
		}
		current.Set(value)
		currentSize = bitLen
		return nil
	}

	zero := new(big.Int)
	one := big.NewInt(1)
	for _, bit := range input.Bits() {
		value := zero
		if bit {
			value = one
		}
		if err := appendPacked(value, 1); err != nil {
			return nil, err
		}
	}
	for _, packed := range extraPacked {
		if err := appendPacked(packed.value, packed.bitLen); err != nil {
			return nil, err
		}
	}
	if hasPacked {
		if err := appendField(current); err != nil {
			return nil, err
		}
	}

	return fields, nil
}

// deriveNonceModern computes a deterministic nonce using the modern Mina/o1js algorithm.
// The nonce is derived as:
//  1. Build HashInput with message fields + [pk.x, pk.y, Field(privateKey)] and packed network ID.
//  2. Convert the input to fields using modern chunked packing.
//  3. Convert every packed field to 255 bits in LSB-first order.
//  4. Convert the bits to bytes and hash them with Blake2b-256.
//  5. Clear the top 2 bits of the last byte to obtain a scalar field element.
//
// Reference: https://github.com/o1-labs/o1js/blob/cda4bce423960d877fe4f6c04feb32036a2e34b5/src/mina-signer/src/signature.ts
func (v *Variant) deriveNonceModern() (*Scalar, error) {
	if v.msg == nil {
		return nil, signatures.ErrInvalidArgument.WithMessage("message is nil for deterministic nonce derivation")
	}

	pkx, err := v.sk.PublicKey().V.AffineX()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to get public key X coordinate")
	}
	pky, err := v.sk.PublicKey().V.AffineY()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to get public key Y coordinate")
	}
	// Convert the private key from the scalar field to the base field.
	// In o1js: let d = Field(privateKey)
	d, err := pasta.NewPallasBaseField().FromBytesBEReduce(v.sk.Value().Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to reinterpret private key as base field")
	}

	// Build the modern HashInput:
	// HashInput.append(message, { fields: [x, y, d], packed: [id] })
	input := v.msg.Clone()
	input.AddFields(pkx, pky, d)
	id, idBitLen := getNetworkIDHashInput(v.nid)
	packed, err := packToFieldsModern(input, packedInput{value: id, bitLen: idBitLen})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot pack nonce input")
	}

	// Convert each packed field to 255 bits before hashing.
	// In o1js: packedInput.map(Field.toBits).flat()
	inputBits := make([]bool, 0, len(packed)*255)
	for _, field := range packed {
		inputBits = append(inputBits, fieldTo255Bits(field)...)
	}
	// Convert bits to bytes using LSB-first ordering and hash with Blake2b-256.
	digest := blake2b.Sum256(bitsToBytes(inputBits))

	// Drop the top two bits of the last byte.
	// Reference: bytes[bytes.length - 1] &= 0x3f in o1js.
	digest[len(digest)-1] &= 0x3f

	// Scalar.fromBytes interprets bytes as little-endian in o1js.
	// Our sf.FromBytes expects big-endian, so reverse the digest first.
	k, err := sf.FromBytes(reversedBytes(digest[:]))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create scalar from bytes")
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
		if v.flavor == signatureFlavorModern {
			k, err = v.deriveNonceModern()
		} else {
			k, err = v.deriveNonceLegacy()
		}
	} else {
		k, err = algebrautils.RandomNonIdentity(sf, v.prng)
	}
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to create scalar from bytes")
	}
	R = group.ScalarBaseMul(k)

	// Ensure R has an even y-coordinate (same as BIP340)
	ry, err := R.AffineY()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot get y coordinate")
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
		return nil, signatures.ErrInvalidArgument.WithMessage("nonceCommitment, publicKeyValue and message must not be nil")
	}
	input := message.Clone()
	pkx, err := publicKeyValue.AffineX()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot get x")
	}
	pky, err := publicKeyValue.AffineY()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot get y")
	}
	ncx, err := nonceCommitment.AffineX()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot get x")
	}
	input.AddFields(pkx, pky, ncx)
	prefix := SignaturePrefix(v.nid)
	var packed []*pasta.PallasBaseFieldElement
	if v.flavor == signatureFlavorModern {
		packed, err = packToFieldsModern(input)
	} else {
		packed, err = input.PackToFields()
	}
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot pack fields")
	}
	e, err := hashWithPrefix(v.newPoseidon, prefix, packed...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute challenge")
	}
	return e, nil
}

// ComputeResponse computes the Mina signature response: s = k + e·x mod n.
func (*Variant) ComputeResponse(privateKeyValue, nonce, challenge *Scalar) (*Scalar, error) {
	if privateKeyValue == nil || nonce == nil || challenge == nil {
		return nil, signatures.ErrInvalidArgument.WithMessage("privateKeyValue, nonce and challenge must not be nil")
	}
	return nonce.Add(challenge.Mul(privateKeyValue)), nil
}

// SerializeSignature encodes the signature to 64 bytes in Mina's little-endian format.
func (*Variant) SerializeSignature(signature *Signature) ([]byte, error) {
	return SerializeSignature(signature)
}

// ============ MPC Methods ============.
//
// These methods support threshold/MPC Schnorr signing with Mina.
// Mina requires R to have an even y-coordinate, similar to BIP-340.

// CorrectAdditiveSecretShareParity is a no-op for Mina since no parity correction
// is needed for secret shares (only for nonce commitments).
func (*Variant) CorrectAdditiveSecretShareParity(_ *PublicKey, share *additive.Share[*Scalar]) (*additive.Share[*Scalar], error) {
	if share == nil {
		return nil, signatures.ErrInvalidArgument.WithMessage("share is nil")
	}
	// no changes needed
	return share.Clone(), nil
}

// CorrectPartialNonceParity adjusts a partial nonce for Mina's even-y requirement.
// If the aggregate nonce commitment R has odd y, each party must negate their
// partial nonce k_i to ensure the final signature is valid.
func (*Variant) CorrectPartialNonceParity(aggregatedNonceCommitments *GroupElement, localNonce *Scalar) (correctedR *GroupElement, correctedK *Scalar, err error) {
	if aggregatedNonceCommitments == nil || localNonce == nil {
		return nil, nil, signatures.ErrInvalidArgument.WithMessage("nonce commitment or k is nil")
	}
	correctedK = localNonce.Clone()
	ancy, err := aggregatedNonceCommitments.AffineY()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot get y")
	}
	if ancy.IsOdd() {
		// If the nonce commitment is odd, we need to negate k to ensure that the parity is correct.
		correctedK = correctedK.Neg()
	}
	correctedR = group.ScalarBaseOp(correctedK)
	return correctedR, correctedK, nil
}

// CorrectPartialNonceCommitmentParity adjusts a partial nonce commitment for Mina's even-y requirement.
// If the aggregate nonce commitment R has odd y, each party must negate their
// partial nonce commitment R_i to ensure the final signature is valid.
func (*Variant) CorrectPartialNonceCommitmentParity(aggregatedNonceCommitment, partialNonceCommitment *GroupElement) (*GroupElement, error) {
	if aggregatedNonceCommitment == nil || partialNonceCommitment == nil {
		return nil, signatures.ErrInvalidArgument.WithMessage("aggregated nonce commitment or partial nonce commitment is nil")
	}
	ancy, err := aggregatedNonceCommitment.AffineY()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot get y")
	}
	if ancy.IsOdd() {
		// If the aggregate nonce commitment is odd, we need to negate the partial commitment as well.
		return partialNonceCommitment.Neg(), nil
	}
	return partialNonceCommitment.Clone(), nil
}
