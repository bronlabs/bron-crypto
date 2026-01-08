package mina

import (
	"github.com/bronlabs/bron-crypto/pkg/base/base58"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

// Base58Check version prefixes for Mina key and signature encoding.
// These prefixes ensure type safety and prevent accidental misuse of encoded data.
//
// Reference: https://github.com/MinaProtocol/mina/blob/develop/src/lib/base58_check/version_bytes.ml
const (
	// PrivateKeyBase58VersionPrefix (0x5A) identifies Base58-encoded private keys.
	PrivateKeyBase58VersionPrefix base58.VersionPrefix = 0x5A
	// NonZeroCurvePointCompressedBase58VersionPrefix (0xCB) identifies Base58-encoded public keys.
	NonZeroCurvePointCompressedBase58VersionPrefix base58.VersionPrefix = 0xCB
	// SignatureBase58VersionPrefix (0x9A) identifies Base58-encoded signatures.
	SignatureBase58VersionPrefix base58.VersionPrefix = 0x9A
)

// EncodePublicKey encodes a Mina public key to Base58Check format.
// The encoding uses version prefix 0xCB with additional bytes [0x01, 0x01],
// followed by the x-coordinate in little-endian and a y-parity byte.
// Format: Base58Check(0xCB || 0x01 || 0x01 || x_LE[32] || y_parity[1])
func EncodePublicKey(publicKey *PublicKey) (base58.Base58, error) {
	if publicKey == nil {
		return "", errs.NewIsNil("public key is nil")
	}
	// Mina uses a 3-byte version prefix: [0xCB, 0x01, 0x01]
	// Mina uses LITTLE-ENDIAN for field elements

	// Get x-coordinate and y-parity
	x, err := publicKey.V.AffineX()
	if err != nil {
		return "", errs.WrapSerialisation(err, "failed to get x coordinate")
	}
	y, err := publicKey.V.AffineY()
	if err != nil {
		return "", errs.WrapSerialisation(err, "failed to get y coordinate")
	}

	// Convert x from big-endian (internal) to little-endian (Mina format)
	xBytesBE := x.Bytes()
	xBytesLE := make([]byte, len(xBytesBE))
	for i := range xBytesBE {
		xBytesLE[i] = xBytesBE[len(xBytesBE)-1-i]
	}

	yParity := byte(0)
	if y.IsOdd() {
		yParity = 1
	}

	// Build payload: [0x01, 0x01] + x-coordinate (LE) + y-parity
	payload := make([]byte, 0, 2+32+1)
	payload = append(payload, 0x01, 0x01) // Additional version bytes
	payload = append(payload, xBytesLE...)
	payload = append(payload, yParity)

	return base58.CheckEncode(payload, NonZeroCurvePointCompressedBase58VersionPrefix), nil
}

// DecodePublicKey decodes a Mina public key from Base58Check format.
// Validates the version prefix (0xCB) and additional bytes [0x01, 0x01],
// then reconstructs the curve point from x-coordinate and y-parity.
func DecodePublicKey(s base58.Base58) (*PublicKey, error) {
	data, v, err := base58.CheckDecode(s)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to decode public key")
	}
	if v != NonZeroCurvePointCompressedBase58VersionPrefix {
		return nil, errs.NewVerification("invalid version prefix for public key. got :%d, need :%d", v, NonZeroCurvePointCompressedBase58VersionPrefix)
	}
	// Mina format: [0x01, 0x01] + x-coordinate (32 bytes, LE) + y-parity (1 byte) = 35 bytes
	if len(data) != 35 {
		return nil, errs.NewLength("decoded public key data. got :%d, need :%d", len(data), 35)
	}
	// Verify additional version bytes
	if data[0] != 0x01 || data[1] != 0x01 {
		return nil, errs.NewVerification("invalid additional version bytes. got :[%02x, %02x], need :[0x01, 0x01]", data[0], data[1])
	}

	// Extract x-coordinate and y-parity
	xBytesLE := data[2:34] // 32 bytes in little-endian
	yParity := data[34]     // 1 byte

	// Convert x from little-endian (Mina format) to big-endian (internal format)
	xBytesBE := make([]byte, len(xBytesLE))
	for i := range xBytesLE {
		xBytesBE[i] = xBytesLE[len(xBytesLE)-1-i]
	}

	// Parse x-coordinate
	x, err := group.BaseField().FromBytes(xBytesBE)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to parse x coordinate")
	}

	// Reconstruct point from x and y-parity
	pkv, err := group.FromAffineX(x, yParity == 1)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create public key from coordinates")
	}
	publicKey, err := NewPublicKey(pkv)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create public key")
	}
	return publicKey, nil
}

// EncodePrivateKey encodes a Mina private key to Base58Check format.
// The encoding uses version prefix 0x5A with additional byte 0x01,
// followed by the scalar value in little-endian.
// Format: Base58Check(0x5A || 0x01 || scalar_LE[32])
func EncodePrivateKey(privateKey *PrivateKey) (base58.Base58, error) {
	if privateKey == nil {
		return "", errs.NewIsNil("private key is nil")
	}
	// Mina uses a 2-byte version prefix for private keys: [0x5A, 0x01]
	// Mina uses LITTLE-ENDIAN for scalar bytes (contrary to our internal big-endian)
	scalarBytes := privateKey.V.Bytes()
	// Reverse to convert from big-endian (internal) to little-endian (Mina format)
	scalarBytesLE := make([]byte, len(scalarBytes))
	for i := range scalarBytes {
		scalarBytesLE[i] = scalarBytes[len(scalarBytes)-1-i]
	}

	// Build payload: [0x01] + scalar (32 bytes, LE)
	payload := make([]byte, 0, 1+32)
	payload = append(payload, 0x01) // Additional version byte
	payload = append(payload, scalarBytesLE...)

	return base58.CheckEncode(payload, PrivateKeyBase58VersionPrefix), nil
}

// DecodePrivateKey decodes a Mina private key from Base58Check format.
// Validates the version prefix (0x5A) and additional byte 0x01,
// then parses the scalar value from little-endian bytes.
func DecodePrivateKey(s base58.Base58) (*PrivateKey, error) {
	data, v, err := base58.CheckDecode(s)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to decode private key")
	}
	if v != PrivateKeyBase58VersionPrefix {
		return nil, errs.NewVerification("invalid version prefix for private key. got :%d, need :%d", v, PrivateKeyBase58VersionPrefix)
	}
	// Mina format: [0x01] + scalar (32 bytes, LE) = 33 bytes
	if len(data) != 33 {
		return nil, errs.NewLength("decoded private key data. got :%d, need :%d", len(data), 33)
	}
	// Verify additional version byte
	if data[0] != 0x01 {
		return nil, errs.NewVerification("invalid additional version byte. got :0x%02x, need :0x01", data[0])
	}

	// Extract scalar bytes (skip first version byte)
	scalarBytesLE := data[1:] // 32 bytes in little-endian

	// Convert from little-endian (Mina format) to big-endian (internal format)
	scalarBytesBE := make([]byte, len(scalarBytesLE))
	for i := range scalarBytesLE {
		scalarBytesBE[i] = scalarBytesLE[len(scalarBytesLE)-1-i]
	}

	skv, err := sf.FromBytes(scalarBytesBE)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to create scalar from bytes")
	}
	privateKey, err := NewPrivateKey(skv)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create private key")
	}
	return privateKey, nil
}

// EncodeSignature encodes a Mina signature to Base58Check format.
// The signature is first serialized to 64 bytes (R.x || s in little-endian),
// then encoded with version prefix 0x9A.
func EncodeSignature(signature *Signature) (base58.Base58, error) {
	if signature == nil {
		return "", errs.NewIsNil("signature is nil")
	}
	data, err := SerializeSignature(signature)
	if err != nil {
		return "", errs.WrapSerialisation(err, "failed to serialise signature")
	}
	return base58.CheckEncode(data, SignatureBase58VersionPrefix), nil
}

// DecodeSignature decodes a Mina signature from Base58Check format.
// Validates the version prefix (0x9A) and deserializes the 64-byte payload
// to reconstruct the signature (R point with even y, response scalar s).
func DecodeSignature(s base58.Base58) (*Signature, error) {
	data, v, err := base58.CheckDecode(s)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to decode signature")
	}
	if v != SignatureBase58VersionPrefix {
		return nil, errs.NewVerification("invalid version prefix for signature. got :%d, need :%d", v, SignatureBase58VersionPrefix)
	}
	if len(data) != SignatureSize {
		return nil, errs.NewLength("decoded signature data. got :%d, need :%d", len(data), SignatureSize)
	}
	sig, err := DeserializeSignature(data)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to deserialize signature")
	}
	return sig, nil
}
