package mina

// import (
// 	"fmt"

// 	"github.com/bronlabs/bron-crypto/pkg/base/base58"
// 	"github.com/bronlabs/bron-crypto/pkg/base/errs"
// )

// // https://github.com/MinaProtocol/mina/blob/develop/src/lib/base58_check/version_bytes.ml
// const (
// 	PrivateKeyBase58VersionPrefix                  base58.VersionPrefix = 0x5A
// 	NonZeroCurvePointCompressedBase58VersionPrefix base58.VersionPrefix = 0xCB
// 	SignatureBase58VersionPrefix                   base58.VersionPrefix = 0x9A
// )

// func EncodePublicKey(publicKey *PublicKey) (base58.Base58, error) {
// 	if publicKey == nil {
// 		return "", errs.NewIsNil("public key is nil")
// 	}
// 	enc := base58.NewEncoder(NonZeroCurvePointCompressedBase58VersionPrefix)
// 	return enc.Encode(publicKey.V.Bytes()), nil
// }

// func DecodePublicKey(s base58.Base58) (*PublicKey, error) {
// 	dec := base58.NewEncoder(NonZeroCurvePointCompressedBase58VersionPrefix)
// 	data, err := dec.Decode(s)
// 	if err != nil {
// 		return nil, errs.WrapSerialisation(err, "failed to decode public key")
// 	}
// 	fmt.Println("Decoded public key data:", data)
// 	fmt.Println(base58.NewEncoder(NonZeroCurvePointCompressedBase58VersionPrefix).Encode(data))
// 	// Check the length of the decoded data
// 	if len(data) != PublicKeySize {
// 		return nil, errs.NewLength("decoded public key data. got :%d, need :%d", len(data), PublicKeySize)
// 	}
// 	pkv, err := group.FromBytes(data)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to create public key from bytes")
// 	}
// 	publicKey, err := NewPublicKey(pkv)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to create public key")
// 	}
// 	return publicKey, nil
// }

// func EncodePrivateKey(privateKey *PrivateKey) (base58.Base58, error) {
// 	if privateKey == nil {
// 		return "", errs.NewIsNil("private key is nil")
// 	}
// 	enc := base58.NewEncoder(PrivateKeyBase58VersionPrefix)
// 	return enc.Encode(privateKey.V.Bytes()), nil
// }

// func DecodePrivateKey(s base58.Base58) (*PrivateKey, error) {
// 	dec := base58.NewEncoder(PrivateKeyBase58VersionPrefix)
// 	data, err := dec.Decode(s)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to decode private key")
// 	}
// 	fmt.Println("Decoded private key data:", data)
// 	fmt.Println(base58.NewEncoder(PrivateKeyBase58VersionPrefix).Encode(data))
// 	if len(data) != PrivateKeySize {
// 		return nil, errs.NewLength("decoded private key data. got :%d, need :%d", len(data), PrivateKeySize)
// 	}
// 	skv, err := sf.FromBytes(data)
// 	if err != nil {
// 		return nil, errs.WrapSerialisation(err, "failed to create scalar from bytes")
// 	}
// 	privateKey, err := NewPrivateKey(skv)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to create private key")
// 	}
// 	return privateKey, nil
// }

// func EncodeSignature(signature *Signature) (base58.Base58, error) {
// 	if signature == nil {
// 		return "", errs.NewIsNil("signature is nil")
// 	}
// 	data, err := SerializeSignature(signature)
// 	if err != nil {
// 		return "", errs.WrapSerialisation(err, "failed to serialize signature")
// 	}
// 	enc := base58.NewEncoder(SignatureBase58VersionPrefix)
// 	return enc.Encode(data), nil
// }

// func DecodeSignature(s base58.Base58) (*Signature, error) {
// 	dec := base58.NewEncoder(SignatureBase58VersionPrefix)
// 	data, err := dec.Decode(s)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to decode signature")
// 	}
// 	if len(data) != SignatureSize {
// 		return nil, errs.NewLength("decoded signature data. got :%d, need :%d", len(data), SignatureSize)
// 	}
// 	sig, err := DeserializeSignature(data)
// 	if err != nil {
// 		return nil, errs.WrapSerialisation(err, "failed to deserialize signature")
// 	}
// 	return sig, nil
// }
