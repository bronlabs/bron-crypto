package rsa

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"reflect"
	"runtime"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var (
	_ Padding = (*pkcs1v15Padding)(nil)
)

type pkcs1v15Padding struct {
}

func NewPKCS1v15Padding() Padding {
	return &pkcs1v15Padding{}
}

func (p *pkcs1v15Padding) HashAndPad(bitLen int, hashFunc func() hash.Hash, message []byte) (*saferith.Nat, error) {
	hasher := hashFunc()
	hasher.Write(message)
	hashed := hasher.Sum(nil)

	hashName := runtime.FuncForPC(reflect.ValueOf(hashFunc).Pointer()).Name()
	chash, ok := hashFuncToCryptoHash[hashName]
	if !ok {
		return nil, errs.NewFailed("unsupported hash func")
	}

	hashLen, prefix, err := p.hashInfo(chash, len(hashed))
	if err != nil {
		return nil, err
	}

	tLen := len(prefix) + hashLen
	k := (bitLen + 7) / 8
	if k < tLen+11 {
		return nil, errs.NewFailed("message too long for RSA key size")
	}

	// EM = 0x00 || 0x01 || PS || 0x00 || T
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-tLen:k-hashLen], prefix)
	copy(em[k-hashLen:k], hashed)

	return new(saferith.Nat).SetBytes(em), nil
}

func (*pkcs1v15Padding) hashInfo(chash crypto.Hash, inLen int) (hashLen int, prefix []byte, err error) {
	hashLen = chash.Size()
	if inLen != hashLen {
		return 0, nil, errs.NewFailed("input must be hashed message")
	}
	prefix, ok := hashPrefixes[chash]
	if !ok {
		return 0, nil, errs.NewFailed("unsupported hash function")
	}
	return hashLen, prefix, nil
}

var hashFuncToCryptoHash = map[string]crypto.Hash{
	runtime.FuncForPC(reflect.ValueOf(sha256.New).Pointer()).Name(): crypto.SHA256,
	runtime.FuncForPC(reflect.ValueOf(sha512.New).Pointer()).Name(): crypto.SHA512,
}

//nolint:exhaustive // prototype
var hashPrefixes = map[crypto.Hash][]byte{
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}
