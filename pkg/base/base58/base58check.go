package base58

// import (
// 	"crypto/sha256"
// 	"fmt"

// 	"github.com/bronlabs/bron-crypto/pkg/base/ct"
// 	"github.com/bronlabs/bron-crypto/pkg/base/errs"
// ).

// const (
// 	ChecksumLen          int = 4
// 	VersionLen           int = 1
// 	minimumDecodedLength     = VersionLen + ChecksumLen
// ).

// type (
// 	VersionPrefix byte
// 	Checksum      [ChecksumLen]byte
// ).

// func (c Checksum) Equal(other Checksum) bool {
// 	return ct.SliceEqual(c[:], other[:]) == 1
// }.

// func DeriveChecksum(input []byte) (cksum Checksum) {
// 	h := sha256.Sum256(input)
// 	h2 := sha256.Sum256(h[:])
// 	copy(cksum[:], h2[:ChecksumLen])
// 	return
// }.

// func CheckEncode(input []byte, version VersionPrefix) Base58 {
// 	b := make([]byte, 0, VersionLen+len(input)+ChecksumLen)
// 	b = append(b, byte(version))
// 	b = append(b, input...)
// 	cksum := DeriveChecksum(b)
// 	b = append(b, cksum[:]...)
// 	return Encode(b)
// }.

// func CheckDecode(input Base58) (result []byte, version VersionPrefix, err error) {
// 	decoded := Decode(input)
// 	fmt.Println(">>>>>", len(decoded), decoded)
// 	if len(decoded) < minimumDecodedLength {
// 		return nil, 0, errs.NewLength("decoded input too short for Base58")
// 	}
// 	version = VersionPrefix(decoded[0])

// 	var decodedChecksum [ChecksumLen]byte
// 	copy(decodedChecksum[:], decoded[len(decoded)-ChecksumLen:])

// 	versionAndPayload := decoded[:len(decoded)-ChecksumLen]
// 	recomputedChecksum := DeriveChecksum(versionAndPayload)

// 	if !recomputedChecksum.Equal(decodedChecksum) {
// 		return nil, 0, errs.NewVerification("checksum mismatch")
// 	}
// 	result = versionAndPayload[VersionLen:]
// 	return
// }.
