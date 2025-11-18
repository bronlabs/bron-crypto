package base58

import (
	"crypto/sha256"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
)

const (
	ChecksumLen          int = 4
	VersionLen           int = 1
	minimumDecodedLength     = VersionLen + ChecksumLen
)

var (
	ErrChecksumMismatch = errs2.New("checksum mismatch")
	ErrInvalidLength    = errs2.New("decoded input too short for Base58")
)

type (
	VersionPrefix byte
	Checksum      [ChecksumLen]byte
)

func (c Checksum) Equal(other Checksum) bool {
	return ct.SliceEqual(c[:], other[:]) == 1
}

func DeriveChecksum(input []byte) (cksum Checksum) {
	h := sha256.Sum256(input)
	h2 := sha256.Sum256(h[:])
	copy(cksum[:], h2[:ChecksumLen])
	return
}

func CheckEncode(input []byte, version VersionPrefix) Base58 {
	b := make([]byte, 0, VersionLen+len(input)+ChecksumLen)
	b = append(b, byte(version))
	b = append(b, input...)
	cksum := DeriveChecksum(b)
	b = append(b, cksum[:]...)
	return Encode(b)
}

func CheckDecode(input Base58) (result []byte, version VersionPrefix, err error) {
	decoded := Decode(input)
	if len(decoded) < minimumDecodedLength {
		return nil, 0, ErrInvalidLength.WithStackTrace()
	}
	version = VersionPrefix(decoded[0])

	var decodedChecksum [ChecksumLen]byte
	copy(decodedChecksum[:], decoded[len(decoded)-ChecksumLen:])

	versionAndPayload := decoded[:len(decoded)-ChecksumLen]
	recomputedChecksum := DeriveChecksum(versionAndPayload)

	if !recomputedChecksum.Equal(decodedChecksum) {
		return nil, 0, ErrChecksumMismatch.WithStackTrace()
	}
	result = versionAndPayload[VersionLen:]
	return
}
