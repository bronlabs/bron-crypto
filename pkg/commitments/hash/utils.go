package hash_comm

import (
	"encoding/binary"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

func NewCommittingKeyFromCrsBytes(sessionId []byte, crs ...[]byte) (*CommittingKey, error) {
	h, err := blake2b.New256(sessionId)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create hash")
	}
	for _, c := range crs {
		_, err = h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(c))))
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create committing key")
		}
		_, err = h.Write(c)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create committing key")
		}
	}
	sum := h.Sum(nil)
	var key [blake2b.Size256]byte
	copy(key[:], sum)

	return NewCommittingKey(key), nil
}
