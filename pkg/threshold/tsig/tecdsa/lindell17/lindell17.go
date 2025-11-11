package lindell17

import (
	"encoding/binary"
	"slices"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

const Threshold = 2

type PartialSignature struct {
	C3 *paillier.Ciphertext
}

func NewPartialSignature(c3 *paillier.Ciphertext) (*PartialSignature, error) {
	if c3 == nil {
		return nil, errs.NewIsNil("invalid ciphertext")
	}
	return &PartialSignature{C3: c3}, nil
}

// sorted quorum IDs in big-endian format, used for commitment scheme CRS and dlog proofs.
func QuorumBytes(quorum ds.Set[sharing.ID]) [][]byte {
	if quorum == nil || quorum.Size() == 0 {
		return nil
	}
	bigS := make([][]byte, quorum.Size())
	for i, id := range slices.Sorted(quorum.Iter()) {
		bigS[i] = binary.BigEndian.AppendUint64(nil, uint64(id))
	}
	return bigS
}
