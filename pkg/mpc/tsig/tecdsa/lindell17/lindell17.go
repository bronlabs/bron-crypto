package lindell17

import (
	"encoding/binary"
	"slices"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// Threshold is the Lindell17 tECDSA threshold.
const Threshold = 2

// QuorumBytes returns sorted quorum IDs in big-endian byte format.
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
