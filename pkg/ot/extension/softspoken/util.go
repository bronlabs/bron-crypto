package softspoken

import (
	"strconv"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

// HashSalted hashes the κ-bit length rows of a [L*ξ][κ] bit matrix, outputting
// rows of κ bits in a [L][ξ][κ] bit matrix. sid is used as a salt.
func HashSalted(sid []byte, bufferIn [][]byte,
	bufferOut [][Xi][KappaBytes]byte,
) (err error) {
	L := len(bufferOut)
	eta := len(bufferIn) // η = L*ξ
	if eta != L*Xi {
		return errs.NewInvalidArgument("input sizes don't match (%d != %d)", eta, L*Xi)
	}
	for l := 0; l < L; l++ {
		for i := 0; i < Xi; i++ {
			if len(bufferIn[i]) != KappaBytes {
				return errs.NewInvalidArgument("input slice bit-size is not Kappa")
			}
			digest, err := hashing.Hash(sha3.New256, []byte("Copper_Softspoken_COTe"), sid, []byte(strconv.Itoa(i)), bufferIn[l*Xi+i])
			if err != nil {
				return errs.WrapFailed(err, "writing into HashSalted")
			}
			copy(bufferOut[l][i][:], digest)
		}
	}
	return nil
}
