package softspoken

import (
	"strconv"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton/pkg/base/errs"
)

// HashSalted hashes the κ-bit length rows of a [L*ξ][κ] bit matrix, outputting
// rows of ω×κ bits in a [L][ξ][ω][κ] bit matrix (an expansion of 1:ω). sid is
// used as a salt.
func HashSalted(sid []byte, bufferIn [][]byte,
	bufferOut [][Xi][ROTeWidth][KappaBytes]byte,
) (e error) {
	L := len(bufferOut)
	eta := len(bufferIn) // η = L*ξ
	if eta != L*Xi {
		return errs.NewInvalidArgument("input sizes don't match")
	}
	flatBufferOut := make([]byte, ROTeWidth*KappaBytes)
	for l := 0; l < L; l++ {
		for i := 0; i < Xi; i++ {
			if len(bufferIn[i]) != KappaBytes {
				return errs.NewInvalidArgument("input slice bit-size is not Kappa")
			}
			hash := sha3.NewCShake256(sid, []byte("Copper_Softspoken_COTe"))
			if _, err := hash.Write([]byte(strconv.Itoa(i))); err != nil {
				return errs.WrapFailed(err, "writing index into HashSalted")
			}
			if _, err := hash.Write(bufferIn[l*Xi+i]); err != nil {
				return errs.WrapFailed(err, "writing input to HashSalted")
			}
			if _, err := hash.Read(flatBufferOut); err != nil {
				return errs.WrapFailed(err, "reading digest from HashSalted")
			}
			for k := 0; k < ROTeWidth; k++ {
				copy(bufferOut[l][i][k][:], flatBufferOut[k*KappaBytes:(k+1)*KappaBytes])
			}
		}
	}
	return nil
}
