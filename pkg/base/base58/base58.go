package base58

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/errs-go/pkg/errs"
)

const (
	Alphabet     string = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	alphabetIdx0 byte   = '1'
)

type Base58 string

func (b Base58) Equal(other Base58) bool {
	return ct.SliceEqual([]byte(b), []byte(other)) == 1
}

var (
	radix58 = num.N().FromUint64(58)
	zero    = num.N().FromUint64(0)
	one     = num.N().FromUint64(1)
	// Pre-computed table: ASCII → 0–57 (invalid = 0xFF)
	// Initialise once in init().
	b58 [256]byte
)

func init() { //nolint:gochecknoinits // initialises base58 decoding table
	for i := range b58 {
		b58[i] = 0xFF
	}
	for i, char := range Alphabet {
		b58[char] = byte(i)
	}
	if alphabetIdx0 != Alphabet[0] {
		panic(errs.New("alphabetIdx0 must be the first character of the alphabet"))
	}
}

func Encode(data []byte) Base58 {
	x, err := num.N().FromBytes(data)
	if err != nil {
		panic(errs.Wrap(err).WithMessage("failed to convert bytes to Nat"))
	}
	answer := make([]byte, 0, len(data)*136/100)
	var rem *num.Nat
	for x.Compare(zero).Is(base.GreaterThan) {
		x, rem, err = x.EuclideanDiv(radix58)
		if err != nil {
			panic(errs.Wrap(err).WithMessage("failed to perform division"))
		}
		answer = append(answer, Alphabet[rem.Uint64()])
	}
	for range utils.LeadingZeroBytes(data) {
		answer = append(answer, alphabetIdx0)
	}
	sliceutils.Reverse(answer)
	return Base58(string(answer))
}

func Decode(s Base58) []byte {
	answer := zero
	j := one

	for i := len(s) - 1; i >= 0; i-- {
		tmp := b58[s[i]]
		if tmp == 0xFF {
			return []byte("")
		}
		scratch := num.N().FromUint64(uint64(tmp)).Mul(j)
		answer = answer.Add(scratch)
		j = j.Mul(radix58)
	}

	tmpval := answer.Big().Bytes()

	var leadingZerosCount int
	for leadingZerosCount = 0; leadingZerosCount < len(s) && s[leadingZerosCount] == alphabetIdx0; leadingZerosCount++ { //nolint:revive // empty block is intentional.
		// count leading zeros
	}
	flen := leadingZerosCount + len(tmpval)
	val := make([]byte, flen)
	copy(val[leadingZerosCount:], tmpval)
	return val
}
