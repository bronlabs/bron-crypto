package rvole

import (
	"crypto/sha3"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

// expandLabel is the cSHAKE256 function name of the row expansion.
const expandLabel = "BRON_CRYPTO-RVOLE-EXPAND"

// expand stretches the output of one random OT into n field elements: cSHAKE256
// with the key as the input and expandLabel as the function name produces n
// wide encodings, each reduced into the field without bias. The key is uniform,
// secret to the party that does not hold it, and used for exactly one
// expansion, so no further domain separation is needed; the expansion is a PRG
// when cSHAKE256 is modelled as a random oracle.
func expand[S algebra.PrimeFieldElement[S], M ot.Message](field algebra.PrimeField[S], key M, n int) ([]S, error) {
	xof := sha3.NewCSHAKE256([]byte(expandLabel), nil)
	if _, err := xof.Write(ot.MessageAsSlice(&key)); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot absorb the key")
	}
	wide := field.WideElementSize()
	buf := make([]byte, n*wide)
	if _, err := io.ReadFull(xof, buf); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot squeeze the expansion")
	}

	out := make([]S, n)
	for i := range n {
		var err error
		out[i], err = field.FromWideBytes(buf[i*wide : (i+1)*wide])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot reduce element %d into the field", i)
		}
	}
	return out, nil
}
