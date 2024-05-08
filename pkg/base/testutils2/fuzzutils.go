package testutils2

import (
	"bytes"
	"encoding/gob"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/fkechacha20"
	"github.com/stretchr/testify/require"
)

const prngSalt = "KRYPTON_FUZZUTIL_PRNG_SALT-"

type fuzzerPrng = fkechacha20.Prng

var defaultSeed = make([]byte, fkechacha20.ChachaPRNGSecurityStrength)

func NewPrng(seed []byte) (csprng.Seedable, error) {
	if len(seed) == 0 {
		seed = defaultSeed
	}
	return fkechacha20.NewPrng(seed, []byte(prngSalt))
}

func SerializeForCorpus(f *testing.F, x any, gobRegister func()) []byte {
	f.Helper()
	gobRegister()
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(x)
	require.NoError(f, err)
	return buf.Bytes()
}
