package keyedblock

import (
	"crypto/aes"
	crand "crypto/rand"
	"time"

	"github.com/copperexchange/krypton/pkg/base/errs"
)

func BenchmarkKeyedAes() (t_faes, t_aes int64, err error) {
	numRounds := int64(1000)
	t_faes, t_aes = int64(0), int64(0)
	input, output, ctxt, key := make([]byte, 16), make([]byte, 16), make([]byte, 16), make([]byte, 16)

	for i := int64(0); i < numRounds; i++ {
		if _, err = crand.Read(input); err != nil {
			return 0, 0, errs.WrapFailed(err, "Bench failed")
		}
		if _, err = crand.Read(key); err != nil {
			return 0, 0, errs.WrapFailed(err, "Bench failed")
		}
		c1, err := NewKeyedCipher(key)
		if err != nil {
			return 0, 0, errs.WrapFailed(err, "Bench failed")
		}
		t0 := time.Now()
		c1.SetKey(key)
		c1.Encrypt(ctxt, input)
		t_faes += time.Since(t0).Nanoseconds()
		c1.Decrypt(output, ctxt)

		t0 = time.Now()
		c2, err := aes.NewCipher(key)
		if err != nil {
			return 0, 0, errs.WrapFailed(err, "Bench failed")
		}
		c2.Encrypt(ctxt, input)
		t_aes += time.Since(t0).Nanoseconds()
		c2.Decrypt(output, ctxt)
	}
	t_faes /= numRounds
	t_aes /= numRounds
	return t_faes, t_aes, nil
}
