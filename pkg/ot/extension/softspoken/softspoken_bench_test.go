package softspoken_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
)

// benchLengths are the numbers of random OTs l one extension is benchmarked
// on; the extension adds its 128 check rows on top.
var benchLengths = []int{1024, 1 << 15}

// BenchmarkSoftSpoken times one extension (both parties, in process, messages
// passed without serialisation) per iteration and reports the time per OT:
// the IKNP03 columns, the consistency check and the randomisation of l rows.
// The base OTs are synthetic and excluded; the participants, and so the PRG
// streams, are created inside the loop because an extension advances them.
func BenchmarkSoftSpoken(b *testing.B) {
	for _, l := range benchLengths {
		b.Run(fmt.Sprintf("L=%d", l), func(b *testing.B) {
			benchmarkSoftSpoken(b, l)
		})
	}
}

func benchmarkSoftSpoken(b *testing.B, l int) {
	b.Helper()
	prng := pcg.NewRandomised()
	baseReceiverOut, baseSenderOut := syntheticBaseOTs(b, prng, kappa)

	for b.Loop() {
		ctxs := twoPartyContexts(b, prng)
		sender, err := softspoken.NewSender(ctxs[extSenderID], baseReceiverOut)
		require.NoError(b, err)
		receiver, err := softspoken.NewReceiver(ctxs[extReceiverID], baseSenderOut, prng)
		require.NoError(b, err)

		_, message, err := receiver.Extend(l)
		require.NoError(b, err)
		_, err = sender.Extend(message)
		require.NoError(b, err)
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(l), "ns/OT")
}
