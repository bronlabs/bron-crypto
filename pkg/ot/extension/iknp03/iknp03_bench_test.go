package iknp03_test

import (
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/iknp03"
)

// benchLengths are the extension lengths l the protocol is benchmarked on.
var benchLengths = []int{1024, 1 << 16}

// BenchmarkIKNP03 times one extension (both parties, in process, messages
// passed without serialisation) per iteration and reports the time per OT,
// for 128-bit and 256-bit rows. The base OTs are synthetic and excluded; the
// participants, and so the PRG streams, are created inside the loop because
// an extension advances them.
func BenchmarkIKNP03(b *testing.B) {
	for _, l := range benchLengths {
		b.Run(fmt.Sprintf("L=%d/K=%d", l, ot.MessageBitLen[ot.Message128]()), func(b *testing.B) {
			benchmarkIKNP03[ot.Message128](b, l)
		})
		b.Run(fmt.Sprintf("L=%d/K=%d", l, ot.MessageBitLen[ot.Message256]()), func(b *testing.B) {
			benchmarkIKNP03[ot.Message256](b, l)
		})
	}
}

func benchmarkIKNP03[M ot.Message](b *testing.B, l int) {
	b.Helper()
	prng := pcg.NewRandomised()
	baseReceiverOut, baseSenderOut := syntheticBaseOTs(b, prng, ot.MessageBitLen[M]())
	choices := make(ot.Choices, l/8)
	_, err := io.ReadFull(prng, choices)
	require.NoError(b, err)

	for b.Loop() {
		ctxs := twoPartyContexts(b, prng)
		sender, err := iknp03.NewSender[M](ctxs[extSenderID], baseReceiverOut)
		require.NoError(b, err)
		receiver, err := iknp03.NewReceiver[M](ctxs[extReceiverID], baseSenderOut)
		require.NoError(b, err)

		_, message, _, err := receiver.Extend(choices)
		require.NoError(b, err)
		_, _, err = sender.Extend(message)
		require.NoError(b, err)
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(l), "ns/OT")
}
