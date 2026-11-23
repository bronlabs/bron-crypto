package mrr21_test

import (
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/mrr21"
)

// benchBatches are the batch sizes L the protocol is benchmarked on.
var benchBatches = []int{128, 1024}

// BenchmarkMRR21 times one full run of the protocol (both parties, in process,
// messages passed without serialisation) per iteration and reports the time
// per OT. Session contexts are created inside the loop because a run consumes
// the transcript; their cost is small compared to the curve arithmetic.
func BenchmarkMRR21(b *testing.B) {
	for _, l := range benchBatches {
		b.Run(fmt.Sprintf("k256/L=%d/K=%d", l, ot.MessageBitLen[ot.Message128]()), func(b *testing.B) {
			benchmarkMRR21[ot.Message128](b, k256.NewCurve(), l)
		})
	}
}

func benchmarkMRR21[M ot.Message, G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](b *testing.B, group algebra.PrimeGroup[G, S], l int) {
	b.Helper()
	prng := pcg.NewRandomised()
	choices := make(ot.Choices, l/8)
	_, err := io.ReadFull(prng, choices)
	require.NoError(b, err)

	for b.Loop() {
		ctxs := twoPartyContexts(b, prng)
		sender, err := mrr21.NewSender[M](ctxs[senderID], group, l, prng)
		require.NoError(b, err)
		receiver, err := mrr21.NewReceiver[M](ctxs[receiverID], group, l, prng)
		require.NoError(b, err)

		senderMsg, err := sender.Round1()
		require.NoError(b, err)
		receiverMsg, err := receiver.Round1(choices)
		require.NoError(b, err)
		_, err = sender.Round2(receiverMsg)
		require.NoError(b, err)
		_, err = receiver.Round2(senderMsg)
		require.NoError(b, err)
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(l), "ns/OT")
}
