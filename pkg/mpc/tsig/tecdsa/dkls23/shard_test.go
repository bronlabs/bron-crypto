package dkls23_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
)

func TestAuxiliaryInfoEqualIncludesReceiverSeeds(t *testing.T) {
	t.Parallel()

	senderSeeds := hashmap.NewComparable[sharing.ID, *vsot.SenderOutput]()
	senderSeeds.Put(1, &vsot.SenderOutput{
		SenderOutput: ot.SenderOutput[[]byte]{
			Messages: [][2][][]byte{
				{
					{[]byte{1}},
					{[]byte{2}},
				},
			},
		},
	})

	receiverSeedsA := hashmap.NewComparable[sharing.ID, *vsot.ReceiverOutput]()
	receiverSeedsA.Put(1, &vsot.ReceiverOutput{
		ReceiverOutput: ot.ReceiverOutput[[]byte]{
			Choices:  []byte{0x80},
			Messages: [][][]byte{{{3}}},
		},
	})
	receiverSeedsB := hashmap.NewComparable[sharing.ID, *vsot.ReceiverOutput]()
	receiverSeedsB.Put(1, &vsot.ReceiverOutput{
		ReceiverOutput: ot.ReceiverOutput[[]byte]{
			Choices:  []byte{0x00},
			Messages: [][][]byte{{{3}}},
		},
	})

	left, err := dkls23.NewAuxiliaryInfo(senderSeeds.Freeze(), receiverSeedsA.Freeze())
	require.NoError(t, err)
	right, err := dkls23.NewAuxiliaryInfo(senderSeeds.Freeze(), receiverSeedsB.Freeze())
	require.NoError(t, err)

	require.False(t, left.Equal(right))
}
