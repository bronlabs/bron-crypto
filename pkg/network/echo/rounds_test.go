package echo_test

import (
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/echo"
	"github.com/bronlabs/bron-crypto/pkg/network/testutils"
)

type dummyParticipant struct{}

type dummyMessage uint64

func (m dummyMessage) Validate(p *dummyParticipant, _ sharing.ID) error {
	if m == 0 {
		return network.ErrMissing.WithMessage("zero message")
	}
	return nil
}

func TestHappyPath(t *testing.T) {
	t.Parallel()
	ids := sharing.NewOrdinalShareholderSet(3)
	parties := []*echo.Participant[dummyMessage, *dummyParticipant]{}
	for id := range ids.Iter() {
		p, err := echo.NewParticipant[dummyMessage, *dummyParticipant](id, ids)
		require.NoError(t, err)
		parties = append(parties, p)
	}

	var err error
	r1 := make(map[sharing.ID]network.OutgoingUnicasts[*echo.Round1P2P[dummyMessage, *dummyParticipant], *echo.Participant[dummyMessage, *dummyParticipant]])
	for _, p := range parties {
		r1[p.SharingID()], err = p.Round1(dummyMessage(rand.Uint64()))
		require.NoError(t, err)
	}
	r2In := ntu.MapUnicastO2I(t, parties, r1)

	r2 := make(map[sharing.ID]network.OutgoingUnicasts[*echo.Round2P2P[dummyMessage, *dummyParticipant], *echo.Participant[dummyMessage, *dummyParticipant]])
	for _, p := range parties {
		r2[p.SharingID()], err = p.Round2(r2In[p.SharingID()])
		require.NoError(t, err)
	}
	r3In := ntu.MapUnicastO2I(t, parties, r2)

	for _, p := range parties {
		_, err := p.Round3(r3In[p.SharingID()])
		require.NoError(t, err)
	}
}

func TestEquivocationDetected(t *testing.T) {
	t.Parallel()
	ids := sharing.NewOrdinalShareholderSet(3)
	parties := []*echo.Participant[dummyMessage, *dummyParticipant]{}
	for id := range ids.Iter() {
		p, err := echo.NewParticipant[dummyMessage, *dummyParticipant](id, ids)
		require.NoError(t, err)
		parties = append(parties, p)
	}

	var err error
	r1 := make(map[sharing.ID]network.OutgoingUnicasts[*echo.Round1P2P[dummyMessage, *dummyParticipant], *echo.Participant[dummyMessage, *dummyParticipant]])
	for i, p := range parties {
		r1[p.SharingID()], err = p.Round1(dummyMessage(i + 1))
		require.NoError(t, err)
	}

	forged, err := serde.MarshalCBOR(dummyMessage(42))
	require.NoError(t, err)
	m, ok := r1[parties[0].SharingID()].Get(parties[1].SharingID())
	require.True(t, ok)
	m.Payload = forged

	r2In := ntu.MapUnicastO2I(t, parties, r1)

	r2 := make(map[sharing.ID]network.OutgoingUnicasts[*echo.Round2P2P[dummyMessage, *dummyParticipant], *echo.Participant[dummyMessage, *dummyParticipant]])
	for _, p := range parties {
		r2[p.SharingID()], err = p.Round2(r2In[p.SharingID()])
		require.NoError(t, err)
	}
	r3In := ntu.MapUnicastO2I(t, parties, r2)

	_, err = parties[0].Round3(r3In[parties[0].SharingID()])
	require.NoError(t, err)
	for _, p := range parties[1:] {
		_, err := p.Round3(r3In[p.SharingID()])
		require.ErrorContains(t, err, "mismatched echo")
	}
}
