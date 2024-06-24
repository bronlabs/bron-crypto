package rb_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/rb"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/hpke"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"testing"
	"time"
)

func Test_SimulatorAuth(t *testing.T) {
	const n = 3

	sessionId := "testSessionId"
	identities := make([]types.IdentityKey, n)
	for i := range identities {
		var err error
		identities[i], err = rb.NewAuthIdentity()
		require.NoError(t, err)
	}

	// every participant sends 1 message to every other, and receives one message from every other
	participantRunner := func(idIdx int) {
		me := identities[idIdx]
		coordinator, err := rb.DialCoordinatorSimulator(sessionId, identities[idIdx].(types.AuthKey), identities)
		auth := rb.NewSimulatorAuth(coordinator)
		require.NoError(t, err)

		// send
		for _, them := range identities {
			if me.Equal(them) {
				continue
			}
			err = auth.Send(them, []byte(fmt.Sprintf("%s -> %s", me.String(), them.String())))
			require.NoError(t, err)
		}

		// receive
		received := make(map[string][]byte)
		for i := 0; i < len(identities)-1; i++ {
			from, message, err := auth.Receive()
			require.NoError(t, err)
			fmt.Printf("%s: Received '%s' from %s\n", me.String(), string(message), from.String())
			if _, ok := received[from.String()]; ok {
				require.Fail(t, "duplicated message from ", from.String())
			}
			received[from.String()] = message
		}

		// check
		require.Len(t, received, n-1)
		for _, id := range identities {
			if id.Equal(me) {
				continue
			}
			if _, ok := received[id.String()]; !ok {
				require.Fail(t, "no message from %s", id.String())
			}
		}
	}

	errChan := make(chan error)
	go func() {
		var group errgroup.Group
		for i := range n {
			group.Go(func() error {
				participantRunner(i)
				return nil
			})
		}
		errChan <- group.Wait()
	}()

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(1 * time.Second):
		require.Fail(t, "timeout")
	}
}

func Test_SealOpen(t *testing.T) {
	sk1, err := p256.NewCurve().ScalarField().Random(crand.Reader)
	require.NoError(t, err)
	pk1 := p256.NewCurve().ScalarBaseMult(sk1)

	sk2, err := p256.NewCurve().ScalarField().Random(crand.Reader)
	require.NoError(t, err)
	pk2 := p256.NewCurve().ScalarBaseMult(sk2)

	cs := &hpke.CipherSuite{
		KDF:  hpke.KDF_HKDF_SHA256,
		KEM:  hpke.DHKEM_P256_HKDF_SHA256,
		AEAD: hpke.AEAD_CHACHA_20_POLY_1305,
	}

	plainText := []byte("Hello")
	cipherText, epk, err := hpke.Seal(hpke.Auth, cs, plainText, []byte("aad"), pk2, &hpke.PrivateKey{D: sk1, PublicKey: pk1}, nil, nil, nil, crand.Reader)
	require.NoError(t, err)

	decrypted, err := hpke.Open(hpke.Auth, cs, cipherText, []byte("aad"), &hpke.PrivateKey{D: sk2, PublicKey: pk2}, epk, pk1, nil, nil, nil)
	require.NoError(t, err)

	require.Equal(t, plainText, decrypted)
}
