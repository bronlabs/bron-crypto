package serde_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

type registeredType struct {
	Value uint64
}

type concurrentRegisteredType struct {
	Value uint64
}

func TestUnmarshalCBORRequiresRegisteredTag(t *testing.T) {
	t.Parallel()

	const tag = 61001
	serde.Register[registeredType](tag)

	encoded, err := cbor.Marshal(registeredType{Value: 7})
	require.NoError(t, err)

	_, err = serde.UnmarshalCBOR[registeredType](encoded)
	require.Error(t, err)

	tagged, err := serde.MarshalCBOR(registeredType{Value: 7})
	require.NoError(t, err)

	decoded, err := serde.UnmarshalCBOR[registeredType](tagged)
	require.NoError(t, err)
	require.Equal(t, registeredType{Value: 7}, decoded)
}

func TestMarshalCBORMarshalsExplicitCBORTag(t *testing.T) {
	t.Parallel()

	const tag = 61002

	data, err := serde.MarshalCBOR(cbor.Tag{
		Number:  tag,
		Content: struct{ Value uint64 }{Value: 5},
	})
	require.NoError(t, err)

	var wrapped cbor.Tag
	err = cbor.Unmarshal(data, &wrapped)
	require.NoError(t, err)
	require.Equal(t, uint64(tag), wrapped.Number)
}

func TestConcurrentRegisterAndMarshal(t *testing.T) {
	t.Parallel()

	const tag = 61003
	var registerOnce sync.Once
	var wg sync.WaitGroup
	errCh := make(chan error, 32)

	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			registerOnce.Do(func() {
				serde.Register[concurrentRegisteredType](tag)
			})
			data, err := serde.MarshalCBOR(concurrentRegisteredType{Value: 11})
			if err != nil {
				errCh <- err
				return
			}
			decoded, err := serde.UnmarshalCBOR[concurrentRegisteredType](data)
			if err != nil {
				errCh <- err
				return
			}
			if decoded != (concurrentRegisteredType{Value: 11}) {
				errCh <- fmt.Errorf("unexpected decoded value: %+v", decoded)
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}
