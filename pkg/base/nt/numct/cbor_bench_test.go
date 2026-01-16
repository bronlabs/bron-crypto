package numct_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

func BenchmarkNat_CBOR(b *testing.B) {
	n := numct.NewNat(1234567890)

	b.Run("Marshal", func(b *testing.B) {
		b.ResetTimer()
		for range b.N {
			_, err := n.MarshalCBOR()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	data, _ := n.MarshalCBOR()

	b.Run("Unmarshal", func(b *testing.B) {
		var recovered numct.Nat
		b.ResetTimer()
		for range b.N {
			err := recovered.UnmarshalCBOR(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkModulus_CBOR(b *testing.B) {
	n := numct.NewNat(65537)
	m, _ := numct.NewModulus(n)

	b.Run("Marshal", func(b *testing.B) {
		b.ResetTimer()
		for range b.N {
			_, err := m.MarshalCBOR()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	data, _ := m.MarshalCBOR()

	b.Run("Unmarshal", func(b *testing.B) {
		var recovered numct.Modulus
		b.ResetTimer()
		for range b.N {
			err := recovered.UnmarshalCBOR(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
