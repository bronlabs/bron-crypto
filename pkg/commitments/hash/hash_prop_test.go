package hash_comm_test

import (
	"bytes"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/prng"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/commitments/testutils/properties"
	"pgregory.net/rapid"
)

func CommitmentKeyGenerator() *rapid.Generator[*hash_comm.CommitmentKey] {
	return rapid.Custom(func(t *rapid.T) *hash_comm.CommitmentKey {
		b := rapid.SliceOfN(rapid.Byte(), hash_comm.KeySize, hash_comm.KeySize).Draw(t, "commitment key bytes")
		var out hash_comm.CommitmentKey
		copy(out[:], b)
		return &out
	})
}

func CommitmentGenerator(tb testing.TB, _ commitments.CommitmentKey[*hash_comm.CommitmentKey, hash_comm.Message, hash_comm.Witness, hash_comm.Commitment]) *rapid.Generator[hash_comm.Commitment] {
	tb.Helper()
	return rapid.Custom(func(t *rapid.T) hash_comm.Commitment {
		b := rapid.SliceOfN(rapid.Byte(), hash_comm.DigestSize, hash_comm.DigestSize).Draw(t, "commitment bytes")
		var out hash_comm.Commitment
		copy(out[:], b)
		return out
	})
}

func MessageGenerator(tb testing.TB, _ commitments.CommitmentKey[*hash_comm.CommitmentKey, hash_comm.Message, hash_comm.Witness, hash_comm.Commitment]) *rapid.Generator[hash_comm.Message] {
	tb.Helper()
	return rapid.Custom(func(t *rapid.T) hash_comm.Message {
		return hash_comm.Message(rapid.SliceOfN(rapid.Byte(), 0, 32).Draw(t, "message bytes"))
	})
}

func WitnessGenerator(tb testing.TB, _ commitments.CommitmentKey[*hash_comm.CommitmentKey, hash_comm.Message, hash_comm.Witness, hash_comm.Commitment]) *rapid.Generator[hash_comm.Witness] {
	tb.Helper()
	return rapid.Custom(func(t *rapid.T) hash_comm.Witness {
		b := rapid.SliceOfN(rapid.Byte(), hash_comm.DigestSize, hash_comm.DigestSize).Draw(t, "witness bytes")
		var out hash_comm.Witness
		copy(out[:], b)
		return out
	})
}

func CommitmentKeyPropertySuite(tb testing.TB) *properties.CommitmentKeyProperties[*hash_comm.CommitmentKey, hash_comm.Message, hash_comm.Witness, hash_comm.Commitment] {
	tb.Helper()
	return &properties.CommitmentKeyProperties[*hash_comm.CommitmentKey, hash_comm.Message, hash_comm.Witness, hash_comm.Commitment]{
		PRNG:             prng.PRNGFuncTypeErase(pcg.NewRandomised),
		KeyGenerator:     CommitmentKeyGenerator(),
		MessageGenerator: MessageGenerator,
		MessagesAreEqual: func(m1, m2 hash_comm.Message) bool {
			return bytes.Equal(m1, m2)
		},
		WitnessesAreEqual: func(w1, w2 hash_comm.Witness) bool {
			return bytes.Equal(w1[:], w2[:])
		},
	}
}

func WitnessPropertySuite(tb testing.TB) *properties.WitnessProperties[hash_comm.Witness] {
	tb.Helper()
	return &properties.WitnessProperties[hash_comm.Witness]{
		WitnessGenerator: WitnessGenerator(tb, nil),
		WitnessesAreEqual: func(w1, w2 hash_comm.Witness) bool {
			return bytes.Equal(w1[:], w2[:])
		},
	}
}

func MessagePropertySuite(tb testing.TB) *properties.MessageProperties[hash_comm.Message] {
	tb.Helper()
	return &properties.MessageProperties[hash_comm.Message]{
		MessageGenerator: MessageGenerator(tb, nil),
		MessagesAreEqual: func(m1, m2 hash_comm.Message) bool {
			return bytes.Equal(m1, m2)
		},
	}
}

func CommitmentPropertySuite(tb testing.TB) *properties.CommitmentProperties[hash_comm.Commitment] {
	tb.Helper()
	return &properties.CommitmentProperties[hash_comm.Commitment]{
		CommitmentGenerator: CommitmentGenerator(tb, nil),
		CommitmentsAreEqual: func(c1, c2 hash_comm.Commitment) bool {
			return bytes.Equal(c1[:], c2[:])
		},
	}
}

func TestCommitmentKeyProperties(t *testing.T) {
	CommitmentKeyPropertySuite(t).CheckAll(t)
}

func TestWitnessProperties(t *testing.T) {
	WitnessPropertySuite(t).CheckAll(t)
}

func TestMessageProperties(t *testing.T) {
	MessagePropertySuite(t).CheckAll(t)
}

func TestCommitmentProperties(t *testing.T) {
	CommitmentPropertySuite(t).CheckAll(t)
}
