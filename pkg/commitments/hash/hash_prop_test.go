package hash_comm_test

import (
	"bytes"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/prng"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/commitments/properties"
	"pgregory.net/rapid"
)

func CommitmentKeyGenerator() *rapid.Generator[hash_comm.CommitmentKey] {
	return rapid.Custom(func(t *rapid.T) hash_comm.CommitmentKey {
		b := rapid.SliceOfN(rapid.Byte(), hash_comm.DigestSize, hash_comm.DigestSize).Draw(t, "commitment key bytes")
		var out hash_comm.CommitmentKey
		copy(out[:], b)
		return out
	})
}

func CommitmentGenerator() *rapid.Generator[hash_comm.Commitment] {
	return rapid.Custom(func(t *rapid.T) hash_comm.Commitment {
		b := rapid.SliceOfN(rapid.Byte(), hash_comm.DigestSize, hash_comm.DigestSize).Draw(t, "commitment bytes")
		var out hash_comm.Commitment
		copy(out[:], b)
		return out
	})
}

func MessageGenerator() *rapid.Generator[hash_comm.Message] {
	return rapid.Custom(func(t *rapid.T) hash_comm.Message {
		return hash_comm.Message(rapid.SliceOfN(rapid.Byte(), 0, 32).Draw(t, "message bytes"))
	})
}

func WitnessGenerator() *rapid.Generator[hash_comm.Witness] {
	return rapid.Custom(func(t *rapid.T) hash_comm.Witness {
		b := rapid.SliceOfN(rapid.Byte(), hash_comm.DigestSize, hash_comm.DigestSize).Draw(t, "witness bytes")
		var out hash_comm.Witness
		copy(out[:], b)
		return out
	})
}

func CommitmentKeyPropertySuite() *properties.CommitmentKeyProperties[hash_comm.CommitmentKey, hash_comm.Message, hash_comm.Witness, hash_comm.Commitment] {
	return &properties.CommitmentKeyProperties[hash_comm.CommitmentKey, hash_comm.Message, hash_comm.Witness, hash_comm.Commitment]{
		PRNG:                   prng.PRNGFuncTypeErase(pcg.NewRandomised),
		CommitmentKeyGenerator: CommitmentKeyGenerator(),
		MessageGenerator:       MessageGenerator(),
		MessagesAreEqual: func(m1, m2 hash_comm.Message) bool {
			return bytes.Equal(m1, m2)
		},
		WitnessesAreEqual: func(w1, w2 hash_comm.Witness) bool {
			return bytes.Equal(w1[:], w2[:])
		},
	}
}

func WitnessPropertySuite() *properties.WitnessProperties[hash_comm.Witness] {
	return &properties.WitnessProperties[hash_comm.Witness]{
		WitnessGenerator: WitnessGenerator(),
		WitnessesAreEqual: func(w1, w2 hash_comm.Witness) bool {
			return bytes.Equal(w1[:], w2[:])
		},
	}
}

func MessagePropertySuite() *properties.MessageProperties[hash_comm.Message] {
	return &properties.MessageProperties[hash_comm.Message]{
		MessageGenerator: MessageGenerator(),
		MessagesAreEqual: func(m1, m2 hash_comm.Message) bool {
			return bytes.Equal(m1, m2)
		},
	}
}

func CommitmentPropertySuite() *properties.CommitmentProperties[hash_comm.Commitment] {
	return &properties.CommitmentProperties[hash_comm.Commitment]{
		CommitmentGenerator: CommitmentGenerator(),
		CommitmentsAreEqual: func(c1, c2 hash_comm.Commitment) bool {
			return bytes.Equal(c1[:], c2[:])
		},
	}
}

func TestCommitmentKeyProperties(t *testing.T) {
	CommitmentKeyPropertySuite().CheckAll(t)
}

func TestWitnessProperties(t *testing.T) {
	WitnessPropertySuite().CheckAll(t)
}

func TestMessageProperties(t *testing.T) {
	MessagePropertySuite().CheckAll(t)
}

func TestCommitmentProperties(t *testing.T) {
	CommitmentPropertySuite().CheckAll(t)
}
