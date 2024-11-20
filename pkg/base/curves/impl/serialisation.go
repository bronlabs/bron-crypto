package impl

import (
	"encoding/json"
	"encoding/pem"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type Serializer func() []byte
type Deserializer[E any] func(input []byte) (E, error)

// this is same as pem.Block, but with json tags to print it nicely.
type jsonPemBlock struct {
	Type    string            `json:"type"`
	Headers map[string]string `json:"headers,omitempty"`
	Bytes   []byte            `json:"bytes"`
}

func MarshalJson(name string, f Serializer) ([]byte, error) {
	e := &jsonPemBlock{
		Type:  name,
		Bytes: f(),
	}
	marshalled, err := json.Marshal(e)
	if err != nil {
		return nil, errs.WrapFailed(err, "json marshal failed")
	}
	return marshalled, nil
}

func UnmarshalJson[E any](f Deserializer[E], input []byte) (E, error) {
	var block jsonPemBlock
	if err := json.Unmarshal(input, &block); err != nil {
		return *new(E), errs.WrapSerialisation(err, "could not unmarshal json to pem block")
	}
	return f(block.Bytes)
}

func ParseJSON(data []byte) (name string, serialised []byte, err error) {
	var e jsonPemBlock
	if err := json.Unmarshal(data, &e); err != nil {
		return "", nil, errs.WrapSerialisation(err, "json unmarshal failed")
	}
	if e.Type == "" {
		return "", nil, errs.NewMissing("curve name is not in the json")
	}
	if len(e.Bytes) == 0 {
		return "", nil, errs.NewMissing("serialised bytes are missing")
	}
	return e.Type, e.Bytes, nil
}

func MarshalBinary(name string, f Serializer) []byte {
	e := &pem.Block{
		Type:  name,
		Bytes: f(),
	}
	return pem.EncodeToMemory(e)
}

func UnmarshalBinary[E any](f Deserializer[E], input []byte) (E, error) {
	block, rest := pem.Decode(input)
	if block == nil || len(rest) != 0 {
		return *new(E), errs.NewType("pem decoding had leftovers of length %d > 0 or block is nil", len(rest))
	}
	return f(block.Bytes)
}

func ParseBinary(data []byte) (name string, serialised []byte, err error) {
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 {
		return "", nil, errs.NewType("pem decoding had leftovers of length %d > 0 or block is nil", len(rest))
	}
	if len(block.Bytes) == 0 {
		return "", nil, errs.NewMissing("serialised bytes are missing")
	}
	return block.Type, block.Bytes, nil
}
