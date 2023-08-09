package types

const HASH_KEY_SIZE = 32

type Hashable interface {
	Hash() [HASH_KEY_SIZE]byte
}

func Equals(a, b Hashable) bool {
	return a.Hash() == b.Hash()
}
