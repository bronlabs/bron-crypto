package types

type Hashable interface {
	Hash() [32]byte
}

func Equals(a, b Hashable) bool {
	return a.Hash() == b.Hash()
}
