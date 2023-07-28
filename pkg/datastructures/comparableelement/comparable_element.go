package comparableelement

type Hashable interface {
	HashCode() uint32
}

func Equals(a Hashable, b Hashable) bool {
	return a.HashCode() == b.HashCode()
}
