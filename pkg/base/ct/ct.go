package ct

import "unsafe"

type (
	Choice uint64
	Bool   = Choice
)

const (
	Zero Choice = 0
	One  Choice = 1

	False Bool = 0
	True  Bool = 1
)

func (c Choice) Not() Choice {
	return c ^ One
}

type Comparable[E any] interface {
	Compare(rhs E) (gt, eq, lt Bool)
}

type Equatable[E any] interface {
	Equal(rhs E) Bool
}

type ConditionallySelectable[E any] interface {
	Select(choice Choice, x0, x1 E)
}

type ConditionallyAssignable[E any] interface {
	Select(choice Choice, x0, x1 E)
}

// CSelect returns a if yes==1, else b. Works for any T. Branchless wrt data.
func CSelect[T any](yes Choice, a, b T) T {
	out := b
	CMOV(&out, yes, &a)
	return out
}

// CMOV: *dst = *src if yes==1; otherwise unchanged. Works for any T. Branchless.
func CMOV[T any](dst *T, yes Choice, src *T) {
	n := int(unsafe.Sizeof(*dst))
	m := byte(0 - byte(yes&1))
	d := unsafe.Slice((*byte)(unsafe.Pointer(dst)), n)
	s := unsafe.Slice((*byte)(unsafe.Pointer(src)), n)
	for i := range n {
		di := d[i]
		d[i] = di ^ ((di ^ s[i]) & m)
	}
}

// CSwap swaps *x and *y iff yes==1. Any T. Alias-safe.
func CSwap[T any](x, y *T, yes Choice) {
	ax := CSelect(yes, *y, *x)
	ay := CSelect(yes, *x, *y)
	*x, *y = ax, ay
}
