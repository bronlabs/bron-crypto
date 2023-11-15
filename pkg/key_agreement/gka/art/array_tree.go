package art

import (
	"math/bits"

	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

type ArrayTree[T any] []T

// NewArrayTree creates a new array tree with given array of the leaves.
// Leaves in the array tree occupy even-indexed array tree elements.
func NewArrayTree[T any](leaves []T) ArrayTree[T] {
	tree := ArrayTree[T](make([]T, (2*len(leaves))-1))
	for i, j := 0, 0; i < len(leaves); i, j = i+1, j+2 {
		tree[j] = leaves[i]
	}
	return tree
}

// Level returns the depth level of the node at index x.
// 0 means the most bottom (leaf).
func (ArrayTree[T]) Level(x int) int {
	return bits.TrailingZeros32(^(uint32(x)))
}

// Root returns the index of the root element node of the tree.
func (t ArrayTree[T]) Root() int {
	return (1 << utils.FloorLog2(len(t))) - 1
}

// Left returns the index of the left child node .
func (t ArrayTree[T]) Left(x int) int {
	k := t.Level(x)
	return x ^ (0b01 << (k - 1))
}

// Right returns the index of the right child node.
func (t ArrayTree[T]) Right(x int) int {
	k := t.Level(x)
	return x ^ (0b11 << (k - 1))
}

// Parent returns the index of the parent node.
func (t ArrayTree[T]) Parent(x int) int {
	k := t.Level(x)
	b := (x >> (k + 1)) & 0b1
	return (x | (1 << k)) ^ (b << (k + 1))
}

// Sibling returns the index of the sibling node.
func (t ArrayTree[T]) Sibling(x int) int {
	p := t.Parent(x)
	if x < p {
		return t.Right(p)
	} else {
		return t.Left(p)
	}
}
