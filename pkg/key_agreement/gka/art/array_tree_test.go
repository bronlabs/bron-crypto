package art_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/key_agreement/gka/art"
)

/*
							 X
							 |
				   .---------+---------.
				  /                     \
				 X                       X
				 |                       |
			 .---+---.               .---+---.
			/         \             /         \
		   X           X           X           X
		  / \         / \         / \         / \
		 /   \       /   \       /   \       /   \
	    X     X     X     X     X     X     X     X
	    0  1  2  3  4  5  6  7  8  9 10 11 12 13 14
*/
func Test_ArrayTreeHappyPath(t *testing.T) {
	t.Parallel()

	tree := art.ArrayTree[int](make([]int, 15))

	require.True(t, tree.Root() == 7)

	require.True(t, tree.Parent(9) == 11)
	require.True(t, tree.Parent(13) == 11)
	require.True(t, tree.Left(11) == 9)
	require.True(t, tree.Right(11) == 13)
	require.True(t, tree.Sibling(9) == 13)
	require.True(t, tree.Sibling(13) == 9)

	require.True(t, tree.Parent(0) == 1)
	require.True(t, tree.Parent(2) == 1)
	require.True(t, tree.Left(1) == 0)
	require.True(t, tree.Right(1) == 2)
	require.True(t, tree.Sibling(0) == 2)
	require.True(t, tree.Sibling(2) == 0)
}

func Test_ArrayTreeTraversal(t *testing.T) {
	t.Parallel()

	tree := art.ArrayTree[int](make([]int, 15))
	traversal := []struct {
		node    int
		sibling int
		left    int
		right   int
		parent  int
	}{
		{node: 9, sibling: 13, left: 8, right: 10, parent: 11},
		{node: 11, sibling: 3, left: 9, right: 13, parent: 7},
		{node: 7},
	}

	for node, i := 9, 0; node != tree.Root(); node, i = tree.Parent(node), i+1 {
		require.Equal(t, node, traversal[i].node)
		require.Equal(t, tree.Sibling(node), traversal[i].sibling)
		require.Equal(t, tree.Left(node), traversal[i].left)
		require.Equal(t, tree.Right(node), traversal[i].right)
		require.Equal(t, tree.Parent(node), traversal[i].parent)
	}
}
