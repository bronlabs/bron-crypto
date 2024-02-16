package art

import (
	"slices"
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	"github.com/copperexchange/krypton-primitives/pkg/key_agreement/dh"
	"github.com/copperexchange/krypton-primitives/pkg/key_agreement/tripledh"
)

type AsynchronousRatchetTree struct {
	myIdentitySecret  curves.Scalar
	myEphemeralSecret curves.Scalar
	myIdentityPublic  curves.Point
	myEphemeralPublic curves.Point
	tree              ArrayTree[*node]
	size              int
}

// NewAsynchronousRatchetTree creates the asynchronous ratcheting tree.
// The leaf node with the lexicographically lowest identity key becomes a leader of the group
// (i.e. generates keys at non-leaves nodes which other group members updates on).
func NewAsynchronousRatchetTree(myAuthKey, myEphemeralKey curves.Scalar, theirIdentityKeys, theirEphemeralKeys []curves.Point) (ratchetTree *AsynchronousRatchetTree, err error) {
	myPublicIdentityKey := myAuthKey.ScalarField().Curve().ScalarBaseMult(myAuthKey)
	myPublicEphemeralKey := myEphemeralKey.ScalarField().Curve().ScalarBaseMult(myEphemeralKey)

	// 1. [Build ART] Construct full binary tree.
	leaves := make([]*node, len(theirIdentityKeys))

	// 2. [Build ART] Every leaf represents a group member with corresponding keys.
	for i := range leaves {
		leaves[i] = &node{
			publicIdentityKey:  theirIdentityKeys[i],
			publicEphemeralKey: theirEphemeralKeys[i],
		}
		if myPublicIdentityKey.Equal(theirIdentityKeys[i]) {
			leaves[i].privateIdentityKey = myAuthKey
			leaves[i].privateEphemeralKey = myEphemeralKey
		}
	}
	sort.Sort(byIdentity(leaves))

	// 3. [Build ART] Compute node keys.
	// 3.i. [Build ART] Compute node keys of the leader.
	leaves[0].privateNodeKey = leaves[0].privateEphemeralKey
	leaves[0].publicNodeKey = leaves[0].publicEphemeralKey

	// 3.ii [Build ART] Compute node keys of the remaining leaves.
	// Although X3DH is symmetric for both parties, we still need to distinguish side, as the order of keys is different.
	if leaves[0].publicIdentityKey.Equal(myPublicIdentityKey) {
		// I am the leader.
		for i := 1; i < len(leaves); i++ {
			secret, err := tripledh.DeriveSecretLocal(
				leaves[0].privateIdentityKey, leaves[i].publicIdentityKey,
				leaves[0].privateEphemeralKey, leaves[i].publicEphemeralKey,
			)
			if err != nil {
				return nil, errs.WrapFailed(err, "cannot derive secret")
			}

			leaves[i].privateNodeKey = secret
			leaves[i].publicNodeKey = leaves[i].privateNodeKey.ScalarField().Curve().ScalarBaseMult(leaves[i].privateNodeKey)
		}
	} else {
		// I am NOT a leader.
		for i := 1; i < len(leaves); i++ {
			if leaves[i].privateIdentityKey != nil && leaves[i].privateEphemeralKey != nil {
				secret, err := tripledh.DeriveSecretRemote(
					leaves[0].publicIdentityKey, leaves[i].privateIdentityKey,
					leaves[0].publicEphemeralKey, leaves[i].privateEphemeralKey,
				)
				if err != nil {
					return nil, errs.WrapFailed(err, "cannot derive secret")
				}

				leaves[i].privateNodeKey = secret
				leaves[i].publicNodeKey = leaves[i].privateNodeKey.ScalarField().Curve().ScalarBaseMult(leaves[i].privateNodeKey)
			}
		}
	}

	// 1.i. [Build ART] Extend binary tree to full binary tree as it's easier to work with (some node would be empty).
	trueTreeSize := 2*len(leaves) - 1
	allLeavesSize := 1 << utils.CeilLog2(len(leaves))
	remainingLeavesSize := allLeavesSize - len(leaves)
	fullLeaves := slices.Grow(leaves, remainingLeavesSize)
	tree := NewArrayTree(fullLeaves)
	for i, n := range tree {
		if n == nil {
			tree[i] = &node{}
		}
	}

	// 4. Rebuild node keys.
	art := &AsynchronousRatchetTree{
		myIdentitySecret:  myAuthKey,
		myEphemeralSecret: myEphemeralKey,
		myIdentityPublic:  myPublicIdentityKey,
		myEphemeralPublic: myPublicEphemeralKey,
		tree:              tree,
		size:              trueTreeSize,
	}
	if err := art.rebuildTree(); err != nil {
		return nil, errs.WrapFailed(err, "cannot rebuild ratchet tree")
	}

	return art, nil
}

func (p *AsynchronousRatchetTree) GetMyPublicIdentityKey() curves.Point {
	return p.myIdentityPublic
}

// IsLeader return true if my identity key is the lexicographically lowest, otherwise false.
func (p *AsynchronousRatchetTree) IsLeader() bool {
	return p.myIdentityPublic.Equal(p.tree[0].publicIdentityKey)
}

// SetupGroup returns public keys of all nodes.
// If this is done by the Leader other non-leader nodes use this information to sync their tree nodes with public keys.
func (p *AsynchronousRatchetTree) SetupGroup() []curves.Point {
	// 5. [Build ART] The leader broadcasts all node public keys.
	publicKeys := make([]curves.Point, p.size)
	for i := range publicKeys {
		publicKeys[i] = p.tree[i].publicNodeKey
	}

	return publicKeys
}

// ProcessSetup updates public keys at nodes, verifying that duplicates (if any) match already existing ones.
// This is done by all non-leader nodes to sync their trees.
func (p *AsynchronousRatchetTree) ProcessSetup(publicKeys []curves.Point) (err error) {
	// 6. [Build ART] Every non-leader node receives public node keys...
	for i, pk := range publicKeys {
		if p.tree[i].publicNodeKey == nil {
			p.tree[i].publicNodeKey = pk
		} else if !p.tree[i].publicNodeKey.Equal(pk) {
			return errs.NewArgument("invalid keys")
		}
	}

	// 6.i. ...and re-runs rebuild tree procedure.
	if err := p.rebuildTree(); err != nil {
		return errs.WrapFailed(err, "cannot rebuild the tree")
	}

	return nil
}

// UpdateKey updates private key of the leaf node.
// This will update the node's key and returns new public keys of the path to the root which other nodes can update on.
func (p *AsynchronousRatchetTree) UpdateKey(newPrivateKey curves.Scalar) (pk []curves.Point, err error) {
	// 1. [Ratchet]
	// It's necessary just to check leaves on the tree, hence iterate only even-indexed nodes where leaves sit at.
	for i := 0; i < p.size; i += 2 {
		if !p.tree[i].publicIdentityKey.Equal(p.myIdentityPublic) {
			continue
		}

		// 1.i [Ratchet] Set net node keys in the corresponding leaf.
		p.tree[i].privateNodeKey = newPrivateKey
		p.tree[i].publicNodeKey = p.tree[i].privateNodeKey.ScalarField().Curve().ScalarBaseMult(p.tree[i].privateNodeKey)

		// 1.ii [Ratchet] Void all node keys on the path from the leaf to the root of the tree.
		j := p.tree.Parent(i)
		for {
			p.tree[j].privateNodeKey = nil
			p.tree[j].publicNodeKey = nil
			if j == p.tree.Root() {
				break
			}
			j = p.tree.Parent(j)
		}

		// 1.iii [Ratchet] Re-run rebuild procedure.
		if err := p.rebuildTree(); err != nil {
			return nil, errs.WrapFailed(err, "cannot rebuild the tree")
		}

		// 1.iv [Ratchet] Broadcasts all public node keys on the path in the tree from the leaf to the tree root.
		publicKeys := make([]curves.Point, 0)
		j = i
		for {
			publicKeys = append(publicKeys, p.tree[j].publicNodeKey)
			if j == p.tree.Root() {
				break
			}
			j = p.tree.Parent(j)
		}
		return publicKeys, nil
	}

	return nil, errs.NewFailed("invalid identity")
}

// ProcessUpdate updates public key of the node.
// This will update the node's public key and all public keys of nodes on the path to the root.
func (p *AsynchronousRatchetTree) ProcessUpdate(newPublicKeys []curves.Point, publicIdentityKey curves.Point) (err error) {
	// 2. [Ratchet] Every other member receives the node public keys.
	for i := 0; i < p.size; i += 2 {
		if !p.tree[i].publicIdentityKey.Equal(publicIdentityKey) {
			continue
		}

		// 2.i. [Ratchet] Update the node public keys in the nodes on the path from the leaf to the root.
		j := i
		for k := 0; k < len(newPublicKeys); k++ {
			p.tree[j].privateNodeKey = nil
			p.tree[j].publicNodeKey = newPublicKeys[k]
			if j == p.tree.Root() {
				break
			}
			j = p.tree.Parent(j)
		}

		// 2.ii [Ratchet] Re-run rebuild procedure.
		err = p.rebuildTree()
		if err != nil {
			return errs.WrapFailed(err, "cannot rebuild the tree")
		}
		break
	}

	return nil
}

// DeriveStageKey returns private key of the root which is used to derive a group encryption/decryption key.
func (p *AsynchronousRatchetTree) DeriveStageKey() curves.Scalar {
	// 7. [Build ART] The private node key at root is used to derive group encryption key.
	return p.tree[p.tree.Root()].privateNodeKey
}

func (p *AsynchronousRatchetTree) rebuildTree() (err error) {
	// 4. [Build ART] Rebuild procedure.
	// Iterate nodes from the lowest level bottom up...
	for i, step := 0, 4; i < p.tree.Root(); i, step = 2*i+1, step*2 {
		// ...starting from the most left node.
		for left := i; left < len(p.tree); left += step {
			right := p.tree.Sibling(left)
			parent := p.tree.Parent(left)
			switch {
			// 4.i [Build ART] The left child has node private key, the right child has node public key.
			case p.tree[left].privateNodeKey != nil && p.tree[right].publicNodeKey != nil:
				sk, err := dh.DiffieHellman(p.tree[left].privateNodeKey, p.tree[right].publicNodeKey)
				if err != nil {
					return errs.NewFailed("cannot derive secret value at %d", parent)
				}
				p.tree[parent].privateNodeKey, err = p.tree[left].privateNodeKey.ScalarField().Hash(sk.Bytes())
				if err != nil {
					return errs.NewHashing("cannot hash secret value at %d", parent)
				}
				p.tree[parent].publicNodeKey = p.tree[parent].privateNodeKey.ScalarField().Curve().ScalarBaseMult(p.tree[parent].privateNodeKey)

			// 4.ii [Build ART] the left child has node public key, the right child has node private key.
			case p.tree[left].publicNodeKey != nil && p.tree[right].privateNodeKey != nil:
				sk, err := dh.DiffieHellman(p.tree[right].privateNodeKey, p.tree[left].publicNodeKey)
				if err != nil {
					return errs.NewFailed("cannot derive secret value %d", parent)
				}
				p.tree[parent].privateNodeKey, err = p.tree[right].privateNodeKey.ScalarField().Hash(sk.Bytes())
				if err != nil {
					return errs.NewHashing("cannot hash secret value %d", parent)
				}
				p.tree[parent].publicNodeKey = p.tree[parent].privateNodeKey.ScalarField().Curve().ScalarBaseMult(p.tree[parent].privateNodeKey)

			// 4.iii [Build ART] The right child is empty (while the left is not).
			case p.tree[left].publicNodeKey != nil && parent >= p.size:
				p.tree[parent].privateNodeKey = p.tree[left].privateNodeKey
				p.tree[parent].publicNodeKey = p.tree[left].publicNodeKey
			}
		}
	}

	return nil
}

type node struct {
	privateIdentityKey  curves.Scalar
	privateEphemeralKey curves.Scalar
	privateNodeKey      curves.Scalar

	publicIdentityKey  curves.Point
	publicEphemeralKey curves.Point
	publicNodeKey      curves.Point
}

type byIdentity []*node

var _ sort.Interface = byIdentity(nil)

func (b byIdentity) Len() int {
	return len(b)
}

func (b byIdentity) Less(i, j int) bool {
	return b[i].publicIdentityKey.AffineX().Cmp(b[j].publicIdentityKey.AffineX()) < 0
}

func (b byIdentity) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}
