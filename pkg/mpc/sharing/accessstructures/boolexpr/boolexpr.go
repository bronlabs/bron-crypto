package boolexpr

import (
	"iter"
	"maps"
	"slices"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/internal"
)

type gateKind uint8

const (
	gate gateKind = iota + 1
	attribute
)

type Node struct {
	kind gateKind

	// for attribute gates
	attr internal.ID

	// for gate nodes
	threshold int
	children  []*Node
}

// ID constructs an attribute leaf labelled by the given shareholder ID.
//
// Attribute leaves are the terminal nodes of a threshold-gate access tree and
// correspond to the rows of the induced MSP.
func ID(id internal.ID) *Node {
	//nolint:exhaustruct // only attribute properties set
	return &Node{
		kind: attribute,
		attr: id,
	}
}

// Threshold constructs an internal threshold gate with the given threshold and
// ordered children.
//
// The gate is satisfied when at least `threshold` of its children are
// satisfied. The child order is significant for MSP induction because the
// local interpolation points are assigned as 1, 2, ..., len(children).
func Threshold(threshold int, children ...*Node) *Node {
	//nolint:exhaustruct // only gate properties set
	return &Node{
		kind:      gate,
		threshold: threshold,
		children:  children,
	}
}

// And constructs an AND gate over the provided children.
//
// This is shorthand for a threshold gate whose threshold equals the number of
// children.
func And(nodes ...*Node) *Node {
	return Threshold(len(nodes), nodes...)
}

// Or constructs an OR gate over the provided children.
//
// This is shorthand for a 1-of-n threshold gate.
func Or(nodes ...*Node) *Node {
	return Threshold(1, nodes...)
}

// ThresholdGateAccessStructure is an access structure represented as a rooted
// threshold-gate tree.
//
// Internal nodes are threshold gates, leaves are shareholder attributes, and a
// coalition is qualified when it satisfies the root gate.
type ThresholdGateAccessStructure struct {
	root         *Node
	shareholders map[internal.ID]bool
}

// NewThresholdGateAccessStructure constructs an access structure from a
// threshold-gate tree root.
//
// The shareholder universe is derived from all attribute leaves reachable from
// the root.
func NewThresholdGateAccessStructure(thresholdGateTreeRoot *Node) *ThresholdGateAccessStructure {
	shareholders := make(map[internal.ID]bool)
	allShareholders(thresholdGateTreeRoot, shareholders)

	return &ThresholdGateAccessStructure{
		root:         thresholdGateTreeRoot,
		shareholders: shareholders,
	}
}

// IsQualified reports whether the given shareholder IDs satisfy the threshold
// gates from the leaves up to the root.
func (a *ThresholdGateAccessStructure) IsQualified(ids ...internal.ID) bool {
	shareholders := map[internal.ID]bool{}
	for _, id := range ids {
		shareholders[id] = true
	}
	return treeEval(a.root, shareholders)
}

// Shareholders returns the set of all shareholder IDs that occur as attribute
// leaves in the tree.
func (a *ThresholdGateAccessStructure) Shareholders() ds.Set[internal.ID] {
	return hashset.NewComparable(slices.Collect(maps.Keys(a.shareholders))...).Freeze()
}

// MaximalUnqualifiedSetsIter streams maximal unqualified sets of the access
// structure.
//
// This method is not implemented yet and currently panics.
func (*ThresholdGateAccessStructure) MaximalUnqualifiedSetsIter() iter.Seq[ds.Set[internal.ID]] {
	// TODO implement me
	panic("implement me")
}

// CountLeaves returns the number of attribute leaves in the threshold-gate
// tree.
//
// This equals the number of rows in the MSP produced by [InducedMSP].
func (a *ThresholdGateAccessStructure) CountLeaves() int {
	return treeCountLeaves(a.root)
}

func allShareholders(node *Node, shareholders map[internal.ID]bool) {
	if node == nil || (node.kind != gate && node.kind != attribute) {
		return
	}

	if node.kind == attribute {
		shareholders[node.attr] = true
	} else {
		for _, child := range node.children {
			allShareholders(child, shareholders)
		}
	}
}

func treeEval(node *Node, ids map[internal.ID]bool) bool {
	if node == nil || (node.kind != gate && node.kind != attribute) {
		return false
	}

	if node.kind == attribute {
		b, ok := ids[node.attr]
		return ok && b
	}

	c := sliceutils.Count(
		sliceutils.Map(node.children, func(child *Node) bool { return treeEval(child, ids) }),
		func(b bool) bool { return b },
	)
	return c >= node.threshold
}

func treeCountLeaves(node *Node) int {
	if node == nil || (node.kind != gate && node.kind != attribute) {
		return 0
	}
	if node.kind == attribute {
		return 1
	}

	c := 0
	for _, child := range node.children {
		c += treeCountLeaves(child)
	}
	return c
}
