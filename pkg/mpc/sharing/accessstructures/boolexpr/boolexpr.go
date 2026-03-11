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

func ID(id internal.ID) *Node {
	//nolint:exhaustruct // only attribute properties set
	return &Node{
		kind: attribute,
		attr: id,
	}
}

func Threshold(threshold int, children ...*Node) *Node {
	//nolint:exhaustruct // only gate properties set
	return &Node{
		kind:      gate,
		threshold: threshold,
		children:  children,
	}
}

func And(nodes ...*Node) *Node {
	return Threshold(len(nodes), nodes...)
}

func Or(nodes ...*Node) *Node {
	return Threshold(1, nodes...)
}

type ThresholdGateAccessStructure struct {
	root         *Node
	shareholders map[internal.ID]bool
}

func NewThresholdGateAccessStructure(thresholdGateTreeRoot *Node) *ThresholdGateAccessStructure {
	shareholders := make(map[internal.ID]bool)
	allShareholders(thresholdGateTreeRoot, shareholders)

	return &ThresholdGateAccessStructure{
		root:         thresholdGateTreeRoot,
		shareholders: shareholders,
	}
}

func (a *ThresholdGateAccessStructure) IsQualified(ids ...internal.ID) bool {
	shareholders := map[internal.ID]bool{}
	for _, id := range ids {
		shareholders[id] = true
	}
	return treeEval(a.root, shareholders)
}

func (a *ThresholdGateAccessStructure) Shareholders() ds.Set[internal.ID] {
	return hashset.NewComparable(slices.Collect(maps.Keys(a.shareholders))...).Freeze()
}

func (*ThresholdGateAccessStructure) MaximalUnqualifiedSetsIter() iter.Seq[ds.Set[internal.ID]] {
	// TODO implement me
	panic("implement me")
}

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
