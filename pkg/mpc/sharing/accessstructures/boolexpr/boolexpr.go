package boolexpr

import (
	"iter"
	"maps"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/internal"
)

// GateKind distinguishes between internal threshold gates and attribute leaves in the threshold-gate tree.
type GateKind uint8

const (
	gate GateKind = iota + 1
	attribute
)

type Node struct {
	kind GateKind

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
// The gate is satisfied when at least `threshold` of its children is satisfied.
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

// ThresholdGateAccessStructure is an access structure represented as a threshold-gate tree.
//
// Internal nodes are threshold gates, leaves are shareholder attributes, and a
// coalition is qualified when it satisfies the root gate.
type ThresholdGateAccessStructure struct {
	root         *Node
	shareholders map[internal.ID]bool
}

// NewThresholdGateAccessStructure constructs an access structure from a
// threshold-gate tree.
//
// The shareholder universe is derived from all attribute leaves reachable from the root.
func NewThresholdGateAccessStructure(thresholdGateTreeRoot *Node) (*ThresholdGateAccessStructure, error) {
	if err := checkTree(thresholdGateTreeRoot); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid threshold-gate tree")
	}

	shareholders := make(map[internal.ID]bool)
	allShareholders(thresholdGateTreeRoot, shareholders)
	as := &ThresholdGateAccessStructure{
		root:         thresholdGateTreeRoot,
		shareholders: shareholders,
	}
	return as, nil
}

// IsQualified reports whether the given shareholder IDs satisfy the threshold gates.
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

// MaximalUnqualifiedSetsIter streams maximal unqualified sets of the access structure.
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

func checkTree(node *Node) error {
	if node == nil {
		return internal.ErrIsNil.WithMessage("node is nil")
	}
	if node.kind == attribute {
		if node.attr == 0 {
			return internal.ErrValue.WithMessage("sharing ID cannot be 0")
		}
		return nil
	}
	if node.kind == gate {
		if node.threshold <= 0 {
			return internal.ErrValue.WithMessage("threshold must be positive")
		}
		if node.threshold > len(node.children) {
			return internal.ErrValue.WithMessage("threshold must be less than or equal to the number of children")
		}
		attrChildren := sliceutils.Filter(node.children, func(child *Node) bool { return child.kind == attribute })
		uniqueAttrChildren := make(map[internal.ID]bool)
		for _, child := range attrChildren {
			uniqueAttrChildren[child.attr] = true
		}
		if len(uniqueAttrChildren) != len(attrChildren) {
			return internal.ErrValue.WithMessage("threshold-gate tree must not contain duplicate attribute nodes")
		}

		for _, child := range node.children {
			if err := checkTree(child); err != nil {
				return errs.Wrap(err).WithMessage("invalid child node in threshold gate")
			}
		}
		return nil
	}

	return internal.ErrValue.WithMessage("unknown node kind")
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
