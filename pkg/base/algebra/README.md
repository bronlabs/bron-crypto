# Algebra

This packages defines low level interfaces with which we build the Elliptic Curve interfaces of base/curves.


## Conventions

Note that Go's type system does not support [contra]variance, so both implementation and usage of these interfaces are somewhat unorthodox.

We basically define two types of interfaces:
1. "Abstract": Main interfaces that we build up higher level algebraic structures.
2. "Trait": Additional methods of a structure of a particular type that higher level structure MAY have.

For example, Mathematically the ring (R, +, *) forms a group under addition and a monoid under multiplication. The way we express this is with a additive group and multiplicative monoid traits.

Effectively, this is to prevent name collisions for shared methods of monoid and group. In above example, an additive group and a multiplicative monoid both have identity elements, but cannot both be named Identity(), so the traits define AdditiveIdentity() and MultiplicativeIdentity()

## Hierarchy

### Algebra

The hierarchy of the structures is as follows:

[Structured Set](https://ncatlab.org/nlab/show/structured+set) $\supset$ [Groupoid](https://en.wikipedia.org/wiki/Magma_(algebra)) $\supset$ [Monoid](https://en.wikipedia.org/wiki/Monoid) $\supset$ [Group](https://en.wikipedia.org/wiki/Group_(mathematics)) $\supset$ [Ring](https://en.wikipedia.org/wiki/Ring_(mathematics)) $\supset$ [Finite Field](https://en.wikipedia.org/wiki/Finite_field) $\supset$ [Module](https://en.wikipedia.org/wiki/Module_(mathematics)) $\supset$ [Vector Space](https://en.wikipedia.org/wiki/Vector_space).

### Order Theory

The hierarchy of the structures is as follows:

[Structured Set](https://ncatlab.org/nlab/show/structured+set) $\supset$ [Lattice](https://en.wikipedia.org/wiki/Lattice_(order)) $\supset$ [Bounded Lattice](https://mathworld.wolfram.com/BoundedLattice.html) $\supset$ [Chain](https://en.wikipedia.org/wiki/Total_order#Chains).

To deal with orderings, we define lattices and chains in `order.go`. Note that almost always in the crypto code we will be using chains as finite fields aren't totally ordered.

### Algebraic Geometry

The hierarchy of the structures is as follows:

[Algebraic Variety](https://en.wikipedia.org/wiki/Algebraic_variety) $\supset$ [Algebraic Curve](https://en.wikipedia.org/wiki/Algebraic_curve)

And

[Algebraic Variety](https://en.wikipedia.org/wiki/Algebraic_variety) $\supset$ [Algebraic Group](https://en.wikipedia.org/wiki/Algebraic_group).

For example, an Elliptic curve is an algebraic group of dimension 1 ie. an algebraic curve, but not all algebraic curves form a group.
