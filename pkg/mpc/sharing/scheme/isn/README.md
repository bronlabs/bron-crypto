# Ito-Saito-Nishizeki replicated secret sharing scheme

Package isn implements the Ito-Saito-Nishizeki (ISN) secret sharing scheme for general monotone access structures.

The ISN scheme generalizes threshold secret sharing to arbitrary monotone access structures specified 
in either DNF (Disjunctive Normal Form) or CNF (Conjunctive Normal Form). 
Unlike Shamir's threshold scheme which only supports t-of-n access structures, 
ISN can handle complex authorization policies such as "any 2 executives OR any 3 managers" (DNF) 
or "at least one from each department" (CNF). Note that any access structure is representable in both DNF and CNF, 
but the choice of representation can impact the efficiency of share generation and reconstruction.

This package currently provides the CNF variant (`Scheme`, `Share`, `NewFiniteScheme`, `Deal`, `Reconstruct`).

## CNF Variant

The CNF scheme represents the access structure as maximal unqualified sets (clauses). The dealer splits the secret 
into `l` pieces (where `l` is the number of maximal unqualified sets) and gives piece `j` to every party 
not in maximal unqualified set `Tj`. An authorized coalition is not contained in any maximal unqualified set, 
so it contains at least one party outside each `Tj` and can collect all pieces to reconstruct.

Example: access structure "at least one from `{p1,p2}` AND at least one from `{p3,p4}`" 
has maximal unqualified sets `{{p1,p2}, {p3,p4}}`. Each party receives a sparse map where keys 
are maximal unqualified sets and values are the corresponding secret pieces they hold.

## Spec

### CNF variant

In the CNF variant, the access structure is specified by the maximal unqualified
(a.k.a. maximal unauthorized) sets:

$$
\max(\overline{\Gamma}) = \{T_1, \dots, T_\ell\}.
$$

We split the secret $s$ into $\ell$ pieces $(r_1,\dots,r_\ell)$ such that:

$$
r_1 + \cdots + r_\ell = s.
$$

For each $j$, we give piece $r_j$ to every party not in $T_j$. A qualified
coalition $A \in \Gamma$ is not contained in any unqualified set, so for every
$j$ it contains some party outside $T_j$, and can therefore collect all
$r_j$ and reconstruct $s$.

#### CNF.Deal

- Input: secret `s`, CNF access structure via maximal unqualified sets `{T1..Tl}`, PRNG.
- Output: for each party `p`, a sparse map share that contains `rj` under key `Tj` iff `p ∉ Tj`.
- Construction: sample `r1..r(l-1)` uniformly in the group and set `rl = s - (r1 + ... + r(l-1))`.

Algorithm:

```pseudocode
CNF.Deal(Γ_max_unqual = [T1..Tl], secret s):

1. For each party p in P:
1.1       share[p] := empty map

2. // Create an l-out-of-l additive sharing of s into pieces r1..rl
2.1   Sample r1, ..., r_{l-1} <- uniform in G
2.2   Set rl := s - (r1 + ... + r_{l-1})

3. For j = 1..l:
3.1     For each party p in P:
3.1.1       If p ∉ Tj:
3.1.1.1         share[p][Tj] := rj

4. Output all share[p].
```

### CNF.Reconstruct

- Input: shares from coalition `A` and the same CNF access structure.
- Validate coalition authorization.
- For each maximal unqualified set `Tj`, recover a consistent chunk from parties outside `Tj`.
- Reconstruct `s` as `r1 + ... + rl`.

Algorithm:

```pseudocode
CNF.Reconstruct(Γ_max_unqual = [T1..Tl], coalition A, shares share[p]):

1. Initialize chunks := empty map from maximal unqualified set -> group element

2. For each provided share from party p:
2.1     For each maximal unqualified set Tj where p ∉ Tj:
2.1.1       If share[p][Tj] is missing: FAIL
2.1.2       If chunks[Tj] already set and chunks[Tj] != share[p][Tj]: FAIL
2.1.3       Otherwise set chunks[Tj] := share[p][Tj]

3. If chunks does not contain an entry for every Tj in Γ_max_unqual: FAIL

4. Compute:
       s_hat := sum over all Tj in Γ_max_unqual of chunks[Tj]
   Output s_hat.
```

## Security

The ISN scheme provides information-theoretic security: any unauthorized coalition learns 
no information about the secret. Unlike polynomial-based schemes (Shamir, Feldman, Pedersen), 
ISN works directly over any finite group without requiring field arithmetic.

## Reference

- Section 4.2 of [B25](https://eprint.iacr.org/2025/518.pdf)
