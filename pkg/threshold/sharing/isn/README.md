# Ito-Saito-Nishizeki replicated secret sharing scheme

Package isn implements the Ito-Saito-Nishizeki (ISN) secret sharing scheme
for general monotone access structures.

The ISN scheme generalizes threshold secret sharing to arbitrary monotone
access structures specified in either DNF (Disjunctive Normal Form) or CNF
(Conjunctive Normal Form). Unlike Shamir's threshold scheme which only
supports t-of-n access structures, ISN can handle complex authorization
policies such as "any 2 executives OR any 3 managers" (DNF) or
"at least one from each department" (CNF).

## DNF Variant

The DNF scheme represents the access structure as minimal qualified sets
(clauses). For each minimal qualified set B, the dealer creates an
|B|-out-of-|B| additive sharing of the secret among the parties in B.
Any authorized coalition contains at least one minimal qualified set
and can therefore reconstruct the secret from that clause.

Example: Access structure "A = {p1,p2} OR {p2,p3,p4}" has two minimal
qualified sets. Each party receives a share vector with two components,
one per clause.

## CNF Variant

The CNF scheme represents the access structure as maximal unqualified sets
(clauses). The dealer splits the secret into ℓ pieces (where ℓ is the
number of maximal unqualified sets) and gives piece j to every party
not in maximal unqualified set Tj. An authorized coalition is not
contained in any maximal unqualified set, so it contains at least one
party outside each Tj and can collect all pieces to reconstruct.

Example: Access structure "at least one from {p1,p2} AND at least one
from {p3,p4}" has maximal unqualified sets {{p1,p2}, {p3,p4}}.

## Security

The ISN scheme provides information-theoretic security: any unauthorized
coalition learns no information about the secret. Unlike polynomial-based
schemes (Shamir, Feldman, Pedersen), ISN works directly over any finite
group without requiring field arithmetic.

## Spec

We use the following notation:

- Parties: $P = \{p_1, \cdots, p_n\}$
- Secret's domain is a finite group $s \in G$
- Access Structure $\Gamma \subseteq 2^P$ is monotone: if $A \in \Gamma$ and $A \subseteq \bar{A}$ then $\bar{A} \in \Gamma$
- Minimal qualified sets: $\min(\Gamma) = \{B_1, \cdots, B_m\}$ where each $B_i \in \Gamma$ and no proper subset of $B_i$ is in $\Gamma$
- Maximal unqualified sets: $\max(\overline{\Gamma}) = \{T_1, \cdots, T_\ell\}$ where each $T_j \notin \Gamma$ and no proper superset of $T_j$ is outside $\Gamma$

### DNF variant

Effectively, for each minimal qualified set $B$, we create a fresh $|B|$-out-of-$|B|$ sharing of the same secret among the
parties in $B$; any qualified coalition contains some $B$, so it can reconstruct from that clause alone.

#### DNF.Deal

- Inputs:
  - Access Structure $\Gamma$ via its minimal qualified sets $\min(\Gamma) = \{B_1, \cdots, B_m\}$
  - Secret $s \in G$
  - PRNG
- Output:
  - For each party $p \in P$, a share vector of length $m$ where component $k$ is that party’s piece for clause $B_k$ if $p\in B_k$,
    and $\bot$ / identity otherwise.

Algorithm:

```pseudocode
DNF.Deal(Γ_min = [B1..Bm], secret s):

1. For each party p in P:
1.1       share[p] := array length m
1.2       For k = 1..m:
1.2.1          share[p][k] := 0

2. For k = 1..m:
2.1       Let parties := list(Bk) = [p_i1, ..., p_iℓ]   // ℓ = |Bk|, i1..iℓ are the indices of members of Bk
2.2       Require ℓ ≥ 1
          // Create an ℓ-out-of-ℓ additive sharing of s over the parties in Bk
2.3       Sample r1, ..., r_{ℓ-1} ← uniform in G
2.4       Set rℓ := s - (r1 + ... + r_{ℓ-1})
2.5       For j = 1..ℓ:
2.5.1         share[ parties[j] ][k] := rj

3. Output all share[p].
```

### DNF.Reconstruct

- Inputs:
  - A set of parties $A \subseteq P$ and their shares
  - Access Structure $\Gamma$ via its minimal qualified sets $\min(\Gamma) = \{B_1, \cdots, B_m\}$
- Output:
  - Reconstructed secret $s$ if $A \in \Gamma$ else fail.

Algorithm:

```pseudocode
DNF.Reconstruct(Γ_min = [B1..Bm], provided coalition A, shares share[p]):

1. If A is not authorized (A ∉ Γ): FAIL

2. Find an index k such that Bk ⊆ A.
       (There must exist one because A ∈ Γ and Γ is monotone:
        every authorized set contains a minimal qualified set.)

3. Compute:
       s_hat := sum over p in Bk of share[p][k]
   Output s_hat.
```

### CNF variant

In the CNF variant, the access structure is specified by the maximal unqualified (a.k.a. maximal unauthorized) sets
$\max(\overline{\Gamma}) = \{T_1, \dots, T_\ell\}$. Intuitively, we first split the secret $s$ into $\ell$
independent pieces $r_1,\dots,r_\ell$ such that $r_1 + \cdots + r_\ell = s$. Then, for each $j$, we give piece
$r_j$ to every party not in $T_j$. A qualified coalition $A\in\Gamma$ is not contained in any unqualified set,
so for every $j$ it contains some party outside $T_j$ and can therefore collect all $r_j$ and reconstruct $s$.

#### CNF.Deal

- Inputs:
  - Access Structure $\Gamma$ via its maximal unqualified sets $\max(\overline{\Gamma}) = \{T_1, \cdots, T_\ell\}$
  - Secret $s \in G$
  - PRNG
- Output:
  - For each party $p\in P$, a share vector of length $\ell$ where component $j$ is either $r_j$ (if $p\notin T_j$)
    or $\bot$ / identity (if $p\in T_j$).

Algorithm:

```pseudocode
CNF.Deal(Γ_max_unqual = [T1..Tℓ], secret s):

1. For each party p in P:
1.1       share[p] := array length ℓ
1.2       For j = 1..ℓ:
1.2.1          share[p][j] := 0

2. // Create an ℓ-out-of-ℓ additive sharing of s into pieces r1..rℓ
2.1   Sample r1, ..., r_{ℓ-1} ← uniform in G
2.2   Set rℓ := s - (r1 + ... + r_{ℓ-1})

3. For j = 1..ℓ:
3.1     For each party p in P:
3.1.1       If p ∉ Tj:
3.1.1.1         share[p][j] := rj

4. Output all share[p].
```

### CNF.Reconstruct

- Inputs:
  - A set of parties $A \subseteq P$ and their shares
  - Access Structure $\Gamma$ via its maximal unqualified sets $\max(\overline{\Gamma}) = \{T_1, \cdots, T_\ell\}$
- Output:
  - Reconstructed secret $s$ if $A \in \Gamma$ else fail.

Algorithm:

```pseudocode
CNF.Reconstruct(Γ_max_unqual = [T1..Tℓ], provided coalition A, shares share[p]):

1. If A is not authorized (A ∉ Γ): FAIL

2. For j = 1..ℓ:
2.1     Find any party p in A such that p ∉ Tj.
        (Such p must exist, otherwise A ⊆ Tj and A would be unqualified.)
2.2     Let rj := share[p][j]

3. Compute:
       s_hat := r1 + r2 + ... + rℓ
   Output s_hat.
```

## Reference

- Section 4.2 of [B25](https://eprint.iacr.org/2025/518.pdf)
