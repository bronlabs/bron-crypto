# CNF Variant of ISN replicated secret sharing scheme

The CNF scheme represents the access structure as maximal unqualified sets (clauses). The dealer splits the secret into ℓ pieces (where ℓ is the number of maximal unqualified sets) and gives piece j to every party not in maximal unqualified set Tj. An authorized coalition is not contained in any maximal unqualified set, so it contains at least one party outside each Tj and can collect all pieces to reconstruct.

**Example**: Access structure "at least one from {p1,p2} AND at least one from {p3,p4}" has maximal unqualified sets {{p1,p2}, {p3,p4}}. Each party receives a sparse map where keys are the maximal unqualified sets and values are the secret pieces they hold.

## Spec

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
  - For each party $p \in P$, a share containing a sparse map where the key is $T_j$ (represented as a bitset)
    and the value is $r_j$, if $p \notin T_j$. If $p \in T_j$, the clause is omitted from the map
    (implicitly the identity element).

Algorithm:

```pseudocode
CNF.Deal(Γ_max_unqual = [T1..Tℓ], secret s):

1. For each party p in P:
1.1       share[p] := empty map

2. // Create an ℓ-out-of-ℓ additive sharing of s into pieces r1..rℓ
2.1   Sample r1, ..., r_{ℓ-1} ← uniform in G
2.2   Set rℓ := s - (r1 + ... + r_{ℓ-1})

3. For j = 1..ℓ:
3.1     For each party p in P:
3.1.1       If p ∉ Tj:
3.1.1.1         share[p][ Tj ] := rj
                // Store in sparse map with Tj as key

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
2.2     Let rj := share[p][ Tj ]
        // Retrieve value from sparse map using Tj as key

3. Compute:
       s_hat := r1 + r2 + ... + rℓ
   Output s_hat.
```

## Reference

- Section 4.2 of [B25](https://eprint.iacr.org/2025/518.pdf)
