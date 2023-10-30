# Asynchronous Ratcheting Trees (ART)
This package implements ratcheting tree as described in [art].

## Assumptions
* The group consists of $n$ members,
* Every $i^{th}$ group member has the long-term key pair (identity key) $(ik_i, IK_i)$,
* Every $i^{th}$ group member has the short-term key pair (ephemeral key) $(ek_i, EK_i)$,
* Every $i_{th}$ group member has the public identity key and ephemeral public key of every other node,
* group members are ordered lexicographically by their public identity key, i.e. $IK_0 < IK_1 < ... < IK_{n-1}$,
* $0^{th}$ member (the one with lexicographically lowest $IK_0$) is called the leader (or initiator).
* DH and X3DH normally returns an elliptic curve point, to derive a private key (scalar) from the returned point, the point is encoded to bytes and Hash2Field is used to create scalar from bytes digest.

## Build ART
Every group member builds the tree in the following steps:
1. construct binary tree with at least $n$ leaves,
    1. to ease implementation make it full binary tree with number of leaves being the lowest power of 2 greater than or equal $n$, some nodes would be empty if $n$ is not power of 2,
2. every $i^{th} (i < n)$ leaf represents the $i^{th}$ group member (i.e. has the corresponding $ik_i$ (if known), $IK_i$, $ek_i$ (if known), $EK_i$,
3. every $i^{th}$ leaf has node key pair $(\lambda_i, \Lambda_i)$ computed in the following way:
    1. $(\lambda_0, \Lambda_0) := (ek_0, EK_0)$, $ek_0$ is empty for every leaf other than $0^{th}$,
    2. for $0 < i < (n - 1)$ set $\lambda_i = X3DH(ik_i, IK_0, ek_i, EK_0)$ (if known) and derive $\Lambda_i$
4. (rebuild procedure) derive node key pair for non-leaf nodes in the following way by iterating them from the lowest level bottom up starting from most left nodes:
    1. if the left child has node private key $\lambda_L$ and the right has child node has public node key $\Lambda_R$ then node's private node key $\lambda = DH(\lambda_L, \Lambda_R)$ and corresponding  public node key,
    2. if the left child has node public key $\Lambda_L$ and the right child node has private node key $\lambda_R$ then node's private node key $\lambda = DH(\lambda_R, \Lambda_L)$ and corresponding  public node key,
    3. if the right child is empty then the node's key pair is copied over from the left child
5. the leader/initiator broadcasts all node public keys of all tree nodes,
6. every non-leader node receives public node keys updates corresponding node public keys...,
    1. ... and re-run rebuild procedure,
7. the private node key at root is then used to derive group encryption key.

## Ratchet
If at any point in time a group member decides to change their node key pair, the following procedure is then taking place:
1. the member (e.g. $k^{th}$):
    1. sets new node key pair $(\lambda_k, \Lambda_k)$ at its leaf,
    2. void all node keys on the path from the leaf to the root of the tree
    3. re-runs rebuild procedure,
    4. broadcasts all public node keys on the path in the tree from $k^{th}$ leaf to the tree root,
2. every other member receives the node public key and:
    1. updates the node public key in nodes on the path from $k^{th}$ to the root,
    2. re-runs rebuild procedure.


[art]: <https://eprint.iacr.org/2017/666.pdf>
