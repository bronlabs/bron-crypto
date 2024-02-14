# `bbot`: Batching Base Oblivious Transfers
This package implements the "Batched Simplest OT", an OT protocol with endemic security defined in Figure 3 of
[MRR21](https://eprint.iacr.org/2021/682), to run Random OTs (ROT) for a batch of choice bits in parallel. 

This OT can be used directly as Base OT for OT extension protocols such as SoftspokenOT (in `pkg/ot/extension/softspoken`).


## Protocol Description
A Random Oblivious Transfer (ROT) protocol following Figure 3 of [MRR21](https://eprint.iacr.org/2021/682) with the Masny-Rindal Programmable-Once Pseudo-random Function (POPF) from Section 5.3 and the Key Agreement (KA) protocol of Section 6.1 based on Hash-to-Curve. It is parametrized by a security parameter $\kappa$, a batch size $n$, an elliptic curve $E (p, \mathbb{G}, G)$ with prime order $p$ and a generator $G \in \mathbb{G}$ for a group $\mathbb{G}$, and a Hash-to-curve functionality H_j

**Players**: Sender $S$ and Receiver $R$.

**S.Round1**() --> $(m_S)$
1. Sample $a \in \mathbb{G}$  _(KA.R)_ 
2. Compute $m_S = a \cdot G$ _(KA.msg_1)_ 
3. Send $m_S$ to R.

**R.Round2**$(m_S)$ --> $(r, \phi)$
1. Sample $c \in \{0,1\}^n$ as the random choice bits.
2. Set the two Random Oracles $H_0$ and $H_1$ _(Setup RO)_
3. for $i \in [n]$ do
    1. Sample $b_i \in \mathbb{Z}_p$  _(KA.R)_ 
    2. Compute $m_{R,i} = b_i \cdot G$ _(KA.msg_2)_ 
    3. Compute $r_i = H(bi \cdot m_S, i || c_i)$ _(KA.key_2)_
    4. Sample $\phi_{i,1-c_i} \in \mathbb{G}$  _(POPF.Program)_ 
    5. Compute $\phi_{i,c_i} = m_{R,i} - H_x(\phi_{i,1-c_i})$  _(POPF.Program)_ 
4. Send $(\phi_{1,0}, \dots, \phi_{n,0}, \phi_{1,1}, \dots, \phi_{n,1})$ to S.
5. Return $(r_1, \dots, r_n)$ as the receiver's chosen messages.

**S.Round3**($((\phi_{1,0}, \phi_{1,1}), \dots, (\phi_{n,0}, \phi_{n,1}))$)
1. for $i \in [n]$ do
    1. for $j \in \{0,1\}$ do
        1. Compute $P = \phi_{i,j} + H_j(\phi_{i,1-j})$ _(POPF.Eval)_ 
        2. Compute $s_{i,j} = H_x(a \cdot P, i || j)$ _(KA.key_1)_
