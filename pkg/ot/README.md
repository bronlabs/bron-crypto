# `ot` Oblivious Transfer
This package generalizes a common interface for 1-out-of-2 Oblivious Transfer protocols. 


There are two main types of OT protocols:
- **Base OT**: A protocol that implements an OT functionality (described below) from scratch by relying 
  on public-key cryptography for each OT. We implement:
    - `bbot` "Batching Base OTs", a 3-round protocol from [MRR21](https://eprint.iacr.org/2021/682) providing endemic security.
    - `vsot` "Verifiable Secret Sharing OT", a 6-round protocol from [DKLs18 (protocol 7)](https://eprint.iacr.org/2018/499.pdf) providing 
      malicious security.
- **OT Extension**: A protocol that implements an OT functionality (described below) by using a small number
  of Base OTs as seeds to generate a large number of OTs.
    - `softspoken` "SoftspokenOT", a 3-round protocol from [SoftSpokenOT](https://eprint.iacr.org/2022/192) providing malicious security,
      requiring a Base OT with endemic security (e.g., `bbot`).

We implement all OT protocols to run ξ (Xi) instances of the protocol in parallel, where the batch size ξ must be
a multiple of the computational security parameter κ (=128 bits). 

We implement all the above as Random OT (ROT/ROTe) protocols, and we provide functions to convert them
to standard OT (`Sender.Encrypt` & `Receiver.Decrypt`)
and Correlated OT (`Sender.CreateCorrelation` & `Receiver.ApplyCorrelation`) protocols based on [MR19](https://eprint.iacr.org/2019/706).

## Functionalities (flavors) of Oblivious Transfer: ROT, OT, COT
### Random OT (ROT)
A 1-out-of-2 Random Oblivious Transfer (ROT) is a two-party protocol between a sender 
and a receiver that samples two random messages $(s_0, s_1)$ for the sender, and allows
the receiver to choose one of them $(r_x = s_x)$ via a choice bit $(x)$, hiding:
- the choice bit $(x)$ to the sender.
- the other message $(s_{1-x})$ to the receiver.

```
┌------┐                      ┌------------------┐                  ┌--------┐
|      |                      |      1|2 ROT     |<---(x ∈{0,1})<---|        |
|      |                      |  s_0 <- {0,1}^*  |                  |        |
|Sender|                      |  s_1 <- {0,1}^*  |                  |Receiver|
|      |                      |  r_x = s_{x}     |                  |        |
|      |                      └------------------┘                  |        |
|      | <-- (s_0, s_1) <---------------┴-------------> (r_x) ----> |        |
└------┘                                                            └--------┘
            ┌-
s.t. r_x = -| s_0 if x = 0
            | s_1 if x = 1
		    └-
```

### Standard OT

We can build a standard 1|2 Oblivious Transfer (OT) based on a 1|2 ROT.


```
┌------┐                      ┌------------------┐                  ┌--------┐
|      |                      |      1|2  OT     |<---(x ∈{0,1})<---|        |
|      |----- (m_0, m_1) ---> |                  |                  |        |
|Sender|                      |    m_x = m_{x}   |                  |Receiver|
|      |                      |                  |                  |        |
|      |                      └------------------┘                  |        |
|      |                                └-------------> (m_x) ----> |        |
└------┘                                                            └--------┘
            ┌-
s.t. m_x = -| m_0 if x = 0
            | m_1 if x = 1
		    └-
```

To achieve this functionality, uses the two random messages $(s_0, s_1)$ resulting from a ROT 
to `Encrypt` two messages $(m_0, m_1)$ fixed by the sender with one-time pad $(m_0 ⊕ s_0, m_1 ⊕ s_1)$
and send both to the receiver, who can `Decrypt` one with the message he chose in the ROT 
$m_x = (m_0 ⊕ r_x) * (1-x) + (m_1 ⊕ r_x) * x$.

### Standard OT

Similarly, we can build a Correlated 1|2 Oblivious Transfer (COT) based on a 1|2 ROT,
to establish a correlation $z_A + z_B = a \cdot x$ between the sender and the receiver,
where the sender provides $a \in \Z_q$, the receiver sets the bit $x \in \{0,1\}$,
and the sender and receiver each get a share ($z_A$, $z_B$ respectively) of the product $a \cdot x$.

```
┌------┐                      ┌------------------┐                  ┌--------┐
|      |------ (a ∈ℤq) -----> |      1|2 COT     |<---(x ∈{0,1})<---|        |
|      |                      |                  |                  |        |
|Sender|                      | z_A <- ℤq        |                  |Receiver|
|      |                      | z_B <- a⋅x - z_A |                  |        |
|      |                      └------------------┘                  |        |
|      | <---- (z_A∈ℤq) <---------------┴----------> (z_B∈ℤq) ----> |        |
└------┘                                                            └--------┘
            
s.t. z_A + z_B = a⋅x
```

To achieve this, both parties map their ROT messages $(s_0, s_1, r_x)$ to numbers in $\Z_q$.
Then, the sender sets $z_A = s_0$ and sends a derandomising mask $\tau = s_1 - s_0 + a$ to the receiver,
who can compute $z_B = \tau \cdot x - r_x$.

