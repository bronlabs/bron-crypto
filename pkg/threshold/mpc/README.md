# Binary MPC
This package contains the implementation of Binary MPC.
Currently, it is a semi-honest protocol for three parties only.
Refer to the table below how it can be made maliciously secure.

| Protocol | Parties | Security                      | Remarks                                |
|----------|---------|-------------------------------|----------------------------------------|
| [TinyOT] | 2       | malicious, dishonest-majority |                                        |
| [FLNW17] | 3       | malicious, honest-majority    | patented, information-theoretic secure |
| [Li23+]  | 3       | malicious, honest-majority    |                                        |
| [FKOS15] | n       | malicious, dishonest-majority | "TinierOT"                             |
| [WRK17b] | n       | malicious, dishonest-majority | garbling                               |

[TinyOT]: <https://eprint.iacr.org/2018/843>
[FLNW17]: <https://eprint.iacr.org/2016/944>
[Li23+]: <https://eprint.iacr.org/2023/909>
[FKOS15]: <https://eprint.iacr.org/2015/901.pdf>
[WRK17b]: <https://eprint.iacr.org/2017/189.pdf>
