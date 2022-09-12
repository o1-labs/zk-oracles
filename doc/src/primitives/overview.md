# Primitives
This section introduces cryptographic primitives and optimizations that are used in zkOracles protocol. These primitives include Garbled Circuit (GC), Oblivious Transfer (OT) and general-purpose two-party computation protocols based on GC and OT.

More specifically, this section will cover the following contents.

- **Garbled Circuit**
    - Including the Free-XOR, Point-and-Permute, Row-Reduction and Half-Gate optimizations. Note that zkOracles will use the Half-Gate optimization, and the entire protocol only has semi-honest security.

- **Oblivious Transfer**
    - Including base OT and OT extension. Note that we focus on maliciously secure OT protocols. The overhead is comparable to protocols with semi-honest security.

- **Two-Party Computation Protocol**
    - This is the well-known Yao's 2PC protocol based on GC and OT.