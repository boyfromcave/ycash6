# Spec proposal for 0.5.3: the txid of a Yugen leaf transaction

Provenance: Original (the Ycash developers, 2026), node decision N-D7 (`doc/yugen-node.md`),
review M-4. Spec 0.5.2 is silent on the leaf txid.

## Proposal
1. The txid of a transaction in the Yugen version group is the double-SHA-256 of its
   serialization with both leaf proof fields (`proof_a`, `proof_b`) serialized as empty.
   It therefore covers exactly what the signature hash covers: the ZIP-243 fields plus
   hashYugen over the leaf transfer bytes.
2. The auth digest (`hashAux` of MSG_TX inventory) stays the pre-NU5 placeholder; relay is keyed
   on the txid as for every v4 transaction.
3. A block's leaf proofs are not committed by `hashMerkleRoot`. A block refused for a
   proof-derived reason (bad, missing or over-long proof, leaf weight) is treated as possibly
   corrupt in transit, not invalid for good; a transaction refused for such a reason is not
   cached as rejected. A bundle transaction (proof fields empty) is unchanged.

## Why
A proof is re-randomisable: a txid over the proofs (or over their hashes) lets a relayer change
the txid of a signed transfer (malleability). With rule 1 the txid is fixed by the signer.

## Options considered
(a) txid over the serialization with proofs replaced by their hashes: still malleable.
(b) as proposed, with the auth digest set to the proofs' hash: breaks v4 relay (MSG_TX getdata
matches the placeholder). (c) as proposed: taken.

## Open for the spec
Whether 0.5.3 adds an auth-data commitment for leaf proofs in the block header path (a later NU),
which would let proof-derived refusals mark a block invalid for good.

## Acceptance criteria
- The spec text states rule 1 and rule 3; test vectors give one leaf transaction's txid with
  proofs present and the same txid with proofs replaced.
- The node (regtest, implemented on yugen/node) and yewd-yugen's fallback `Tx::txid()` compute
  the same txid for those vectors.
