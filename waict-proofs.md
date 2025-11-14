# WAICT Proofs and Algorithms

# Introduction

This document defines the data structures and algorithms for the proofs used in the WAICT transparency specification.

# Notation and Dependencies

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119](https://www.rfc-editor.org/rfc/rfc2119) [RFC8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they appear in all capitals, as shown here.

We use the TLS presentation syntax from [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) to represent data structures and their canonical serialized format.

We use the Prefix Tree data structure from the [key transparency draft specification](https://www.ietf.org/archive/id/draft-keytrans-mcmillion-protocol-02.html#name-prefix-tree). We also use the `PrefixProof` structure for proofs of inclusion and non-inclusion, as well as the structure's associated verification algorithm.

We use the Signed Note data structure from the [C2SP signed note standard](https://github.com/C2SP/C2SP/blob/main/signed-note.md). We use the term "cosignature" as in the standard, to refer to a signature on a signed note.

# Inclusion Proofs

An entry

```
struct {
  PrefixProof inc_proof;
  uint8 signed_prefix_root<1..2^24-1>;
} WaictInclusionProof;
```
where `signed_prefix_root` is a signed note whose text is
```
$tdomain/waict-v1/prefix-tree
<base64_root>
```

To verify a `WaictInclusionProof` with respect to a leaf key and value, the verifier:

1. Parses `signed_prefix_root` and extracts the root hash.
1. Verifies `inc_proof` with respect to the given leaf key and value, and the parsed prefix root.
1. Checks that the domain in the first line in `signed_prefix_root` (everything before the first `/`) matches the domain of a transparency service. The client MAY choose the set of transparency services that it trusts for this verification step.
1. Verifies the cosignatures on `signed_prefix_root`. The client MAY choose the set of public keys that it trusts for this verification step.

When the resource is a manifest and the verifier is a web browser, the leaf key is the current site's domain and the value is the `EntryWithCtx`. The client also MUST verify that the resource hash of the provided manifest matches the `resource_hash` of the given entry.
