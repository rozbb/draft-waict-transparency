# WAICT Webapp Transparency for the Browser

# Introduction

This document describes a transparency system for web resources. It enables clients fetching web resources, identified by a URL, to be assured that the received web resource has been publicly logged. It also enables website operators (and others) to enumerate the history of a web resource and observe when it changes.

The primary use case is [WAICT](https://docs.google.com/document/d/16-cvBkWYrKlZHXkWRFvKGEifdcMthUfv-LxIbg6bx2o/edit?tab=t.0#heading=h.hqduv7qhbp3k), Web Application Integrity, Consistency and Transparency, which aims to bring stronger transparency and integrity properties to applications delivered over the web in order to support properties like end-to-end encrypted messaging.

# Glossary

* A **Site** is a web-based service that exposes some functionality that people want to use. Examples include Facebook or Proton Mail. **A Site is identified by its origin**, i.e., the triple of scheme, domain, and port. An origin is precisely specified in [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454.html).
* A **Web Resource** is a file identified by a URL whose contents are committed to by a cryptographic hash.
* A **User** is someone that wants to use a Site. We treat a User and their browser as one in the same in this document.
* The **Asset Host** is a content-addressable storage service. It chosen by a site to be responsible for storing the larger assets associated with transparency. This includes the resources and any values that might be referenced inside those resources.
* A **Transparency Service** is a service that a Site registers with to announce that they have enabled transparency and will log web resources to. It maintains a mapping of site to transparency information.
* A **Witness** ensures that a Transparency Service is well-behaved, i.e., only makes updates that are allowed by the specification. It receives a proof of that the transparency service has correctly transitioned the values in its map. On success, the witness signs a representation of the map.

## Notation and Dependencies

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119](https://www.rfc-editor.org/rfc/rfc2119) [RFC8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they appear in all capitals, as shown here.

We use the TLS presentation syntax from [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) to represent data structures and their canonical serialized format.

We use `||` to denote concatenation of bytestrings.

We use the Prefix Tree data structure from the [key transparency draft specification](https://www.ietf.org/archive/id/draft-keytrans-mcmillion-protocol-02.html#name-prefix-tree). We also use the `PrefixProof` structure for proofs of inclusion and non-inclusion, as well as the structure's associated verification algorithm.

We use the Signed Note data structure from the [C2SP signed note standard](https://github.com/C2SP/C2SP/blob/main/signed-note.md). We use the term "cosignature" as in the standard, to refer to a signature on a signed note.

We use the JSON Schema langauge from the [JSON Schema standard](https://json-schema.org/draft/2020-12/json-schema-core) to specify the structure of JSON objects. We also use the associated [validation standard](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.3) for additional keywords such as `maxLength` or `pattern`.

We use the base64 encoding algorithms described in [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html). Specifically we use the standard "base64" encoding and the URL-safe "base64url" encoding.

# Construction Overview

(TODO: fill in)

(TODO: Include rough estimates for Log storage requirements (and witness if required))

# The Transparency Service

The Transparency Service maintains a mapping of domains to resource hashes (and further, the histories of those resources hashes). This is encoded as a prefix tree whose keys are domains and whose values are either a _tombstone_ entry—meaning an entry that has been deleted and only remains for logging purposes—or an _active_ entry, containing:

1. The prefix root that preceded the creation of the entry
1. The hash of the resource
1. The size of the resource history for the domain
1. A URL to the asset host associated to the domain
1. The _expiry_, i.e., the Unix timestamp, in seconds, denoting the time after which this entry becomes invalid

Concretely, the Transparency Service operator maintains a prefix tree where the keys are domains and values are `EntryWithCtx`, defined as follows:
```
struct {
    uint64 time_created;
    uint8 resource_hash[32];
    uint64 chain_size; (TODO: think whether this is necessary)
    uint8 asset_host_url<1..2^8-1>; (TODO permit many URLs)
    uint64 expiry;
} ActiveEntry;

struct {
    uint64 time_created;
} TombstoneEntry; (TODO: figure out where to store expiry)

enum {
    ActiveEntry active_entry;
    TombstoneEntry tombstone_entry;
} Entry;

struct {
    Entry entry;
    uint8 chain_hash[32];
} EntryWithCtx;
```

## Hash Computations

The `chain_hash` field of an `EntryWithCtx` encodes the history of the resources associated with a given domain. This is how its hashes are computed:

1. A new resource `r` has resource hash `rh = SHA256("waict-rh" || r)`
1. The chain hash `ch` is defined with respect to the new resource hash `rh` and the old chain hash `och` as `ch = SHA256("waict-ch" || och || rh)`

The initial chain hash is the empty string `""`.

## Transparency Service API

We describe the HTTP API that the transparency service MUST expose. We denote the transparency service's domain by the variable `$tdomain`, and an enrolling site's domain as `$sdomain`.

### Enrollment via HTTPS

* Endpoint `/enroll`
* Method: GET
* Parameter `site`: The domain being enrolled. This MUST NOT have characters outside `[a-zA-Z0-9.\-]`.

Calling this endpoint causes the transparency service to make an HTTPS GET query to `https://$site/.well-known/waict-enroll` (TODO: register with IANA).

The enrolling site will return a response containing all the information the transparency service needs to create a new `EntryWithCtx`. Concretely, the site responds with with MIME type `application/json` and the schema (TODO: should history size be in here really? what is the initial chain hash for?):
```json
{
  "title": "Enrollment Data",
  "type": "object",
  "properties": {
    "asset_host": {
      "type": "string",
      "maxLength": 255,
      "$comment": "URL of the asset host"
    },
    "initial_chain_hash": {
      "type": "string",
      "maxLength": 64,
      "$comment": "Hex-encoded hash representing site's history"
    },
    "initial_chain_size": {
      "type": "integer",
      "minimum": 0,
      "$comment": "Initial size of the site's history chain"
    },
    "expiry": {
      "type": "integer",
      "minimum": 0,
      "$comment": "The time, in Unix seconds, that this enrollment expires"
    },
  },
  "required": [ "asset_host", "initial_chain_hash", "expiry" ]
  }
}
```
If the site intends to unenroll, the site serves the special value:
```json
{
  "asset_host": "",
  "initial_chain_hash": "",
  "initial_chain_size": 0,
  "expiry": 0,
}
```

After the transparency service makes the GET request, if it does not already have the domain, it:

1 Creates a leaf with key `$site`
1. Sets the value of the leaf equal to an `EntryWithCtx`, with `chain_hash`, `chain_size`, `asset_host_url`, and `expiry` equal to the given values. It also sets the `time_created` value to the current Unix time in seconds.
1. Computes a new prefix root given the new leaf
1. Gets witness cosignatures on the prefix root (via the Witness API described below)
1. Computes an inclusion proof of the leaf in the new prefix tree
1. Returns a `WaictInclusionProof`, defined as follows:
```
struct {
  EntryWithCtx entry;
  PrefixProof inc_proof;
  uint8 signed_prefix_root<1..2^24-1>;
} WaictInclusionProof;
```
where `signed_prefix_root` is a signed note whose text is
```
$tdomain/waict-v1/prefix-tree
<base64_root>
```

(TODO: consider how to deal with longer latency on enrollments. Should you get a timestamp for when the next epoch lands, or should your connection just hang until it comes)

(TODO: this doesn't give the site an easy way to interface with the transparency service going forward. If the site wants to call `/append`, what authentication mechanism does it use? How do we ensure it is the same person that registered the site? One thought is to make this process challenge-response like ACME. That is, have `$tdomain/begin-enroll` responds with two values, `chal` and `api-key`. The site puts `chal` in its `/.well-known`, and it saves the `api-key`. Then when `$tdomain/end-enroll?site=$site` is called, it will validate `chal` and thus enable `api-key`. Another idea is to keep the 1-shot enrollment and just have the `/.well-known` file contain a pubkey. But pulling in a whole new sig standard for this seems like overkill)

If the domain already exists in the transparency service's prefix tree, then the service checks if the object is the special unenrollment form and, if so, replaces the site's leaf with a `TombstoneEntry` with the current time. If the object is not the special unenrollment form, then the transparency service updates the leaf's `asset_host` and `expiry` fields with the provided ones.

Note: In all endpoints, it is intentional that `time_created` never changes for as long as that entry exists. The only time it changes is on deletion of that leaf.

### Append to chain

* Endpoint: `/append`
* Method: POST
* Body: `application/octet-stream` containing a serialized `AppendReq`, defined below
* Return value: A `WaictInclusionProof` for the new entry in the new prefix tree
* Authentication: Defined by the transparency service, e.g. a JWT. The transparency service MAY apply further policies or rate limits, e.g. requiring payment per resource logged.

The append endpoint takes a domain and a resource value to append to that domain's chain:
```
struct {
  uint8 domain<1..2^8-1>;
  uint8 value<1..2^24-1>;
} AppendReq;
```

The transparency service appends the given value hash to the corresponding entry. That is, the transparency service

1. Fetches the current `EntryWithCtx` with key `domain`, erroring if no entry exists or if the entry is a `TombstoneEntry`
1. Updates the entry's `resource_hash` to the resource hash of `value`
1. Increments the entry's `chain_size`
1. Updates the entry's `chain_hash` by computing the new chain hash with respect to the new resource hash

(TODO: this should maybe support arbitrary fast-forward, not just single item appends; note this has to be within reason bc of the linear proof size)

### Get Leaf

* Endpoint: `/leaf`
* Method: GET
* Query parameter `domain`: The domain of the site whose `EntryWithCtx` is desired
* Return: An `application/octet-stream` containing a `WaictInclusionProof` for the given domain

### Get Resource Hash Tile

* Endpoint: `/resource-hash-tile/<N>[.p/<W>]`
* Method: GET
* Response: An `application/octet-stream` containing up to 256 resource hashes

`<N>` is the index of the _tile_ where each tile is 256 consecutive resource hashes in the history of the site. `N` MUST be a non-negative integer encoded into 3-digit path elements. All but the last path element MUST begin with an x. For example, index 1234067 will be encoded as `x001/x234/067`.

The `.p/<W>` suffix is only present for partial tiles, defined below. <W> is the width of the tile, a decimal ASCII integer between 1 and 255, with no additional leading zeroes.

The transparency service MUST store a tile of an enrolled site for at least one year beyond the youngest entry in the tile. If the tile is partial, then the transparency service MUST NOT delete it until the site unenrolled.

A transparency service MAY prune sites for inactivity. That is, it MAY unenroll them after a year of no updates.

### Get Chain Hash

* Endpoint: `/chain-hash/<N>`
* Method: GET
* Returns: An `application/octet-stream` containing the `N`-th chain hash (0-indexed).

`<N>` is formatted as above. The transparency service MUST store a chain hash of an enrolled site for at least one year.

# Witness API

A witness is a stateful signer. It maintains a full copy of the prefix tree that it is witnessing the evolution of. When a witness receives a signature request from a transparency service, it checks that the tree evolved faithfully, then signs the root. This is its only API endpoint.

## Request signature

* Endpoint: `/request-sig`
* Method: POST
* Body: `application/octet-stream` containing a serialized `SigReq`, defined below

The body of a signature request contains two components:

1. A list of every new prefix tree entry (included deleted ones)
1. The root as a signed note, with variant `0x04` signatures (timestamped ed25519), signed with the calling transparency service's public key. The signed note text is of the form described above.

Concretely, the body is a `SigReq` structure, defined as:
```
struct EntryDelete;

enum {
    ActiveEntry entry_update;
    EntryDelete entry_delete;
} EntryOp;

struct {
    uint8 key[32];
    EntryOp op;
} NewEntry;

struct {
    NewEntry new_entries<1..2^16-1>;
    uint8 note<1..2^24-1>,
} SigReq;
```

To validate a `SigReq`, the witness:

1. Checks that `new_entries` has no duplicates`
1. Loads the last known prefix tree state belonging to the transparency service
1. Updates all entries. For each element of `new_entries`, the witness:
    1. If it is not an `EntryDelete`,
        1. Ensures `chain_size` increases by 1 (TODO: should we permit proofs where a site adds more than one entry?)
        1. Ensures `time_created` is unchanged
        1. Ensures `expiry` is in the future, and not too far in the future
        1. Computes the new chain hash of the entry using its stored old chain hash and the given entry's `resource_hash`.
    1. If it is an `EntryDelete`, sets the entry to a `TombstoneEntry` with the current epoch as `time_created`.
1. Computes the new prefix tree root using the given entries and computed chain hashes
1. Verifies the transparency service's signature on the updated prefix root, aborting on failure
1. Adds its own cosignature to the signed note. Again, this is timestamped ed25519
1. Updates its copy of the prefix tree
1. Returns the new signed note

Note: if a transparency service becomes unable to produce new proofs, it will be impossible for it to get new signatures. So in the case of data loss or intentional tampering, a transparency service is forced to negotiate with witnesses to have them accept a new tree.

(TODO: any other endpoint a witness should provide? registration should probably be with a human in the loop)

# Asset Host API

The asset host only need to be able to return a file given its hash.

## Get Asset

* Endpoint `/fetch/<hash>`, where `<hash>` is length-64 lowercase hex
* Method: GET
* Response: An `octet-stream` containing the resource whose SHA256 hash is `<hash>`

These endpoints are immutable, so asset hosts SHOULD have long caching times.

(TODO: think about signalling hash function in this. use multihash? or just put `/sha256/` in the path?)

# Client Behavior

A client's only job is to verify inclusion proofs. Of course, strong security guarantees only come when the client enforces the validity of these inclusion proofs, which means the client must know when the proofs are necessary and unnecessary (i.e., when transparency is enabled). The question of _signalling_ is often domain specific, though, and is thus left out of scope. See the appendix for examples of how this could be done.

## Verifying a Resource

To verify a given resource on site domain `$sdomain`, the user

1. Computes the resource hash `rh` and checks that it equals `entry.resource_hash`.
1. Parses `signed_prefix_root` and extracts the root hash.
1. Verifies `inc_proof` with respect to the key `$sdomain`, value `entry`, and the parsed prefix root.
1. Checks that the domain in the first line in `signed_prefix_root` (everything before the first `/`) matches the domain of the site being accessed.
1. Verifies the cosignatures on `signed_prefix_root`. The client MAY choose the set of public keys that it trusts for this verification step.

# Appendix

We describe possible uses of this transparency protocol which are not considered part of the standard.

## WAICT Transparency Signalling

We want clients to signal that they support transparency. Doing so will allow the server to avoid sending unnecessary transparency information to the client. To this end, clients SHOULD include the header `WAICT-Transparency-Supported: 1` when connecting to a site. Future versions of this specification may define different version numbers.

### Time-limited Signalling

Sites must also signal to the client the parameters of its transparency guarantees. In particular, it must signal when transparency expires and where to find the inclusion proof. This is done via a response header:
```
WAICT-Transparency: expires=<uint64>, inclusion=<str>
```
where the value of the `expires` field is Unix time in seconds, the value of `inclusion` is a base64url-encoded URL to a `WaictInclusionProof`. (TODO: add an option to embed inclusion into the header if it's short enough; also proof of non-inclusion or proof of tombstone inclusion to show that the site is unenrolled) (TODO: you don't need proof of non-inclusion if you just make sure your tombstone proof validity period is longer than the validity period of whatever is making the user believe transparency should be enabled)

Note: The inclusion proof depends on the manifest. To ensure that all data is coherent, the URLs SHOULD include some component that is unique to the site version, e.g., the current site history hash, or the integrity policy hash.

### Time-independent Signalling

A site can enable transparency in a way that expires much further in the future, and has stronger first-use guarantees. We can define a **preload list**, a list of sites that are preloaded on the browser. If a site is on the preload list then the client will enforce that it receives transparency information from the site, unless the site can prove that it has unenrolled since that preload list was constructed.

In this setting, browser vendors maintain the preload list, and MUST keep the invariant that any site on the preload list stays there until it is unenrolled (either intentionally or by pruning). Further, the preload list must itself be transparent.

## Extension Values with Cooldown

Sites may wish to have associated metadata that is subject to certain update rules. We call these _extensions_. As an example, a site may wish to support Sigstore-based code signing, and have developer OpenID identifiers as extensions. A cooldown period on this extension would guarantee that, if a site changes developer IDs, it must wait, e.g., 24 hours for the change to go into effect. Further, since the manifest extensions are themselves transparent, a site can use a simple script to monitor for extension changes and notify the maintainer if an unexpected change happens.

To define a cooldown mechanism for a site extension, the site maintainer needs to make two updates every time it updates an extension called, say, `foobar`:

1. It updates the extension `foobar` with the value that it desires. It receives the inclusion proof of the manifest in the new prefix tree.
1. It updates the extension `foobar-inclusion` with the inclusion proof above.

Now any client can enforce the cooldown property by simply verifying `foobar-inclusion` and checking how old its timestamp is. If it verifies and the timestamp is sufficiently old, then it uses the value in `foobar`. Otherwise, it errors and uses whatever valid stored value it has.

(TODO: the details above aren't worked out. Where are these extensions stored? How do you check an old inclusion proof without providing the entire old manifest + extensions?)

## Inclusion endpoint

The URL given in the `inclusion` field in the `WAICT-Transparency` header returns the entry (containing the resource hash), a proof showing that that entry is in the prefix tree, and a signed prefix tree root. Concretely, the response is an `application/octet-stream` containing a serialized `WaictInclusionProof`.

## Verifying Inclusion

The client must verify all pieces of data that are committed to by the tree. This includes the integrity policy and the extensions.

### Verifying extensions

To verify a single extension, given its key and value hash, the user:

1. Checks that the given key and value hash appear in `leaf.extensions`
1. Verifies `inc_proof` and signatures as above

# Signaling Transparency to the User

Transparency can be enabled by a site two different ways. One easy to revert and one hard to revert.

A site can enable transparency via the `WAICT-Transparency` header described above. The `expires` field tells the client to expect transparency information from the website until the provided time (exclusive). The client MAY then behave as if transparency were enabled.

## Transparency service signaling

Mere presence in the transparency service map does not imply that a website has transparency enabled for all users. To enable it for all users until the expiry of the entry, the `enforce` flag must be set to `true`.

A site can opt into this stronger enforcement by following the enrollment procedure with `enforce` set to `true`. A transparency service MUST NOT permit `enforce` to be reverted to `false`. If a site operator wishes to disable `enforce`, they must first unenroll.
