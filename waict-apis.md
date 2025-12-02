# WAICT APIs

# Introduction

This document describes a set of APIs for a transparency system for web resources. It enables clients fetching web resources, identified by a URL, to be assured that the received web resource has been publicly logged. It also enables website operators (and others) to enumerate the history of a web resource and observe when it changes.

The primary use case is [WAICT](https://docs.google.com/document/d/16-cvBkWYrKlZHXkWRFvKGEifdcMthUfv-LxIbg6bx2o/edit?tab=t.0#heading=h.hqduv7qhbp3k), Web Application Integrity, Consistency and Transparency, which aims to bring stronger transparency and integrity properties to applications delivered over the web in order to support properties like end-to-end encrypted messaging.

# Glossary

* A **Site** is a web-based service that exposes some functionality that people want to use. Examples include Facebook or Proton Mail. **A Site is identified by its origin**, i.e., the triple of scheme, domain, and port. An origin is precisely specified in [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454.html).
* A **Web Resource** is a file identified by a URL whose contents are committed to by a cryptographic hash.
* A **User** is someone that wants to use a Site. We treat a User and their browser as one in the same in this document.
* A **Transparency Service** is a service that a Site registers with to announce that they have enabled transparency and will log web resources to. It maintains a mapping of site to transparency information.
* An **Asset Host** is a content-addressable storage service. One or more are chosen by a site to be responsible for storing the assets logged in the transparency service.
* A **Witness** ensures that a Transparency Service is well-behaved, i.e., only makes updates that are allowed by the specification. It receives a proof of that the transparency service has correctly transitioned the values in its map. On success, the witness signs a representation of the map.

## Notation and Dependencies

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119](https://www.rfc-editor.org/rfc/rfc2119) [RFC8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they appear in all capitals, as shown here.

We use the TLS presentation syntax from [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) to represent data structures and their canonical serialized format.

We use `||` to denote concatenation of bytestrings. Unless otherwise specified, we use the placeholder text `<digest>` to refer to the zero-padded length-64 lowercase hex encoding of a SHA-256 digest prefixed by `sha256:`.

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
1. A commitment to the asset hosts associated with the domain

Concretely, the Transparency Service operator maintains a prefix tree where the keys are domains and values are `EntryWithCtx`, defined as follows:
```
struct {
    uint64 time_created;
    uint8 resource_hash[32];
    uint64 chain_size; (TODO: think whether this is necessary)
    uint8 asset_hosts_hash[32];
} ActiveEntry;

struct {
    uint64 time_created;
} TombstoneEntry;

enum { active(0), tombstone(1) } EntryTag;
struct {
    EntryTag type;
    select (Entry.type) {
        case active: ActiveEntry;
        case tombstone: TombstoneEntry;
    };
} Entry;

struct {
    Entry entry;
    uint8 chain_hash[32];
} EntryWithCtx;
```

As sites interact with the transparency service, the prefix tree changes. These changes are encoded as a growing sequence of `TreeEvent` structs, defined below. The index of the tree event in the full sequence (0-indexed) is called the event's _epoch_.

```
struct {
  opaque url<1..511>;
} AssetHost;

struct {
  opaque domain<1..255>;
  AssetHost asset_hosts<1..2^13-1>;
} TreeEventAdd;

struct {
  opaque domain<1..255>;
} TreeEventRemove;

struct {
  opaque domain<1..255>;
  opaque new_resource_hash[32];
} TreeEventUpdate;

enum { add(0), remove(1), update(3) } TreeEventTag;
struct {
  TreeEventTag type;
  select (TreeEvent.type) {
      case add: TreeEventAdd;
      case remove: TreeEventRemove;
      case update: TreeEventUpdate;
  };
} TreeEvent;
```

Finally, the tree event sequence has a subsequence called _checkpoint indices_. Each checkpoint index correspond to a tree state that is cosigned by witnesses. Specifically, a checkpoint index `i` corresponds to the prefix tree resulting from processing the tree events with epochs `[0, i)` in order.

(TODO: should events be strongly ordered? That is, should events have their epoch included inside, and should that epoch be included in some hash computations? This would make it so that any two people who agree on a prefix tree root necessarily agree on a tree event sequence. On the other hand, it is weird to hash in unrelated information for tree hashes.)

## Hash Computations

The `chain_hash` field of an `EntryWithCtx` encodes the history of the resources associated with a given domain. This is how its hashes are computed:

1. A new resource `r` has resource hash `rh = SHA-256("waict-rh" || r)`
1. The chain hash `ch` is defined with respect to the new resource hash `rh` and the old chain hash `och` as `ch = SHA-256("waict-ch" || och || rh)`

The initial chain hash is the empty string `""`.

The `asset_hosts_hash` encodes the asset hosts where resources can be fetched from. It's computed over the comma-separated list of base64-encoded URLs, with no trailing comma. `asset_hosts_hash = SHA-256("waict-ah" || entry1_b64 || "," || entry2_b64 || "," || ...)`.

## Transparency Service API

We describe the HTTP API that the transparency service MUST expose. We denote the transparency service's domain by the variable `$tdomain`, and an enrolling site's domain as `$sdomain`.

### Enrollment via HTTPS

* Endpoint `/enroll`
* Method: GET
* Parameter `site`: The domain being enrolled. This MUST NOT have characters outside `[a-zA-Z0-9.\-]`.

Calling this endpoint causes the transparency service to make an HTTPS GET query to `https://$site/.well-known/waict-enroll` (TODO: register with IANA).

The enrolling site will return a response containing all the information the transparency service needs to create a new `EntryWithCtx`. Concretely, the site responds with with MIME type `application/json` and the schema:
```json
{
  "title": "Enrollment Data",
  "type": "object",
  "properties": {
    "asset_hosts": {
      "type": "string",
      "maxLength": 8096,
      "$comment": "Comma-separated list of base64-encoded URLs corresponding to asset hosts"
    }
  },
  "required": [ "asset_hosts" ]
  }
}
```
If the site intends to unenroll, the site responds with the special value:
```json
{
  "asset_hosts": [],
}
```
(TODO: There is an argument that empty asset hosts should be allowed. Eg if you want to sign up for website change monitoring without auditability.)

After the transparency service makes the GET request, if it does not already have the domain, it:

1. Creates a leaf with key `$site`
1. Sets the value of the leaf equal to an `EntryWithCtx`, with `chain_hash`, `chain_size`, and `asset_host_url` equal to the given values. It also sets the `time_created` value to the current Unix time in seconds.
1. Computes a new prefix root given the new leaf
1. Gets witness cosignatures on the prefix root (via the Witness API described below)
1. Computes an inclusion proof of the leaf in the new prefix tree
1. Returns an `EntryWithProof`, defined as follows:
```
struct {
  EntryWithCtx entry;
  WaictInclusionProof inc_proof;
} EntryWithProof;
```
where `WaictInclusionProof` is from the [WAICT proofs spec](./waict-proofs.md).

(TODO: consider how to deal with longer latency on enrollments. Should you get a timestamp for when the next epoch lands, or should your connection just hang until it comes)

(TODO: this doesn't give the site an easy way to interface with the transparency service going forward. If the site wants to call `/append`, what authentication mechanism does it use? How do we ensure it is the same person that registered the site? One thought is to make this process challenge-response like ACME. That is, have `$tdomain/begin-enroll` responds with two values, `chal` and `api-key`. The site puts `chal` in its `/.well-known`, and it saves the `api-key`. Then when `$tdomain/end-enroll?site=$site` is called, it will validate `chal` and thus enable `api-key`. Another idea is to keep the 1-shot enrollment and just have the `/.well-known` file contain a pubkey. But pulling in a whole new sig standard for this seems like overkill)

If the domain already exists in the transparency service's prefix tree, then the service checks if the object is the special unenrollment form and, if so, replaces the site's leaf with a `TombstoneEntry` with the current time. If the object is not the special unenrollment form, then the transparency service updates the leaf's `asset_host` field with the provided one.

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

### Get Asset Hosts

* Endpoint: `/asset-hosts/<digest>`
* Method: GET
* Returns: An `application/octet-stream` containing the comma-separated list of base64-encoded URLs corresponding to the `hash`.

`<digest>` is an `asset_hosts_hash` inside some `EntryWithCtx` hosted by the transparency service. Every such value MUST be served at this endpoint.

This endpoint is similar in function to the [issuers](https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#issuers) endpoint used in Static CT. Sites are not expected to change their asset hosts frequently, but must be free to do so as-needed.

### Get Tree Events

* Endpoint: `/tree-events/<N>`
* Method: GET
* Returns: An `application/octet-stream` containing `TreeEvents`. The contained events have epoch in the range `[N, N+1000)`, and appear in ascending order of epoch. The contained checkpoint indices, if any, are in the range `(N, N+1000]`.

`<N>` is formatted as above. Once an event or checkpoint index has been included in a response for `/tree-events/<N>`, it MUST be included in all future responses for the same endpoint, and the event MUST occur in the same position. As a corrolary, once a response has reached 1000 events, its `events` field is immutable. To help with long-term caching, we say that the first response for `/tree-events/<N>` that contains 1000 events is the response that the endpoint MUST serve forever. This means that checkpoint indices in the specified range MUST NOT change after the 1000th event has been served.

Since this endpoint produces very large responses, a transparency service MAY require additional GET parameters or headers for authorization purposes.

The definition of `TreeEvents` is below:
```
struct {
  uint16 num_events;
  uint16 checkpointed_idxs<0..31>,
  TreeEvent events<1..2^24-1>;
} TreeEvents;
```

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

* Endpoint `/fetch/<digest>`
* Method: GET
* Response: An `octet-stream` containing the resource whose SHA-256 hash is `<digest>`

These endpoints are immutable, so asset hosts SHOULD have long caching times.

(TODO: think about signalling hash function in this. use multihash? or just put `/sha256/` in the path?)

# Client Behavior

A client's only job is to verify inclusion proofs. This is covered in the [WAICT proofs spec](waict-proofs.md). Of course, strong security guarantees only come when the client enforces the validity of these inclusion proofs, which means the client must know when the proofs are necessary and unnecessary (i.e., when transparency is enabled). This question of _signalling_ is covered in the [WAICT signalling spec](waict-signalling.md).

# Appendix

We describe possible uses of this transparency protocol which are not considered part of the standard.

## Extensions

Sites may wish to have associated metadata that is subject to certain update rules. We call these **extensions**.

As an example, a site may wish to support Sigstore-based code signing, and have developer OpenID identifiers as extensions. A cooldown period on this extension would guarantee that, if a site changes developer IDs, it must wait, e.g., 24 hours for the change to go into effect. Further, since the manifest extensions are themselves transparent, a site can use a simple script to monitor for extension changes and notify the maintainer if an unexpected change happens.

To define a cooldown mechanism for a site extension, the site maintainer needs to make two updates every time it updates an extension called, say, `foobar`:

1. It updates the extension `foobar` with the value that it desires (to delete, the value should be set to the empty string, essentially as a tombstone). It receives the inclusion proof of the manifest in the new prefix tree.
1. It updates the extension `foobar-inclusion` with the inclusion proof above.

Now any client can enforce the cooldown property by simply verifying `foobar-inclusion` and checking how old its timestamp is. If it verifies and the timestamp is sufficiently old, then it uses the value in `foobar`. Otherwise, it errors and uses whatever valid stored value it has.

(TODO: the details above aren't worked out. Where are these extensions stored? How do you check an old inclusion proof without providing the entire old manifest + extensions?)

### Preload Lists for Extensions

Clients still have to know to expect the extension, otherwise a site can just delete the extension without cooldown. So any extension ecosystem will have to maintain its own preload list. If a site wants to disable the extension, they request removal from the preload list. Until then, they serve tombstone values.

Another option is to have extensions piggyback on the transparency preload list. This requires one modification: rather than being a list, we say browser vendors maintain a **transparency preload dictionary**, mapping domains to hashes.

In this setup, the browser vendor maintains the signup form as before, but also exposes an input form, where site owners can write the extensions they wish to commit to to all users. The
vendor hashes this list and sets this to the site's value in the transparency preload dictionary. When a user navigates to a site in the preload dictionary, the user retrieves the hash, and expects the site to reveal the extension list it committed to.
