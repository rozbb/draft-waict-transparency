# WAICT Webapp Transparency for the Browser

# Introduction

This document describes a transparency system for web resources. It enables clients fetching web resources, identified by a URL, to be assured that the received web resource has been publicly logged. It also enables website operators (and others) to enumerate the history of a web resource and observe when it changes.

The primary use case is [WAICT](https://docs.google.com/document/d/16-cvBkWYrKlZHXkWRFvKGEifdcMthUfv-LxIbg6bx2o/edit?tab=t.0#heading=h.hqduv7qhbp3k), Web Application Integrity, Consistency and Transparency, which aims to bring stronger transparency and integrity properties to applications delivered over the web in order to support properties like end-to-end encrypted messaging.

# Glossary

* A **Site** is a web-based service that exposes some functionality that people want to use. Examples include Facebook or Proton Mail. **A Site is identified by its origin**, i.e., the triple of scheme, domain, and port. An origin is precisely specified in [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454.html).
* A **Web Resource** is a file identified by a URL whose contents are committed to by a cryptographic hash.
* A **User** is someone that wants to use a Site. We treat a User and their browser as one in the same in this document.
* The **Asset Host** is a party chosen by a site to be responsible for storing the larger assets associated with transparency. This includes the integrity manifest, asset pointer file, and assets themselves.
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

The Transparency Service maintains a mapping of domains to resource hashes (and further, the histories of those resources hashes). This is encoded as a prefix tree whose keys are domains and whose values are either a _tombstone_ entry, meaning an entry that has been deleted and only remains for logging purposes, or an _active_ entry, containing:

1. The prefix root that preceded the creation of the entry
1. The hash of the resource
1. The size of the resource history for the domain
1. A URL to the asset host associated to the domain
1. The _expiry_, i.e., the Unix timestamp, in seconds, denoting the time after which this entry becomes invalid
1. The _enforce_ flag, which, when `true`, causes clients to enforce transparency checks even if the site's transparency-related headers have expired
1. A set of _extensions_, i.e., values associated to the domain, which can be treated differently than ordinary resources.

Concretely, the Transparency Service operator maintains a prefix tree where the keys are domains and values are `EntryWithCtx`, defined as follows:
```
struct {
  uint8 key[16],
  uint8 value_hash[32],
} Extension;

struct {
    uint8 epoch_created[32];
    uint8 resource_hash[32];
    uint64 chain_size; (TODO: think whether this is necessary)
    uint8 asset_host_url<1..2^8-1>; (TODO permit many URLs)
    uint64 expiry;
    bool enforce;
    Extension extensions<0..sizeof(Extension)*16-1>;
} ActiveEntry;

struct {
    uint8 epoch_created[32];
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
    }
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
    "enforce": {
      "type": "boolean",
      "$comment": "Whether this site has transparency enforced by all clients (until the expiry)."
    },
    "expiry": {
      "type": "integer",
      "minimum": 0,
      "$comment": "The time, in Unix seconds, that this enrollment expires"
    },
    "extensions": {
      "type": "array",
      "maxItems": 32,
      "items": { "$ref": "#/$defs/extensionItem" },
      "$comment": "Extensions of the form key -> value"
    }
  },
  "required": [ "asset_host", "initial_chain_hash", "expiry" ],
  "$defs": {
    "extensionItem": {
      "type": "object",
      "required": [ "key", "value" ],
      "properties": {
        "key": {
          "type": "string",
          "maxLength": "16",
        },
        "value": {
          "type": "string",
          "maxLength": "64",
        },
      }
    }
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
  "enforce": false
}
```

After the transparency service makes the GET request, if it does not already have the domain, it:

1 Creates a leaf with key `$site`
1. Sets the value of the leaf equal to an `EntryWithCtx`, with `chain_hash`, `chain_size`, `asset_host_url`, `expiry`, and `enforce` equal to the given values, and with all extension keys set to the given keys, and `value_hash` set to `SHA256("waict-vh" || value)` for each entry. It also sets the `epoch_created` value to the current prefix tree root. (TODO: settle on epoch-created vs time-created)
1. Computes a new prefix root given the new leaf
1. Gets witness cosignatures on the prefix root (via the Witness API described below)
1. Computes an inclusion proof of the leaf in the new prefix tree
1. Returns a struct of the form
```
struct {
  EntryWithCtx entry;
  PrefixProof inc_proof;
  uint8 signed_prefix_root<1..2^24-1>;
} WaictEnrollmentResponse
```
where `signed_prefix_root` is a signed note whose text is
```
$tdomain/waict-v1/prefix-tree
<base64_root>
```

(TODO: consider how to deal with longer latency on enrollments. Should you get a timestamp for when the next epoch lands, or should your connection just hang until it comes)

(TODO: this doesn't give the site an easy way to interface with the transparency service going forward. If the site wants to call `/append`, what authentication mechanism does it use? How do we ensure it is the same person that registered the site? One thought is to make this process challenge-response like ACME. That is, have `$tdomain/begin-enroll` responds with two values, `chal` and `api-key`. The site puts `chal` in its `/.well-known`, and it saves the `api-key`. Then when `$tdomain/end-enroll?site=$site` is called, it will validate `chal` and thus enable `api-key`. Another idea is to keep the 1-shot enrollment and just have the `/.well-known` file contain a pubkey. But pulling in a whole new sig standard for this seems like overkill)

If the transparency service already has this domain, then it checks if the file is the special unenrollment form and, if so, replace the corresponding leaf with a `TombstoneEntry` with the last epoch value. If it is not the special unenrollment form, then the transparency service updates its `asset_host` and `expiry` fields with the provided ones. It also updates the `enforce` field with the provided one if the provided one is `true`. (TODO: and what about extensions? shouldn't updates in those be transparent?)

Note: In all endpoints, it is intentional that `epoch_created` never changes for as long as that entry exists. The only time it changes is on deletion of that leaf.

### Append to chain

* Endpoint: `/append`
* Method: POST
* Parameter `domain`: domain of resource to add or update
* Parameter `value`: base64-encoded value to append
* Return value: A `WaictInclusionProof`, described below
* Authentication: Defined by the transparency service, e.g. a JWT. The transparency service MAY apply further policies or rate limits, e.g. requiring payment per resource logged.

The append endpoint takes a resource value and appends its hash to that leaf's chain. The transparency service hashes the new value into the chain and increments the chain size.

(TODO: this should maybe support arbitrary fast-forward, not just single item appends; note this has to be within reason bc of the linear proof size)

### Get Leaf

* Endpoint: `/get-leaf`
* Method: GET
* Parameter `domain`: The domain of the site whose `EntryWithCtx` is desired
* Return: An `application/octet-stream` containing a `WaictInclusionProof` for the given domain

### Update leaf metadata

(TODO: need to be able to update extensions, asset URLs, enforce, and also some way to bump expiry)

### Resource Hash Tile

* Endpoint: `/resource-hash-tile/<N>[.p/<W>]`
* Method: GET
* Response: An `application/octet-stream` containing up to 256 resource hashes

`<N>` is the index of the _tile_ where each tile is 256 consecutive resource hashes in the history of the site. `N` MUST be a non-negative integer encoded into 3-digit path elements. All but the last path element MUST begin with an x. For example, index 1234067 will be encoded as `x001/x234/067`.

The `.p/<W>` suffix is only present for partial tiles, defined below. <W> is the width of the tile, a decimal ASCII integer between 1 and 255, with no additional leading zeroes.

The transparency service MUST store a tile of an enrolled site for at least one year beyond the youngest entry in the tile. If the tile is partial, then the transparency service MUST NOT delete it until the site unenrolled.

A transparency service MAY prune sites for inactivity. That is, it MAY unenroll them after a year of no updates.

### Chain Hash

* Endpoint: `/chain-hash/<N>`
* Method: GET
* Returns: An `application/octet-stream` containing the `N`-th chain hash (0-indexed).

`<N>` is formatted as above. The transparency service MUST store a chain hash of an enrolled site for at least one year.

(TODO: should we batch manifests like tiles? they can get big)

# Witness API

A witness is a stateful signer. It maintains a full copy of the prefix tree that it is witnessing the evolution of. When a witness receives a signature request from a transparency service, it checks that the tree evolved faithfully, then signs the root. This is its only API endpoint.

## Request signature

* Endpoint: `/req-sig`
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
        1. Ensures `enforce` only moves from false to true, or false to false
        1. Ensures `chain_size` increases by 1 (TODO: should we permit proofs where a site adds more than one entry?)
        1. Ensures `epoch_created` is unchanged
        1. Ensures `expiry` is in the future, and not too far in the future
        1. Computes the new chain hash of the entry using its stored old chain hash and the given entry's `resource_hash`.
    1. If it is an `EntryDelete`, sets the entry to a `TombstoneEntry` with the current epoch as `epoch_created`.
1. Computes the new prefix tree root using the given entries and computed chain hashes
1. Verifies the transparency service's signature on the updated prefix root, aborting on failure
1. Adds its own cosignature to the signed note. Again, this is timestamped ed25519
1. Updates its copy of the prefix tree
1. Returns the new signed note

Note: if a transparency service becomes unable to produce new proofs, it will be impossible for it to get new signatures. So in the case of data loss or intentional tampering, a transparency service is forced to negotiate with witnesses to have them accept a new tree.

(TODO: any other endpoint a witness should provide? registration should probably be with a human in the loop)

# Asset Host API

The asset host only need to be able to return a file given its hash.

## Fetch

* Endpoint `/fetch/<hash>`, where `<hash>` is length-64 lowercase hex
* Method: GET
* Response: An `octet-stream` containing the resource whose SHA256 hash is `<hash>`

These endpoints are immutable, so asset hosts SHOULD have long caching times.

# Site API

Clients which support transparency information and expect to be served a proof SHOULD include the header `WAICT-Transparency-Supported: 1` when connecting to a site. Future versions of this specification may define different version numbers.

In order to convey transparency information to the user, the site tells it where to find transparency information. This is done via a response header:
```
WAICT-Transparency: expires=<uint64>, inclusion=<str>, extensions=<str>
```
where the value of the `expires` field is Unix time in seconds, the value of `inclusion` is a base64url-encoded URL to a transparency inclusion proof, and `extensions` is a base64url-encoded URL to the full list of extension values. (TODO: add an option to embed inclusion into the header if it's short enough) (TODO: also add an option to embed a non-inclusion proof in a newer tree so that you can convince clients you disabled transparency)

Note: The inclusion proof is dependent on the manifest and extensions. To ensure that all data is coherent, the URLs SHOULD include some component that is unique to the site version, e.g., the current site history hash, or the integrity policy hash.

## Extension endpoint

The URL given in the `extension` field in the `WAICT-Transparency` header returns a JSON object of extension values. If a key matches one of the keys in `entry.extensions` served by the inclusion proof endpoint, then the value is either a string literal or a URL to the value. Concretely, every value whose key appears in `entry.extensions` MUST obey the schema:
```json
{
  "oneOf": [
    {
      "title": "Literal",
      "type": "string",
    },
    {
      "title": "URL",
      "type": "object",
      "properties": {
        "url": {
          "type": "string",
          "maxLength": 255,
        }
      }
    }
  ]
}
```
If a URL is used, its response MUST have the MIME type `application/octet-stream`. The hash of a value is given by either the SHA256 hash of the string, encoded as UTF-8, in the case it is a literal, or the SHA256 hash of the octet stream, in the case it is a URL.

## Inclusion endpoint

The URL given in the `inclusion` field in the `WAICT-Transparency` header returns the entry (containing the resource hash), a proof showing that that entry is in the prefix tree, and a signed prefix tree root. Concretely, the response is an `application/octet-stream` containing a serialized `WaictInclusionProof`:
```
struct {
  EntryWithCtx entry;
  PrefixProof inc_proof;
  uint8 signed_prefix_root<1..2^24>;
} WaictInclusionProof;
```
where `signed_prefix_root` is a signed note of the form described above.

## Verifying Inclusion

The client must verify all pieces of data that are committed to by the tree. This includes the integrity policy and the extensions.

### Verifying a Resource

To verify a given resource on site domain `$sdomain`, the user

1. Computes the resource hash `rh` and checks that it equals `entry.resource_hash`.
1. Parses `signed_prefix_root` and extracts the root hash.
1. Verifies `inc_proof` with respect to the key `$sdomain`, value `entry`, and the parsed prefix root.
1. Checks that the domain in the first line in `signed_prefix_root` (everything before the first `/`) matches the domain of the site being accessed.
1. Verifies the cosignatures on `signed_prefix_root`. The client MAY choose the set of public keys that it trusts for this verification step.

### Verifying extensions

To verify a single extension, given its key and value hash, the user:

1. Checks that the given key and value hash appear in `leaf.extensions`
1. Verifies `inc_proof` and signatures as above

# Signaling Transparency to the User

Transparency can be enabled by a site two different ways. One easy to revert and one hard to revert.

## Header Signaling

A site can enable transparency via the `WAICT-Transparency` header described above. The `expires` field tells the client to expect transparency information from the website until the provided time (exclusive). The client MAY then behave as if transparency were enabled.

## Transparency service signaling

Mere presence in the transparency service map does not imply that a website has transparency enabled for all users. To enable it for all users until the expiry of the entry, the `enforce` flag must be set to `true`.

A site can opt into this stronger enforcement by following the enrollment procedure with `enforce` set to `true`. A transparency service MUST NOT permit `enforce` to be reverted to `false`. If a site operator wishes to disable `enforce`, they must first unenroll.
