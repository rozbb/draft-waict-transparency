# WAICT Webapp Transparency for the Browser

# Introduction

This document describes a transparency system for web resources. It enables clients fetching web resources, identified by a URL, to be assured that the received web resource has been publicly logged. It also enables website operators (and others) to enumerate the history of a web resource and observe when it changes.

The primary use case is [WAICT](https://docs.google.com/document/d/16-cvBkWYrKlZHXkWRFvKGEifdcMthUfv-LxIbg6bx2o/edit?tab=t.0#heading=h.hqduv7qhbp3k), Web Application Integrity, Consistency and Transparency, which aims to bring stronger transparency and integrity properties to applications delivered over the web in order to support properties like end-to-end encrypted messaging.

# Glossary

* A **Site** is a web-based service that exposes some functionality that people want to use. Examples include Facebook or Proton Mail. **A Site is identified by its origin**, i.e., the triple of scheme, domain, and port. An origin is precisely specified in [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454.html).
* A **Web Resource** is a file identified by a URL whose contents are committed to by a cryptographic hash.
* A **User** is someone that wants to use a Site. We treat a User and their browser as one in the same in this document.
* The **Asset Host** is a party chosen by a site to be responsible for storing the larger assets associated with transparency. This includes the integrity manifest, asset pointer file, and assets themselves.
* A **Transparency Service** is a service that a Site registers with to announce that they have enabled transparency and will log web resources to.
* A **Witness** ensures that a Transparency Service is well-behaved, i.e., only makes updates that are allowed by the specification. It receives the new dictionary root and a proof of correct transition. On success, the witness signs the new root.


## Notation and dependencies

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119](https://www.rfc-editor.org/rfc/rfc2119) [RFC8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they appear in all capitals, as shown here.

We use `||` to denote concatenation of bytestrings.

We use the Prefix Tree data structure from the [key transparency draft specification](https://www.ietf.org/archive/id/draft-keytrans-mcmillion-protocol-02.html#name-prefix-tree). We also use the `PrefixProof` structure for proofs of inclusion and non-inclusion, as well as the structure's associated verification algorithm.

We use the Signed Note data structure from the [C2SP signed note standard](https://github.com/C2SP/C2SP/blob/main/signed-note.md). We use the term "cosignature" as in the standard, to refer to a signature on a signed note.

We use the JSON Schema langauge from the [JSON Schema standard](https://json-schema.org/draft/2020-12/json-schema-core) to specify the structure of JSON objects. We also use the associated [validation standard](https://json-schema.org/draft/2020-12/json-schema-validation#section-6.3) for additional keywords such as `maxLength` or `pattern`.

We use the base64 encoding algorithms described in [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html). Specifically we use the standard "base64" encoding and the URL-safe "base64url" encoding.

# Construction overview

(TODO: fill in)

(TODO: Include rough estimates for Log storage requirements (and witness if required))

# The Transparency Service

The top-level data structure for transparency is the Transparency Service. This is a , i.e., a tree where each leaf's position is determined by its _key_, and the contents of the leaf is that key's _value_.

The Transparency Service is a prefix tree where the keys are the domains of the websites enrolling in transparency, and the values are of the form:
```
struct {
  uint8 key[16],
  uint8 value_hash[32],
} Extension;

struct {
    uint8 epoch_created[32];
    uint8 resource_hash[32];
    uint64 site_hist_size;
    uint8 asset_host_url<1..2^8-1>;
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
That is, each leaf stores a hash representing the full history of the site at the given domain, as well as a URL to an asset host that can return. It also marks the time of creation by storing in `epoch_created` the hash of the prefix tree root preceding this one. (TODO: make Entry an enum that can also be a tombstone)

## Transparency Service API

### Enrollment via HTTPS

To enroll via HTTPS, a site first exposes an HTTPS endpoint `https://$domain/.well-known/waict-enroll` containing all the information the transparency service needs to

with MIME type `application/json` with the schema (TODO: should history size be in here too? what is the initial chain hash for?):
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
    "initial_site_hist_size": {
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
To request unenrollment, the site serves
```json
{
  "asset_host": "",
  "initial_chain_hash": "",
  "initial_site_hist_size": 0,
  "expiry": 0,
  "enforce": false
}
```

The site then invokes a GET query on `https://$transparency_service_domain/enroll` with GET parameter `site` set to the base64url encoding of `https://$domain`.

The transparency service fetches the file. If the transparency service does not already have the domain, it:

1 Creates a leaf with prefix given by `$domain`
1. Sets the value of the leaf equal to an `EntryWithCtx`, with `chain_hash`, `site_hist_size`, `asset_host_url`, `expiry`, and `enforce` equal to the given values, and with all extension keys set to the given keys, and `value_hash` set to `SHA256(0x04 || value)` for each entry. It also sets the `epoch_created` value to the current prefix tree root. (TODO: settle on epoch-created vs time-created)
1. Computes a new prefix root given the new leaf
1. Gets cosignatures on the prefix root
1. Computes an inclusion proof of the leaf in the new prefix tree
1. Returns a struct of the form
```
struct {
  EntryWithCtxt entry;
  PrefixProof inc_proof;
  uint8 signed_prefix<1..2^24-1>;
} WaictEnrollmentResponse
```
where `signed_prefix` is a signed note.

(TODO: consider how to deal with longer latency on enrollments. Should you get a timestamp for when the next epoch lands, or should your connection just hang until it comes)

If the transparency service already has this domain, then it checks if the file is the special unenrollment form and deletes the corresponding leaf if so. If it is not the special unenrollment form, then the transparency service updates its `asset_host` and `expiry` fields with the provided ones. It also updates the `enforce` field with the provided one if the provided one is `true`. (TODO: and what about extensions? shouldn't updates in those be transparent?)

Note: the `epoch_created` value in a dictionary entry MUST NOT change for as long as that entry exists. The only time it may change is on deletion of that leaf.

### Append to chain

The `POST /append` endpoint takes a resource value and appends its hash to that leaf's chain. The transparency service hashes the new value into the chain and increments the chain size.

* Parameter `domain`: domain of resource to add or update
* Parameter `value`: base64-encoded value to append
* Authentication: Defined by the transparency service, e.g. a JWT. The transparency service MAY apply further policies or rate limits, e.g. requiring payment per resource logged.
* Return value: A `WaictInclusionProof`, described below

(TODO: this should maybe support arbitrary fast-forward, not just single item appends; note this has to be within reason bc of the linear proof size)

### Get Leaf

The transparency service must provide a way of fetching entries in the prefix tree. Any party can fetch this information via `GET $transparency_service_domain/get-leaf`

* Parameter `domain`: The domain of the site whose leaf is desired
* Return: A `WaictInclusionProof` for the given domain

### Update leaf metadata

(TODO: need to be able to update extensions, asset URLs, enforce, and also some way to bump expiry)

# Witness API

A witness is a stateful signer. It maintains a full copy of the prefix tree that it is witnessing the evolution of. Whenever it gets a signature request, it checks that the tree evolved faithfully, then signs the root.

## Request signature

The transparency service requests a signature on an updated prefix tree via `POST $witness/req-sig`. The body contains two components:

1. Every new prefix tree entry
1. The root as a signed note (variant 0x04, i.e., timestamped ed25519 witness cosignatures), signed with the transparency service's public key. The signed note text is of the form
```
$transparency_service_domain/waict-v1/prefix-tree
<base64_root>
```
(TODO: pick different ID than `waict`)

The request payload `SigReq` is encoded in an `application/octet-stream` with the structure:
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

To validate, the witness:

1. Checks that `new_entries` has no duplicates`
1. Loads the last known prefix tree state belonging to the transparency service
1. Updates all entries. For each element of `new_entries`, the witness:
    1. If it is not an `EntryDelete`,
        1. Ensures `enforce` only moves from false to true, or false to false
        1. Ensures `site_hist_size` increases by 1 (TODO: should we permit proofs where a site adds more than one entry?)
        1. Ensures `epoch_created` is unchanged
        1. Ensures `expiry` is in the future, and not too far in the future
        1. Computes the new chain hash of the entry using its stored old chain hash and the given entry's `resource_hash`.
    1. If it is an `EntryDelete`, sets the entry to a `TombstoneEntry` with the current epoch as `epoch_created`.
1. Computes the new prefix tree root using the given entries and computed chain hashes
1. Verifies the transparency service's signature on the updated prefix root, aborting on failure
1. Adds its own signature to the signed note
1. Updates its copy of the prefix tree
1. Returns the new signed note

Note: if a transparency service becomes unable to produce new proofs, it will be impossible for it to get new signatures. So in the case of data loss or intentional tampering, a transparency service is forced to negotiate with witnesses to have them accept a new tree.

(TODO: any other endpoint a witness should provide? registration should probably be with a human in the loop)

# Serving proofs to clients

Clients which support transparency information and expect to be served a proof SHOULD include the header `WAICT-Transparency-Supported: 1`. Future versions of this specification may define different version numbers.

In order to convey transparency information to the user, the site must tell it where to find transparency information. This is done via a response header:
```
WAICT-Transparency: expires=<time>, inclusion=<url>, extensions=<url>
```
where the value of the `expires` field is Unix time in seconds, the value of `inclusion` is a URL to a transparency inclusion proof, and `extensions` is a URL to the full list of extension values. (TODO: add an option to embed inclusion into the header if it's short enough) (TODO: also add an option to embed a non-inclusion proof in a newer tree so that you can convince clients you disabled transparency)

Note: The inclusion proof is dependent on the manifest and extensions. To ensure that all data is coherent, the URLs SHOULD include some component that is unique to the site version, e.g., the current site history hash, or the integrity policy hash.

## Extension endpoint

The URL given in the `extension` field in the `WAICT-Transparency` header returns a JSON object. If a key matches one of the keys in `leaf.extensions` served by the inclusion proof endpoint, then the value is either a string literal or a URL to the value. Concretely, every value whose key appears in `leaf.extensions` MUST obey the schema:
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
If a URL is used, its response MUST have the MIME type `application/octet-stream`. The hash of a value is given by either the hash of the string, encoded as UTF-8, in the case it is a literal, or the hash of the octet stream, in the case it is a URL.

## Inclusion endpoint

The URL given in the `inclusion` field in the `WAICT-Transparency` header returns a proof showing that the hash of the `Integrity-Policy` header is the latest value in the site history at the leaf given by the site's domain, followed by a proof that the leaf is included in a signed prefix tree. Concretely, the proof structure is as follows
```
struct {
  EntryWithCtxt entry;
  PrefixProof inc_proof;
  uint8 signed_prefix<1..2^24>;
} WaictInclusionProof;
```
where `signed_prefix_root` is a signed note of the form described above. The endpoint responds to HTTP GET requests with the above serialized proof, using MIME type `application/octet-string`.

## Verifying inclusion

The client must verify all pieces of data that are committed to by the tree. This includes the integrity policy and the extensions.

### Verifying integrity policy

To verify the given integrity policy the user

1. Computes the resource hash `rh = SHA256(0x00 || resource)`
1. Computes the site history hash `sh = SHA256(0x01 || sibling_hash || ph)`.
1. Checks that `ch = entry.chain_hash`
1. Computes the leaf hash `lh = SHA256(0x03 || entry)`
1. Verifies `inc_proof` with respect to the key `$domain`, the value `lh`, and the root `prefix_root`.
1. Parses `signed_prefix_root` and ensures the domain in the first line (everything before the first `/`) matches the domain of the site being accessed.
1. Verifies the signatures on `signed_prefix_root`. The client MAY choose the set of public keys that it trusts for this verification step.

### Verifying extensions

To verify a single extension, given its key and value hash, the user:

1. Checks that the given key and value hash appear in `leaf.extensions`
1. Computes `lh` and verifies `inc_proof` and signatures as above

# Data APIs

The transparency service hosts mostly hashes, but auditors need to be able to fetch the actual assets the site served. We now describe how an auditor does this.

## Asset host

With the entry in hand, an auditor can make queries to the asset host URL given at `entry.asset_host_url`. The endpoints are:

All endpoints are immutable, so its caching headers SHOULD be long-lived.

### Chain tile

GET `$url/chain-tile/<N>[.p/<W>]`

`<N>` is the index of the _tile_ where each tile is 256 hashes of the hash chain. It MUST be a non-negative integer encoded into 3-digit path elements. All but the last path element MUST begin with an x. For example, index 1234067 will be encoded as `x001/x234/067`.

The `.p/<W>` suffix is only present for partial tiles, defined below. <W> is the width of the tile, a decimal ASCII integer between 1 and 255, with no additional leading zeroes.

The transparency service MUST store a tile of an enrolled dictionary for at least one year beyond the youngest entry in the tile. If the tile is partial, then the transparency service MUST NOT delete it until the site unenrolled.

A transparency service MAY prune sites for inactivity. That is, it MAY unenroll them after a year of no updates.

### Manifest

GET `$url/manifest/<N>` returns an `application/octet-stream` containing the `N`-th manifest (0-indexed).

(TODO: should we batch manifests like tiles? they can get big)

### Asset pointer

An _asset pointer file_ is a JSON object that maps hashes to URLs where the hashes occur.
```json
{
"81db308d0df59b74d4a9bd25c546f25ec0fdb15a8d6d530c07a89344ae8eeb02": "https://s3.aws.com/blob1",
"fbd1d07879e672fd4557a2fa1bb2e435d88eac072f8903020a18672d5eddfb7c": "https://static.github.com/data.gif",
"5e737a67c38189a01f73040b06b4a0393b7ea71c86cf73744914bbb0cf0062eb": "ipfs://CQ+uzle90QIIKHy2bU62ciVlP++lSckhAn6XF1kxm70"
}
```
Concretely, an asset pointer file follows the schema
```json
{
  "title": "Asset Pointer",
  "type": "object",
  "properties": {
    "version": {
      "type": "integer"
    }
    "assets": {
      "type": "object",
      "patternProperties": {
        "^[a-z0-9]{64}$": {
          "type": "string"
        }
      }
    }
  }
}
```

GET `$url/asset-pointer/<N>` returns an `application/octet-stream` containing the asset pointer file associated with the `N`-th manifest (0-indexed).

(TODO: same batching question)

# Signaling transparency to the User

Transparency can be enabled two different ways. One easy to revert and one hard to revert.

## Header signaling

A site can enable transparency via the `WAICT-Transparency` header described above. The `expires` field tells the client to expect transparency information from the website until the provided time (exclusive). The client MAY then behave as if transparency were enabled, i.e., reading the `Integrity-Policy` header and so forth.

## Transparency service signaling

Mere presence in the transparency service dictionary does not imply that a website has transparency enabled for all users. To enable it for all users until the expiry of the entry, the `enforce` flag must be set to `true`.

A site can opt into this stronger enforcement by following the enrollment procedure with `enforce` set to `true`. A transparency service MUST NOT permit `enforce` to be reverted to `false`. If a site operator wishes to disable `enforce`, they must first unenroll.

## Serving the inclusion data

After the presence of transparency is signalled, the user has to verify the transparency. The manifest bundle contains a base64 encoding of the `WaictInclusionProof` of the given resource.
