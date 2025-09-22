# WAICT Webapp Transparency for the Browser

# Introduction

This document is a supplement to the [WAICT](https://docs.google.com/document/d/16-cvBkWYrKlZHXkWRFvKGEifdcMthUfv-LxIbg6bx2o/edit?tab=t.0#heading=h.hqduv7qhbp3k) specification. It proposes a set of use cases for web application transparency, some protocols that attempt to achieve this, and open problems which need to be resolved.

We note that this document does NOT make any assumption about the structure or functioning of web application integrity. We take as a given that there is a unique 32-byte sequence which uniquely identifies the set of assets that a website cares to protect (in practice, the hash of something(s)).

# Glossary

* A **Site** is a web-based service that exposes some functionality that people want to use. Examples include Facebook or Proton Mail. **A Site is identified by its origin**, i.e., the triple of scheme, domain, and port. An origin is precisely specified in [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454.html).
* A **manifest** is a file that commits to the content served by the site.
* A **User** is someone that wants to use a Site. We treat a User and their browser as one in the same in this document.
* The **Enrollment Server** is the service that a Site registers with to announce that they have enabled transparency. There is a single global Enrollment Server.
* The **Log Provider** is the entity that runs a Log. The Log Provider MAY be distinct from the entity that runs the Site. Depending on the Site, the Log Provider may be expected to have high uptime. **A Log Provider is identified by its domain.**
* The **Asset Host** is a party chosen by a site to be responsible for storing the larger assets associated with transparency. This includes the integrity manifest, asset pointer file, and assets themselves.
* A **Witness** ensures that the Enrollment Dictionary is well-behaved, i.e., only makes updates that are allowed by the specification. It receives the new dictionary root and a proof of correct transition. On success, the witness signs the new root.

Finally, the **WAICT integrity policy headers** are the Site's Content Security Policy (CSP) headers that pertain to WAICT integrity. These headers contain the manifest hash as well as information on what types of assets will have integrity enforced (HTML, scripts, images, etc.), and what level of enforcement they are subject to (check-before-run, check-while-run, etc.).

## Notation

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119](https://www.rfc-editor.org/rfc/rfc2119) [RFC8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they appear in all capitals, as shown here.

We use `||` to denote concatenation of bytestrings.

# Construction overview

(TODO: fill in)

(TODO: Include rough estimates for Log storage requirements (and witness if required))

# The Enrollment Dictionary

The top-level data structure for transparency is the Enrollment Dictionary. This is a [KT Prefix Tree](https://www.ietf.org/archive/id/draft-keytrans-mcmillion-protocol-02.html#name-prefix-tree), i.e., a tree where each leaf's position is determined by its _key_, and the contents of the leaf is that key's _value_.

The Enrollment Dictionary is a KT Prefix Tree where the keys are the domains of the websites enrolling in transparency, and the values are of the form:
```
struct {
    u8 epoch_created[32],
    u8 site_hist_hash[32],
    int site_hist_size,
    u8 asset_host_url[256],
    int expiry,
    bool enforce,
    Extension extensions[16],
} Entry;

struct {
  u8 key[16],
  u8 value_hash[32],
} Extension
```
(TODO: add expiry and hard-enable)
That is, each leaf stores a hash representing the full history of the site at the given domain, as well as a URL to an asset host that can return. It also marks the time of creation by storing in `epoch_created` the hash of the prefix tree root preceding this one.

## Witness API

A witness is a stateful signer. It maintains a full copy of the prefix tree that it is witnessing the evolution of. Whenever it gets a signature request, it checks that the tree evolved faithfully, then signs the root.

### Request signature

The enrollment dictionary requests a signature on an updated prefix tree via `POST $witness/req-sig`. The body contains two components:

1. Every new prefix tree entry
1. The signed root

Concretely, the payload is an `application/octet-stream` with the structure
```
struct {
    u8 key[32],
    Entry value,
    u8 added_item_hash[32],
} Leaf;

struct Tombstone {
    u8 key[32],
}

enum LeafOrTombstone {
    Leaf leaf,
    Tombstone tombstone,
}

struct {
    LeafOrTombstone updated_leaves[1..2^16],
    u8 note[1..2^24],
} SigReq
```
where `updated_leaves` does not have any duplicate keys, and `note` is a _signed note_ per the [C2SP signed note standard](https://github.com/C2SP/C2SP/blob/main/signed-note.md), signed by the enrollment server with timestamped Ed25519. The text of the signed note is
```
$enrollment_dict_domain/waict-v1/prefix-tree
<base64_root>
```
To validate, the witness:

1. Checks that `updated_leaves` has no duplicates`
1. Loads the last known prefix tree state belonging to the enrollment dictionary
1. Updates all leaves according to `updated_leaves`. The witness:
    1. For each `key`, computes the new chain hash `ch` from `added_item_hash`. If it is not a tombstone, it
        1. Ensures `ch` equals the entry's `site_hist_hash`
        1. Ensures `enforce` only moves from false to true, or false to false
        1. Ensures `site_hist_size` increases by 1 (TODO: should we permit proofs where a site adds more than one entry?)
        1. Ensures `epoch_created` is unchanged
        1. Ensures `expiry` is in the future, and not too far in the future
    1. If the leaf is a tombstone, it deletes the leaf
1. Recomputes the prefix tree root
1. Verifies the enrollment dictionary's signature on the updated prefix root, aborting on failure
1. Adds its own signature to the signed note
1. Updates its copy of the prefix tree
1. Returns the new signed note

Note: if an enrollment dictionary becomes unable to produce new proofs, it will be impossible for it to get new signatures. So in the case of data loss or intentional tampering, an enrollment dictionary is forced to negotiate with witnesses to have them accept a new tree.

(TODO: any other endpoint a witness should provide? registration should probably be with a human in the loop)

## Enrollment Dictionary API

### Enroll

To enroll, a site first exposes an HTTPS endpoint `https://$domain/.well-known/waict-enroll` with MIME type `application/json` with the schema (TODO: should history size be in here too?):
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
    "initial_site_hist_hash": {
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
      "$coment": "Whether this site has transparency enforced by all clients (until the expiry)."
    },
    "expiry": {
      "type": "integer",
      "minimum": 0,
      "$coment": "The time, in Unix seconds, that this enrollment expires"
    },
    "extensions": {
      "type": "array",
      "maxItems": 32,
      "items": { "$ref": "#/$defs/extensionItem" },
      "$comment": "Extensions of the form key -> value"
    }
  },
  "required": [ "asset_host", "initial_site_hist_hash", "expiry" ],
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
  "initial_site_hist_hash": "",
  "initial_site_hist_size": 0,
  "expiry": 0,
  "enforce": false
}
```

The site then invokes a GET query on `https://$enrollment_dict/enroll` with GET parameter `site` set to the base64url encoding of `https://$domain`.

The enrollment dictionary fetches the file. If the enrollment dictionary does not already have the domain, it:

1 Creates a leaf with prefix given by `$domain`
1. Sets the value of the leaf equal to an `Entry`, with `site_hist_hash`, `site_hist_size`, `asset_host_url`, `expiry`, and `enforce` equal to the given values, and with all extension keys set to the given keys, and `value_hash` set to `SHA256(value)` for each entry. It also sets the `time_created` value to the current time in Unix seconds.
1. Computes a new prefix root given the new leaf
1. Gets cosignatures on the prefix root
1. Computes an inclusion proof of the leaf in the new prefix tree
1. Returns a struct of the form
```
struct {
  u8 leaf_hash[32],
  u8 prefix_root[32],
  PrefixInclusionProof inc_proof,
  Signature sigs[16],
} WaictEnrollmentResponse
```
The enrollment dictionary MAY batch additions to the tree. Batch updates are discussed in TODO.

If the enrollment dictionary already has this domain, then it checks if the file is the special unenrollment form and deletes the corresponding leaf if so. If it is not the special unenrollment form, then the enrollment dictionary updates its `asset_host` and `expiry` fields with the provided ones. It also updates the `enforce` field with the provided one if the provided one is `true`. (TODO: and what about extensions? shouldn't updates in those be transparent?)

Note: the `time_created` value in a dictionary entry MUST NOT change for as long as that entry exists. The only time it may change is on deletion of that leaf.

# Site headers, proofs, and assets

In order to convey transparency information to the user, the site must tell it where to find transparency information. Recall from the WAICT spec that the site sends an `Integrity-Policy` header. In addition to this, we specify the transparency header:
```
WAICT-Transparency: expires=<time>, inclusion=<url>, extensions=<url>
```
where the value of the `expires` field is Unix time in seconds, the value of `inclusion` is a URL to a transparency inclusion proof, and `extensions` is a URL to the full list of extension values.

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
  u8 sibling_hash[32],
  Entry leaf,
  u8 prefix_root[32],
  PrefixInclusionProof inc_proof,
  Signature sigs[16],
} WaictInclusionProof
```
The endpoint responds to HTTP GET requests with the above serialized proof, using MIME type `application/octet-string`.

## Verifying inclusion

The client must verify all pieces of data that are committed to by the tree. This includes the integrity policy and the extensions.

### Verifying integrity policy

To verify the given integrity policy the user

1. Computes the policy hash `ph = SHA256(0x00 || policy)`
1. Computes the site history hash `sh = SHA256(0x01 || sibling_hash || ph)`.
1. Checks that `sh = entry.site_hist_hash`
1. Computes the leaf hash `lh = SHA256(0x03 || entry)`
1. Verifies `inc_proof` with respect to the key `$domain`, the value `lh`, and the root `prefix_root`.
1. Verifies the signatures `sigs` on `prefix_root`. The client MAY choose the public key set that it trusts for this verification step. (TODO: define the signature format. This should probably have keyID baked in like cosignatures)

### Verifying extensions

To verify a single extension, given its key and value hash, the user:

1. Checks that the given key and value hash appear in `leaf.extensions`
1. Computes `lh` and verifies `inc_proof` and signatures as above

# Data APIs

The enrollment dictionary hosts mostly hashes, but auditors need to be able to fetch the actual assets the site served. We now describe how an auditor does this. 

## Enrollment dictionary

The enrollment dictionary must provide a way of fetching entries. First, the auditor requests the `Entry` corresponding to `$domain` by performing an HTTP GET on `$enrollment_server/get-leaf?domain=$domain`. The server returns an `application/octet-stream` containing an `Entry` with an inclusion proof with the key equal to the given domain:
```
struct {
    Entry leaf,
    PrefixInclusion inc,
} GetLeafResp;
```

## Asset host

With the entry in hand, an auditor can make queries to the asset host URL given at `entry.asset_host_url`. The endpoints are:

All endpoints are immutable, so its caching headers SHOULD be long-lived.

### Chain tile

GET `$url/chain-tile/<N>[.p/<W>]`

`<N>` is the index of the _tile_ where each tile is 256 hashes of the hash chain. It MUST be a non-negative integer encoded into 3-digit path elements. All but the last path element MUST begin with an x. For example, index 1234067 will be encoded as `x001/x234/067`.

The `.p/<W>` suffix is only present for partial tiles, defined below. <W> is the width of the tile, a decimal ASCII integer between 1 and 255, with no additional leading zeroes.

The enrollment dictionary MUST store a tile of an enrolled dictionary for at least one year beyond the youngest entry in the tile. If the tile is partial, then the enrollment dictionary MUST NOT delete it until the site unenrolled.

An enrollment dictionary MAY prune sites for inactivity. That is, it MAY unenroll them after a year of no updates.

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

## Enrollment dictionary signaling

Mere presence in the enrollment dictionary does not imply that a website has transparency enabled for all users. To enable it for all users until the expiry of the entry, the `enforce` flag must be set to `true`.

A site can opt into this stronger enforcement by following the enrollment procedure with `enforce` set to `true`. An enrollment dictionary MUST NOT permit `enforce` to be reverted to `false`. If a site operator wishes to disable `enforce`, they must first unenroll.

## Serving the inclusion data

After the presence of transparency is signalled, the user has to verify the transparency. The manifest bundle contains a base64 encoding of the inclusion of the manifest hash into the prefix tree, followed by a signed note of the prefix root. Concrtely, this is:
```
struct {
    PrefixInclusion inc,
    u8 signed_note[1..2^24]
} TProof
```

# Monitoring a Site

A site MAY monitor its entry in an enrollment dictionary by querying `get-leaf`. If its `epoch_created` is unchanged from the last check, then the monitor knows the domain was not unenrolled since last check. The monitor can then also check if the history size increased since the last check.
