# WAICT Transparency Signaling

# Introduction

This spec describes the ways a client signals to a server that they support WAICT, and vice-versa.

# Client-side Signalling

Clients MAY signal that they support transparency. Doing so will allow the server to avoid sending unnecessary transparency information to the client. To signal transparency support, the client includes the request header `WAICT-Transparency-Supported: 1` in their requests to the site. Future versions of this specification may define different version numbers.

# Server-side Signalling

Sites MAY to signal to the client the parameters of its transparency guarantees.

## Time-bound Signaling

The server MAY signal when transparency expires and where to find the inclusion proof. This is done via a response header:
```
WAICT-Transparency: expires=<uint64>, inclusion=<str>
```
where the value of the `expires` field is Unix time in seconds, the value of `inclusion` is a base64url-encoded URL which, when GETted, returns an `application/octet-stream`-encoded `EntryAndProof`. (TODO: add an option to embed inclusion into the header if it's short enough; also proof of non-inclusion or proof of tombstone inclusion to show that the site is unenrolled) (TODO: you don't need proof of non-inclusion if you just make sure your tombstone proof validity period is longer than the validity period of whatever is making the user believe transparency should be enabled)

Note: The inclusion proof depends on the manifest. To ensure that all data is coherent, the URLs SHOULD include some component that is unique to the site version, e.g., the current site history hash, or the integrity policy hash.

## Time-independent Signaling

A site MAY enable transparency in a way that expires much further in the future, and has stronger first-use guarantees. We can define a **transparency preload list**, a list of sites that are preloaded on the browser. If a site is on the transparency preload list then the client will enforce that it receives transparency information from the site, unless the site can prove that it has unenrolled since that preload list was constructed.

In this setting, browser vendors maintain the transparency preload list, and MUST keep the invariant that any site on the preload list stays there until it is unenrolled (either intentionally or by pruning). Further, the preload list must itself be transparent.

# Signalling Extensions

Sites might wish to enroll in more than just transparency. As an example, a site may wish to support Sigstore-based code signing, and have developer OpenID identifiers as extensions. A cooldown period on this extension would guarantee that, if a site changes developer IDs, it must wait, e.g., 24 hours for the change to go into effect. Further, since the manifest extensions are themselves transparent, a site can use a simple script to monitor for extension changes and notify the maintainer if an unexpected change happens.

## Preload Dictionary

(TODO: This idea is very tentative. Kill this section if it is not feasible)

Clients have to know to expect the extension, otherwise a site can just delete the extension without cooldown. So any extension ecosystem will have to maintain its own preload list. Equivalently, the transparency preload list can associate every entry with a hash. A site includes (the hash of) all their enabled extensions in this **transparency preload dictionary**, to ensure clients enforce these extensions.

## Extension Endpoints

A site stores its extension list at  `/.well-known/waict-extension-list`. This endpoint has MIME type `application/octet-stream`. Its body is a `list`, defined below
```
COMMA ::= ','
tag ::= [a-z0-9.\-]{1..32}
emptyList ::= COMMA?
nonemptyList ::= tag | (COMMA | tag){0..256} | COMMA?
list ::= emptyList OR nonemptyList
```
In words, `list` is a comma-separated list (trailing comma permitted) of length at most 256 of `tag`s, each of which is a lowercase alphanumeric (plus dashes) nonempty string of length at most 32. Duplicate entries are permitted, they are just treated as if the entry appeared once. The extension list endpoint SHOULD be included in the site's integrity manifest, thus providing transparency for extensions.

`tag` values SHOULD be registered with IANA in order to avoid collision.

The endpoint `/.well-known/waict-extensions/` is where all extension-specific data lives. For a given extension tag `t`, all `t`-specific extension data SHOULD be stored with the path prefix `/.well-known/waict-extensions/<t>`. This way, if tags do not collide, their associated data will not collide either.
