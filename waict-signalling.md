# WAICT Enforcement Signaling

# Introduction

This spec describes the ways a server signals to a client to enforce the use of WAICT.

# Conventions

This document uses Structured Field Values for HTTP (RFC 8941).

# Client-side Signalling

Clients SHOULD signal that they support WAICT. Doing so will allow the server to avoid sending unnecessary information to the client.

To signal WAICT support, the client includes the structured request header `WAICT-Supported` which is an `sf-list` of `sf-integers` in their requests to the site.

Each integer defines a version of WAICT supported by the client. The version defined by this document is `1`.

Future versions of this specification may define different version numbers.

TODO: More idiomatic way to do this? User-Agent Capabilities?

# Server-side Signalling

Sites wanting clients to benefit from the security guarentees SHOULD signal to the client to enforce the use of WAICT via a HTTP Header attached to their responses..

## Header Format

This takes the form of a structured header named `WAICT` with the field value Dictionary. The following key-values MUST be present.

* `version` an `sf-integer`. If the value is not `1` this header must be ignored.
* `max-age` a `sf-integer` which must be `>= 0`.
* `preload` a `sf-boolean`.
* `mode` a `sf-token` containing either `audit` or `enforce`.

Any other keys MUST be ignored. Servers may set additional keys prefixed `GREASE` which clients MUST ignore. If one or more of these keys is missing or invalid, the entire header MUST be ignored.

## Semantics

Note to self: Manifest can't be configurable for WAICT.

The `version` field is used for negotiation. The only defined value is `1`. Future standards may define alternative values.

The `max-age` field indicates how long the client should cache this header for in seconds.

The `preload` field indicates whether the server wishes for client vendors to provision clients in advance with this signal. Guidance for this field is laid out in Section X.X.

The `mode` field indicates the type of enforcement that the client should enact.

## Client Behavior

Upon parsing a valid `WAICT` header, the client SHOULD store the `mode` against the `origin` for at most `max-age` seconds.

There may be situations in which clients are unable to store this record. For example, clients may not have access to long term state (e.g. they are running a private browsing mode). Such clients SHOULD store the record for as long as they are able.

If the client uses partitioned storage by origin and this header is set on a third party domain, the client SHOULD NOT store it. WAICT is only effective in a first-party context.

A client encountering a WAICT record for an origin MUST treat all previously cached respones for that origin as stale.

TODO: Guidance around handling requests made in parallel or concurrently to discovering a header.

When a client has a stored WAICT record for an origin, the client MUST check that each response is valid according to the provided WAICT manifest and transparency proof (see spec TODO).

If any response is invalid, as described in spec TODO, the client follow the enforcement requirements laid out below.

### Audit

Audit mode is intended for web developers to validate their deployment. It does not provide security for clients.

To that end, compliant clients MUST display appropriate error messages in their console, developer tools or other messaging surfaces intended for expert users.

Compliant clients MUST still load the resource correctly.

Compliant clients MUST NOT display error messages to end-users who are not experts or have not otherwise indicated they wish to see additional technical information.

If the server has indicated support for the Reporting API (https://developer.mozilla.org/en-US/docs/Web/API/Reporting_API), the client SHOULD report the WAICT report error with the following structure:

TODO

### Enforce

Enforce mode is intended to provide security for clients.

The behavior of Enforce mode varies dependning on whether the error is localised to a subresource.

If the error is localised to a sub resource (e.g. the main page can be loaded, the WAICT manifest can be loaded and is transparent) then the client MUST NOT process that resource.

Otherwise, the client MUST display a warning page describing that a WAICT error has occurred. The client SHOULD NOT allow the user to bypass the error page.

## Preloading

Sites can signal their desire for client vendors to preload WAICT status onto their devices. As a general rule, sites SHOULD NOT preload WAICT status. Preloading WAICT may lead to irrecovable errors. However, some sites with particular threat models MAY preload.

The details of how client vendors are alerted to this are vendor-specific, but sites wishing to enable preloading MUST:

* Set mode to enforce.
* Set preload to 1
* Set max-age to a value greater than 1 year.

Client vendors may configure clients with preload information via their client-specific out of band channels. Such clients should enforce WAICT as long as their vendor-supplied preload list is up to date.

Vendors may choose different cutoffs for when they cosndier a preload list to be stale, but are RECOMMENDED to use a value of 30 days. That is, if a client goes 30 days without recieving an updated preload list, it should stop enforcing entries on the preload list.

## Server Operator Advice

* Be careful. You can kill your website.
* Audit only. Every audit failure would be a broken client.
* Switch to enforce when confident.
* Gradual Rollout. Consider selective roll out e.g. to a specific locale.
* Short lifetime. Raise it periodically.
* Preload only if extremely confident and committed.
* Disable by stopping serving the header. Serve the transparent opt-out.

# Security Considerations

* Enforce provides security, audit doesn't.
* TOFU vs Preload.