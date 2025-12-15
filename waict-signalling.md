# WAICT Enforcement Signaling

# Introduction

This spec describes the ways a server signals to a client to enforce the use of WAICT.

# Conventions

This document uses Structured Field Values for HTTP ([RFC 9651](https://www.rfc-editor.org/rfc/rfc9651)) such as `sf-list` and `sf-integer`.

In this document, `origin` refers to the tuple (scheme, host, port) as defined in [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454).

# Advertising WAICT Support

Clients SHOULD signal that they support WAICT to the server through the use of user-agent client hints. Doing so will allow the server to avoid sending unnecessary information to clients which don't support WAICT.

To signal WAICT support, the [user agent client hint](https://wicg.github.io/ua-client-hints/) `Sec-CH-WAICT` is used whose value is a `sf-list` of `sf-integers`. Each integer represents a supported version of WAICT. This specification defines version `1`. If clients include a `Sec-CH-WAICT` header in their requests, the included version numbers MUST be supported by the client.

Servers supporting WAICT SHOULD actively solicit client hints for WAICT by including `Sec-CH-WAICT` in their `Accept-CH` response header (See [Section 3.1 of RFC 8942](https://www.rfc-editor.org/rfc/rfc8942#section-3.1)). Servers MUST tolerate unknown integers in the `Sec-CH-WAICT` request header.

For example, a client that supports versions 1 and 2 of WAICT might send:

`Sec-CH-WAICT: 1, 2`

# Enforcing the use of WAICT

Sites wanting clients to benefit from the security guarantees of WAICT SHOULD signal to supporting clients to enforce its use using the response header defined in this section.

## Header Format

This takes the form of a structured response header named `Sec-WAICT-v1-Enforce` with a field value of type Dictionary. The following key-value pairs MUST be present.

* `max-age` a `sf-integer` that MUST be `>= 0`.
* `preload` an `sf-boolean`.
* `mode` an `sf-token` containing either `audit` or `enforce`.

Any other keys MUST be ignored. If one or more of these keys is missing or invalid, the entire header MUST be ignored. Servers MAY set additional keys prefixed `GREASE-` which clients MUST ignore.

## Semantics

The `max-age` field indicates how long the client should cache this header for in seconds.

The `preload` field indicates whether the server wishes for client vendors to provision clients in advance with this signal. Guidance for this field is laid out in the [Preloading](#preloading) section.

The `mode` field indicates how clients should enforce WAICT for this origin.

For example, a site that wishes to enable enforcement with preloading and a `max-age` of one year could send:

`Sec-WAICT-v1-Enforce: max-age=31536000, mode="enforce", preload=?1`

## Client Behavior

When an origin is using WAICT, all requests made with a matching [top-level navigation initiator origin](https://fetch.spec.whatwg.org/#ref-for-request-top-level-navigation-initiator-origin) will be impacted by the WAICT security policy.


When processing a response to same-origin request (that is the request's origin matches its top-level navigation initiator origin) clients MUST check for valid WAICT enforcement response headers and SHOULD store the WAICT `mode` for this origin for at most `max-age` seconds from the present.

However, WAICT does not impact requests made to a WAICT-enforcing domain in other top-level contexts if those top level-contexts do not advertise WAICT themselves. Clients MUST ignore WAICT headers set on responses whose origin does not match their current top-level navigation initiator origin. An example:

* `foo.com` and `bar.com` both embed resources located on each others domains
* `foo.com` uses WAICT and sets an enforcement header. `bar.com` does not use WAICT.
* Clients which navigate to pages on `foo.com` will enforce WAICT on sub-resource requests, including those for `bar.com`.
* Clients which navigate to `bar.com` will not enforce WAICT, even when loading sub-resources from `foo.com`.

There may be situations in which clients are unable to store the WAICT enforcement mode. For example, clients may not have access to long-term state (e.g. they are running in a private browsing mode). Such clients SHOULD store the record for as long as they are able.

A client encountering a WAICT enforcement header for an origin for the first time MUST treat all previously cached responses for that origin as stale.

If the client had a previously stored WAICT record for an origin, it will overwrite it with the new configuration if:

* The new record is mode `enforce` and the previous record was mode `audit`, or
* The new record and old record indicate the same mode and the new record's expiry time (`max-age` seconds from the present) is further in the future.

When a client has a stored and unexpired WAICT record for an origin, the client MUST check that each response is valid according to the provided WAICT manifest and transparency proof (see [the proof specification](waict-proofs.md)). If a response is invalid then the client MUST follow the enforcement requirements laid out below.

### Audit

Audit mode is intended for web developers to validate their deployment. It does not provide security for clients.

To that end, compliant clients MUST display appropriate error messages in their console, developer tools or other messaging surfaces intended for expert users.

Compliant clients MUST still load the resource correctly.

Compliant clients MUST NOT display error messages to end-users who are not experts or have not otherwise indicated they wish to see additional technical information.

If the server has indicated support for the [Reporting API](https://developer.mozilla.org/en-US/docs/Web/API/Reporting_API), the client SHOULD report the WAICT error as a `waict-violation`. The corresponding `body` property includes the keys and values from [integrity-violations](https://developer.mozilla.org/en-US/docs/Web/API/IntegrityViolationReportBody), additionally enriched with an additional entry `reason`, an `sf-string` indicating the reason for the failure as described below.

- `manifest_unavailable` - The manifest for the origin could not be loaded.
- `no_transparency_proof` - The manifest was loaded, but no transparency proof was provided.
- `invalid_transparency_proof` - A manifest and transparency proof were provided, but it could not be parsed.
- `untrusted_transparency_proof` - A manifest and transparency proof were provided, but it could not be authenticated.
- `missing_from_manifest` - A valid manifest was available, but this resource was not covered.
- `no_manifest_match` - A valid manifest was available and described this resource, but the resource didn't match the manifest entry.

### Enforce

Enforce mode is intended to provide security for clients.

The behavior of Enforce mode varies depending on whether the error is localized to a sub-resource.

If the error is localized to a subresource (e.g. the main page can be loaded, the WAICT manifest can be loaded and has a valid transparency proof) then the client MUST NOT process that resource.

Otherwise, the client MUST display a warning page describing that a WAICT error has occurred. The client SHOULD NOT allow the user to bypass the error page.

The client SHOULD also report the error as described for `audit` mode.

## Preloading

Websites can signal their desire for client vendors to preload WAICT status onto their clients. As a general rule, websites SHOULD NOT preload WAICT status. Preloading WAICT may lead to irrecoverable errors. However, some websites with particular threat models MAY preload.

The details of how client vendors are alerted to this are vendor-specific, but websites wishing client vendors to preload MUST use a WAICT enforcement header with:

* `mode` set to `enforce`.
* `preload` set to `1`
* `max-age` set to a value greater than or equal to 1 year (`31536000` seconds).

Client vendors may configure clients with preload information via their client-specific out-of-band channels. Such clients should enforce WAICT as long as their vendor-supplied preload list is up to date.

Vendors may choose different cutoffs for when they consider a preload list to be stale, but are RECOMMENDED to use a value of 30 days. That is, if a client goes 30 days without receiving an updated preload list, it should stop enforcing entries on the preload list.

## Server Operator Advice (Non-Normative)

Server operators should be cautious when deploying WAICT enforcement. In general, there is no recourse for a faulty deployment in `enforce` mode, other than waiting out the `max-age` period. In the event of a faulty deployment and the use of `preload`, the waiting-out period is potentially unbounded.

Server operators are recommended to deploy WAICT in `audit` mode initially and gain confidence in their deployment gradually. Server operators should treat reported errors seriously. Every reported error will result in a broken client if `enforce` is enabled.

Once a server operator has become confident in their use of `audit` mode, they should consider switching to `enforce` mode with a low `max-age`, e.g. on the order of minutes. As time passes, server operators should consider raising the `max-age`.

The exact age that server operators settle on is a tradeoff between the maximum recovery time for their site and how often users are expected to visit their site and still need a security benefit.

The use of preload is a specialist feature which is unlikely to be suitable for the majority of sites using WAICT. Sites should only enable preload if they are committed to making their site unavailable when WAICT is unavailable.

Sites wishing to stop using WAICT should stop serving the enforcement header and wait out their previously set `max-age`. Sites may be able to unenroll through the use of the opt-out signal described in the [proofs specification](waict-proofs.md).

# Security Considerations

The use of this header is essential for the overall security of WAICT. Clients must be aware of the need to enforce WAICT in order to gain security benefits from it.

Clients only gain a security benefit from the use of `enforce` mode. Clients do not gain a security benefit from the use of `audit` mode.

When used without `preload`, clients only get a security benefit once they have visited the website and seen the enforcement header. This security benefit is only retained if their next visit to the website falls within the `max-age` window.

Using the `preload` functionality allows clients to benefit from the security of `WAICT` from their first visit and for as long as either the website is serving the WAICT header or the client is receiving updates to its preload list.

# Appendix: Design Decisions

This design emulates that of RFC 6797 (HSTS).

A key constraint is that client vendors typically cannot ensure that their clients have consistent or non-stale configurations. Further, connection failures to valid websites for stale clients are intolerable to website operators.

As a consequence, this design ensures that websites continue to maintain availability if a client has stale data (enforced via the `max-age` signals on headers and preload lists). This also means that security is only available for non-stale clients.
