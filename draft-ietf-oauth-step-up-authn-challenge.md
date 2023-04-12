%%%
title = "OAuth 2.0 Step-up Authentication Challenge Protocol"
abbrev = "OAuth Authn Challenge"
ipr = "trust200902"
area = "Security"
workgroup = "Web Authorization Protocol"
keyword = ["security", "oauth2", "openid connect", "oauth", "step-up"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-ietf-oauth-step-up-authn-challenge-latest"
stream = "IETF"
status = "standard"

[[author]]
initials="V."
surname="Bertocci"
fullname="Vittorio Bertocci"
organization="Auth0/Okta"
    [author.address]
    email = "vittorio@auth0.com"

[[author]]
initials="B."
surname="Campbell"
fullname="Brian Campbell"
organization="Ping Identity"
    [author.address]
    email = "bcampbell@pingidentity.com"


%%%

.# Abstract

It is not uncommon for resource servers to require different authentication strengths or recentness according to the characteristics of a request. This document introduces a mechanism for a resource server to signal to a client that the authentication event associated with the access token of the current request does not meet its authentication requirements and specify how to meet them.
This document also codifies a mechanism for a client to request that an authorization server achieve a specific authentication strength or recentness when processing an authorization request.

{mainmatter}

# Introduction {#Introduction}

In simple API authorization scenarios, an authorization server will determine what authentication technique to use to handle a given request on the basis of aspects such as the scopes requested, the resource, the identity of the client and other characteristics known at provisioning time.
Although the approach is viable in many situations, it falls short in several important circumstances. Consider, for instance, an eCommerce API requiring different authentication strengths depending on whether the item being purchased exceeds a certain threshold, dynamically estimated by the API itself using a logic that is opaque to the authorization server.
An API might also determine that  a more recent user authentication is required based on its own risk evaluation of the API request.

This document extends the error codes collection defined by [@!RFC6750] with a new value, `insufficient_user_authentication`, which can be used by resource servers to signal to the client that the authentication event associated with the access token presented with the request does not meet the authentication requirements of the resource server.
This document also introduces `acr_values` and `max_age` parameters for the `Bearer` authentication scheme challenge defined by [@!RFC6750], which the resource server can use to explicitly communicate to the client the required authentication strength or recentness.

The client can use that information to reach back to the authorization server with an authorization request specifying the authentication requirements indicated by protected resource, by including the `acr_values` or `max_age` authorization request parameters as defined in [@OIDC].

Those extensions will make it possible to implement interoperable step up authentication with minimal work from resource servers, clients and authorization servers.

## Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [@!RFC2119] [@!RFC8174]
when, and only when, they appear in all capitals, as shown here.

This specification uses the terms "access token", "authorization server", "authorization endpoint", "authorization request", "client", "protected resource", and "resource server" defined by The OAuth 2.0 Authorization Framework [@!RFC6749].

# Protocol Overview

The following is an end-to-end sequence of a typical step-up authentication scenario implemented according to this specification.
The scenario assumes that, before the sequence described below takes place, the client already obtained an access token for the protected resource.

!---
~~~
+----------+                                          +--------------+
|          |                                          |              |
|          |-----------(1) request ------------------>|              |
|          |                                          |              |
|          |<---------(2) challenge ------------------|   Resource   |
|          |                                          |    Server    |
|  Client  |                                          |              |
|          |-----------(5) request ------------------>|              |
|          |                                          |              |
|          |<-----(6) protected resource -------------|              |
|          |                                          +--------------+
|          |
|          |
|          |  +-------+                              +---------------+
|          |->|       |                              |               |
|          |  |       |--(3) authorization request-->|               |
|          |  | User  |                              |               |
|          |  | Agent |<-----------[...]------------>| Authorization |
|          |  |       |                              |     Server    |
|          |<-|       |                              |               |
|          |  +-------+                              |               |
|          |                                         |               |
|          |<-------- (4) access token --------------|               |
|          |                                         |               |
+----------+                                         +---------------+
~~~
!---
Figure: Abstract protocol flow {#abstract-flow}

1. The client requests a protected resource, presenting an access token.
2. The resource server determines that the circumstances in which the presented access token was obtained offer insufficient authentication strength and/or recentness, hence it denies the request and returns a challenge describing (using a combination of `acr_values` and `max_age`) what authentication requirements must be met for the resource server to authorize a request.
3. The client directs the user agent to the authorization server with an authorization request that includes the `acr_values` and/or `max_age` indicated by the resource server in the previous step.
4. After whatever sequence required by the grant of choice plays out, which will include the necessary steps to authenticate the user in accordance with the `acr_values` and/or `max_age` values of the authorization request, the authorization server returns a new access token to the client. The access token contains or references information about the authentication event.
5. The client repeats the request from step 1, presenting the newly obtained access token.
6. The resource server finds that the user authentication performed during the acquisition of the new access token complies with its requirements, and returns the representation of the requested protected resource.

The validation operations mentioned in step 2 and 6 imply that the resource server has a way of evaluating the authentication level by which the access token was obtained. This document will describe how the resource server can perform that determination when the access token is a JWT Access token [@RFC9068] or is validated via introspection [@RFC7662].
Other methods of determining the authentication level by which the access token was obtained are possible, per agreement by the authorization server and the protected resource, but are beyond the scope of this specification.

It is worthwhile to remark that the notion of "authentication level", as used in this document, represents an assessment the resource server performs on specific authentication methods, to arbitrarily determine whether it meets its own security criteria for the requested resource. "Authentication level" in this specification does not imply, requires nor refers to an absolute hierarchy of authentication methods expressed in interoperable fashion. The notion of level emerges from the fact that the resource server will accept some methods and reject others, hence establishing a way of comparing methods that meets the intuitive notion of "step up" .

Although the case in which the new access token supersedes old tokens by virtue of a higher authentication level is common, in line with the intuition the term "step-up authentication" suggests, it is important to keep in mind that this might not necessarily hold true in the general case. For example: a resource server might require for a particular request a higher authentication level and a shorter validity, resulting in a token suitable for one-off calls but leading to frequent prompts, hence a suboptimal user experience, if reused for routine operations. In those scenarios, the client would be better served by keeping both the old tokens, associated with a lower authentication level, and the new one - selecting the appropriate token for each API call. This is not a new requirement for clients, as incremental consent and least privilege principles will require similar heuristics for managing access tokens associated to different scopes and permission levels. This document does not recommend any specific token caching strategy, as that will be dependent on the characteristics of every particular scenario and remains application-dependent as in the core OAuth cases.
Also recall that OAuth 2.0 [@!RFC6749] assumes access tokens are treated as opaque by clients. The token format might be unreadable to the client or might change at any time to become unreadable. So, during the course of any token caching strategy, a client must not attempt to inspect the content of the access token to determine the associated authentication information or other details (see Section 6 of [@!RFC9068] for a more detailed discussion).

# Authentication Requirements Challenge {#Challenge}


This specification introduces a new error code value for the `error` parameter of the challenge of the `Bearer` authentication scheme from [@!RFC6750] and other OAuth authentication schemes, such as [@I-D.ietf-oauth-dpop], which use the same `error` parameter:

`insufficient_user_authentication`
:   The authentication event associated with the access token presented with the request does not meet the authentication requirements of the protected resource.

Note: the logic through which the resource server determines that the current request does not meet the authentication requirements of the protected resource, and associated functionality (such as expressing, deploying and publishing such requirements) is out of scope for this document.

Furthermore, this specification defines the following `WWW-Authenticate` auth-param values for those OAuth authentication schemes to convey the authentication requirements back to the client.

`acr_values`
:   A space-separated string listing the authentication context class reference values, in order of preference, one of which the protected resource requires for the authentication event associated with the access token. The authentication context, as defined in section 1.2 of [@OIDC] conveys information about how authentication takes place (e.g., what authentication method(s) or assurance level to meet).


`max_age`
:   Indicates the allowable elapsed time in seconds since the last active authentication event associated with the access token. An active authentication event entails a user interacting with the authorization server in response to an authentication prompt. Note that while the auth-param value can be conveyed as a token or quoted-string (see section 11.2 of [@RFC9110]), it has to represent a non-negative integer.

(#acr-challenge) below is an example of a `Bearer` authentication scheme challenge with the `WWW-Authenticate` header using the `insufficient_user_authentication` error code value to inform the client that the access token presented is not sufficient to gain access to the protected resource, and the `acr_values` parameter to let the client know that the expected authentication level corresponds to the authentication context class reference identified by `myACR`.

Note that while this specification only defines usage of the above auth-params with the `insufficient_user_authentication` error code, it does not preclude future specifications or profiles from defining their usage with other error codes.

!---
~~~
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication",
  error_description="A different authentication level is required",
  acr_values="myACR"
~~~
!---
Figure: Authentication Requirements Challenge indicating `acr_values` {#acr-challenge}

The following example in (#age-challenge) shows a challenge informing the client that last active authentication event associated with the presented access token is too old and a more recent authentication is needed.

!---
~~~
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication",
  error_description="More recent authentication is required",
  max_age="5"
~~~
!---
Figure: Authentication Requirements Challenge indicating `max_age` {#age-challenge}


The auth-params `max_age` and `acr_values` MAY both occur in the same challenge if the resource server needs to express requirements both about recency and authentication levels.
If the resource server determines that the request is also lacking the scopes required by the requested resource, it MAY include the `scope` attribute with the scope necessary to access the protected resource, as described in section 3.1 of [@!RFC6750].

# Authorization Request

A client receiving a challenge from the resource server carrying the error code `insufficient_user_authentication` SHOULD parse the `WWW-Authenticate` header for  `acr_values` and `max_age` and use them, if present, in constructing an authorization request, which is then conveyed to the authorization server's authorization endpoint via the user agent in order to obtain a new access token complying with the corresponding requirements.
Both `acr_values` and `max_age` authorization request parameters are OPTIONAL parameters defined in Section 3.1.2.1. of [@OIDC]. This document does not introduce any changes in the authorization server behavior defined in [@OIDC] for processing those parameters, hence any authorization server implementing OpenID Connect will be able to participate in the flow described here with little or no changes. See (#AuthzResp) for more details.

The example authorization request URI below, which might be used after receiving the challenge in (#acr-challenge), indicates to the authorization server that the client would like the authentication to occur according to the authentication context class reference identified by `myACR`.
!---
~~~
https://as.example.net/authorize?client_id=s6BhdRkqt3
&response_type=code&scope=purchase&acr_values=myACR
~~~
!---
Figure: Authorization Request indicating `acr_values`


After the challenge in (#age-challenge), a client might direct the user agent to the following example authorization request URI where the `max_age` parameter indicates to the authorization server that the user authentication event needs to have occurred no more than five seconds prior.
!---
~~~
https://as.example.net/authorize?client_id=s6BhdRkqt3
&response_type=code&scope=purchase&max_age=5
~~~
!---
Figure: Authorization Request indicating `max_age`

# Authorization Response {#AuthzResp}
Section 5.5.1.1 of [@OIDC]  establishes that an authorization server receiving a request containing the `acr_values` parameter MAY attempt to authenticate the user in a manner that satisfies the requested Authentication Context Class Reference, and include the corresponding value in the `acr` claim in the resulting ID Token. The same section also establishes that in case the desired authentication level cannot be met, the authorization server SHOULD include in the `acr` claim a value reflecting the authentication level of the current session (if any). Furthermore, Section 3.1.2.1 [@OIDC] states that if a request includes the `max_age` parameter, the authorization server MUST include the `auth_time` claim in the issued ID Token.
An authorization server complying with this specification will react to the presence of the `acr_values` and `max_age` parameters by including `acr` and `auth_time` in the access token (see (#authn-info-in-at) for details).
Although [@OIDC] leaves the authorization server free to decide how to handle the inclusion of `acr` in the ID Token when requested via `acr_values`, when it comes to access tokens in this specification, the authorization server SHOULD consider the requested acr value as necessary for successfully fulfilling the request. That is, the requested `acr` value is included in the access token if the authentication operation successfully met its requirements, or that the authorization request fails in all other cases, returning `unmet_authentication_requirements` as defined in [@OIDCUAR]. The recommended behavior will help prevent clients getting stuck in a loop where the authorization server keeps returning tokens that the resource server already identified as not meeting its requirements hence known to be rejected as well.

# Authentication Information Conveyed via Access Token {#authn-info-in-at}

To evaluate whether an access token meets the protected resource's requirements, the resource server needs a way of accessing information about the authentication event by which that access token was obtained. This specification provides guidance on how to convey that information in conjunction with two common access token validation methods: the one described in [@!RFC9068], where the access token is encoded in JWT format and verified via a set of validation rules, and the one described in [@!RFC7662], where the token is validated and decoded by sending it to an introspection endpoint.
Authorization servers and resource servers MAY elect to use other encoding and validation methods, however those are out of scope for this document.

## JWT Access Tokens

When access tokens are represented as JSON Web Tokens (JWT) [@RFC7519], the `auth_time` and `acr` claims (per Section 2.2.1 of [@!RFC9068]) are used to convey the time and context of the user authentication event that the authentication server performed during the course of obtaining the access token. It is useful to bear in mind that the values of those two parameters are established at user authentication time and will not change in the event of access token renewals. See the aforementioned Section 2.2.1 of [@!RFC9068] for details. The following is a conceptual example showing the decoded content of such a JWT access token.

!---
~~~
Header:

{"typ":"at+JWT","alg":"ES256","kid":"LTacESbw"}

Claims:

{
 "iss": "https://as.example.net",
 "sub": "someone@example.net",
 "aud": "https://rs.example.com",
 "exp": 1646343000,
 "iat": 1646340200,
 "jti" : "e1j3V_bKic8-LAEB_lccD0G",
 "client_id": "s6BhdRkqt3",
 "scope": "purchase",
 "auth_time": 1646340198,
 "acr": "myACR"
}
~~~
!---

## OAuth 2.0 Token Introspection {#introspect}

OAuth 2.0 Token Introspection [@!RFC7662] defines a method for a protected resource to query an authorization server about the active state of an access token as well as to determine metainformation about the token.
The following two top-level introspection response members are defined to convey information about the user authentication event that the authentication server performed during the course of obtaining the access token.

`acr`
:   Authentication Context Class Reference. String specifying an Authentication Context Class Reference value that identifies the Authentication Context Class that the user authentication performed satisfied.

`auth_time`
:   Time when the user authentication occurred. A JSON numeric value representing the number of seconds from 1970-01-01T00:00:00Z UTC until the time of date/time of the authentication event.

The following example shows an introspection response with information about the user authentication event by which the access token was obtained.

!---
~~~
HTTP/1.1 200 OK
Content-Type: application/json

{
  "active": true,
  "client_id": "s6BhdRkqt3",
  "scope": "purchase",
  "sub": "someone@example.net",
  "aud": "https://rs.example.com",
  "iss": "https://as.example.net",
  "exp": 1639528912,
  "iat": 1618354090,
  "auth_time": 1646340198,
  "acr": "myACR"
}
~~~
!---

# Authorization Server Metadata {#ASMetadata}

Authorization Servers can advertise their support of this specification by including in their metadata document (as defined in [@!RFC8414]) the value `acr_values_supported` as defined in section 3 of [@OIDCDISC]. The presence of `acr_values_supported` in the authorization server metadata document signals that the authorization server will understand and honor the `acr_values` and `max_age` parameters in incoming authorization requests.

# Deployment Considerations {#Deployment}

This specification facilitates the communication of requirements from a resource server to a client, which in turn can enable a smooth step-up authentication experience. However, it is important to realize that the user experience achievable in every specific deployment is a function of the policies each resource server and authorization server pairs establish. Imposing constraints on those policies is out of scope for this specification, hence it is perfectly possible for resource servers and authorization servers to impose requirements that are impossible for users to comply with, or leading to an undesirable user experience outcome.
The authentication prompts presented by the authorization server as a result of the method of propagating authentication requirements described here might require the user to perform some specific actions such as using multiple devices, having access to devices complying with specific security requirements, and so on. Those extra requirements, concerning more about how to comply with a particular requirement rather than indicating the identifier of the requirement itself, are out of scope for this specification.

# Security Considerations {#Security}

This specification adds to previously defined OAuth mechanisms.  Their respective Security Considerations apply - OAuth 2.0 [@RFC6749], JWT access tokens [@RFC9068], Bearer WWW-Authentication [@!RFC6750], token introspection [@RFC7662], and authorization server metadata [@RFC8414].

This document MUST NOT be used to position OAuth as an authentication protocol. For the purposes of this specification, the way in which a user authenticated with the authorization server to obtain an access token is salient information, as a resource server might decide whether to grant access on the basis of how that authentication operation was performed. Nonetheless, this specification does not attempt to define the mechanics by which authentication takes place, relying on a separate authentication layer to take care of the details. In line with other specifications of the OAuth family, this document assumes the existence of a session without going into the details of how it is established or maintained, what protocols are used to implement that layer (e.g., OpenID Connect), and so forth.
Depending on the policies adopted by the resource server, the `acr_values` parameter introduced in (#Challenge) might unintentionally disclose information about the authenticated user, the resource itself, the authorization server, and any other context-specific data that an attacker might use to gain knowledge about their target.
For example, a resource server requesting an acr value corresponding to a high level of assurance for some users but not others might identify possible high privilege users to target with spearhead phishing attacks.
Implementers should use care in determining what to disclose in the challenge and in what circumstances.
The logic examining the incoming access token to determine whether a challenge should be returned can execute either before or after the conventional token validation logic, be it based on JWT token validation, introspection, or any other method. The resource server MAY return a challenge without verifying the client presented a valid token. However, this approach will leak the required properties of an authorization token to an actor who has not proven they can obtain a token for this resource server.

As this specification provides a mechanism for the resource server to trigger user interaction, it's important for the authorization server and clients to consider that a malicious resource server might abuse of that feature.

# IANA Considerations {#IANA}

##  OAuth Extensions Error Registration

This specification requests registration of the following error value in the "OAuth Extensions Error" registry [@IANA.OAuth.Params] established by [@!RFC6749].

* Name: `insufficient_user_authentication`
* Usage Location: resource access error response
* Protocol Extension: OAuth 2.0 Step-up Authentication Challenge Protocol
* Change controller: IETF
* Specification document(s): (#Challenge) of [[ this specification ]]


## OAuth Token Introspection Response Registration

This specification requests registration of the following values in the "OAuth Token Introspection Response" registry [@IANA.OAuth.Params] established by [@RFC7662].

Authentication Context Class Reference:

* Name: `acr`
* Description: Authentication Context Class Reference
* Change Controller: IETF
* Specification Document(s): (#introspect) of [[ this specification ]]

Authentication Time:

* Name: `auth_time`
* Description: Time when the user authentication occurred
* Change Controller: IETF
* Specification Document(s): (#introspect) of [[ this specification ]]



<reference anchor="OIDC" target="https://openid.net/specs/openid-connect-core-1_0.html">
  <front>
    <title>OpenID Connect Core 1.0 incorporating errata set 1</title>
    <author initials="N." surname="Sakimura" fullname="Nat Sakimura">
      <organization>NRI</organization>
    </author>
    <author initials="J." surname="Bradley" fullname="John Bradley">
      <organization>Ping Identity</organization>
    </author>
    <author initials="M." surname="Jones" fullname="Mike Jones">
      <organization>Microsoft</organization>
    </author>
    <author initials="B." surname="de Medeiros" fullname="Breno de Medeiros">
      <organization>Google</organization>
    </author>
    <author initials="C." surname="Mortimore" fullname="Chuck Mortimore">
      <organization>Salesforce</organization>
    </author>
   <date day="8" month="Nov" year="2014"/>
  </front>
</reference>

<reference anchor="OIDCDISC" target="https://openid.net/specs/openid-connect-discovery-1_0.html">
  <front>
    <title>OpenID Connect Core 1.0 incorporating errata set 1</title>
    <author initials="N." surname="Sakimura" fullname="Nat Sakimura">
      <organization>NRI</organization>
    </author>
    <author initials="J." surname="Bradley" fullname="John Bradley">
      <organization>Ping Identity</organization>
    </author>
    <author initials="M." surname="Jones" fullname="Mike Jones">
      <organization>Microsoft</organization>
    </author>
    <author initials="E." surname="Jay" fullname="Edmund Jay">
      <organization>Illumila</organization>
    </author>

   <date day="8" month="Nov" year="2014"/>
  </front>
</reference>

<reference anchor="OIDCUAR" target="https://openid.net/specs/openid-connect-unmet-authentication-requirements-1_0.html">
  <front>
    <title>OpenID Connect Core Error Code unmet_authentication_requirements</title>
    <author initials="T." surname="Lodderstedt" fullname="Torsten Lodderstedt">
      <organization>YES</organization>
    </author>
   <date day="8" month="May" year="2019"/>
  </front>
</reference>

<reference anchor="IANA.OAuth.Params" target="https://www.iana.org/assignments/oauth-parameters">
 <front>
   <title>OAuth Parameters</title>
   <author><organization>IANA</organization></author>
 </front>
</reference>



{backmatter}

# Acknowledgements {#Acknowledgements}

I wanted to thank the Academy, the viewers at home, the shampoo manufacturers, etc..

This specification was developed within the OAuth Working Group under
the chairpersonship of Rifaat Shekh-Yusef and Hannes Tschofenig with
Paul Wouters, and Roman Danyliw serving as Security
Area Directors. Additionally, the following individuals contributed
ideas, feedback, corrections, and wording that helped shape this specification:
Caleb Baker,
Ivan Kanakarakis,
Pieter Kasselman,
Aaron Parecki,
Denis Pinkas,
Dima Postnikov,
and
Filip Skokan.

Some early discussion of the motivations and concepts that precipitated the initial version
of this document occurred at the 2021 OAuth Security Workshop. The authors thank the organizers of the
workshop (Guido Schmitz, Steinar Noem, and Daniel Fett) for hosting an event that is conducive to
collaboration and community input.


# Document History

   [[ To be removed from the final specification ]]

-15

-14

* Updates from Httpdir telechat review

-13

* Make IETF the Change Controller for all registration requests per IANA suggestion
* More updates from Genart review
* Updates from Artart review
* Updates from Secdir review

-12

* Updates from Genart Last Call review

-11

- Updates in the Protocol Overview section clarifying the nature of "authentication levels" and caching strategies, addressing AD review comments

-10

* Fix two references where the section numbers got lost presumably due to tooling issues

-09

* Updates addressing AD review comments

-07/-08

* Editorial updates addressing Shepherd Review comments

-06

* Update examples/figures to be clear that the authorization request is sent by the client via directing the user agent (not directly from client to AS)

-05

* Forgotten Acknowledgements
* Minor updates to the updates in -04

-04

* Editorial updates/notes from WGLC feedback

-03

* Clarified that `acr_values` and `max_age` can co-occur in the challenge when necessary
* fleshed out deployment and security considerations
* fleshed out IANA considerations
* Attempt to clarify that while `acr_values` can request more than one value, only one of them is used and ends up in the token

-02

* Fix typos introduced in -01
* Begin to fill out the Acknowledgements

-01

* Added AS Metadata section with pointer to `acr_values_supported`
* Mention that it's not necessarily the case that a new 'stepped-up' token always supersedes older tokens
* Add examples with `max_age`

-00 (Working Group Draft)

* Initial WG revision (content unchanged from draft-bertocci-oauth-step-up-authn-challenge-01)

-01 draft-bertocci-oauth-step-up-authn-challenge

* Fixed example
* Clarified/noted that scope can also be in the WWW-Authenticate/401

-00 draft-bertocci-oauth-step-up-authn-challenge

* Initial Individual Draft (with all the authority thereby bestowed https://datatracker.ietf.org/doc/html/draft-abr-twitter-reply).
