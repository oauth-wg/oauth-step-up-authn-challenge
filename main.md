%%%
title = "OAuth 2.0 Step-up Authentication Challenge Protocol"
abbrev = "OAuth Authn Challenge"
ipr = "trust200902"
area = "Security"
workgroup = "Web Authorization Protocol"
keyword = ["security", "oauth2", "openid connect", "oauth", "step-up"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-ietf-oauth-step-up-authn-challenge-03"
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

It is not uncommon for resource servers to require different authentication strengths or freshness according to the characteristics of a request. This document introduces a mechanism for a resource server to signal to a client that the authentication event associated with the access token of the current request doesn't meet its authentication requirements and specify how to meet them. 
This document also codifies a mechanism for a client to request that an authorization server achieve a specific authentication strength or freshness when processing an authorization request.

{mainmatter}

# Introduction {#Introduction}

In simple API authorization scenarios, an authorization server will statically determine what authentication technique to use to handle a given request on the basis of aspects such as the scopes requested, the resource, the identity of the client and other characteristics known at provisioning time.
Although the approach is viable in many situations, it falls short in several important circumstances. Consider, for instance, an eCommerce API requiring different authentication strengths depending on whether the item being purchased exceeds a certain threshold, dynamically estimated by the API itself using a logic that is opaque to the authorization server.
An API might also determine that  a more recent user authentication is required based on its own risk evaluation of the API request.  

This document extends the error codes collection defined by [@!RFC6750] with a new value, `insufficient_user_authentication`, which can be used by resource servers to signal to the client that the authentication event associated with the access token presented with the request doesn't meet the authentication requirements of the resource server.
This document also introduces `acr_values` and `max_age` parameters for the `WWW-Authenticate` response header defined by [@!RFC6750], which the resource server can use to explicitly communicate to the client the required authentication strength or recentness. 

The client can use that information to reach back to the authorization server with an authorization request specifying the authentication requirements indicated by protected resource, by including the `acr_values` or `max_age` parameter as defined in [@OIDC].

Those extensions will make it possible to implement interoperable step up authentication with minimal work from resource servers, clients and authorization servers.

## Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [@!RFC2119] [@!RFC8174]
when, and only when, they appear in all capitals, as shown here.

# Protocol Overview

Following is an end-to-end sequence of a typical step-up authentication scenario implemented according to this specification.
The scenario assumes that, before the sequence described below takes place, the client already obtained an access token for the protected resource.

!---
~~~ 
 +----------+                                +--------------+
 |          |                                |              |
 |          |-----(1) resource request------>|              |
 |          |                                |              |
 |          |<-------(2) challenge ----------|   Resource   |
 |          |                                |    Server    |
 |          |                                |              |
 |          |-----(5) resource request ----->|              |
 |          |                                |              |
 |          |<---(6) protected resource -----|              |
 |          |                                +--------------+
 |  Client  | 
 |          |
 |          |                                +---------------+
 |          |                                |               |
 |          |---(3) authorization request--->|               |
 |          |                                |               |
 |          |<-------------...-------------->| Authorization |
 |          |                                |     Server    |
 |          |<------ (4) access token -------|               |
 |          |                                |               |
 +----------+                                +---------------+
~~~
!---
Figure: Abstract protocol flow {#abstract-flow}

1. The client requests a protected resource, presenting an access token.
2. The resource server determines that the circumstances in which the presented access token was obtained offer insufficient authentication strength and/or freshness, hence it denies the request and returns a challenge describing (using a combination of `acr_values` and `max_age`) what authentication requirements must be met for the resource server to authorize a request.
3. The client directs the user agent to the authorization server with an authorization request that includes the `acr_values` and/or `max_age` indicated by the resource server in the previous step. 
4. After whatever sequence required by the grant of choice plays out, which will include the necessary steps to authenticate the user in accordance with the `acr_values` and/or `max_age` values of the authorization request, the authorization server returns a new access token to the client. The access token contains or references information about the authentication event. 
5. The client repeats the request from step 1, presenting the newly obtained access token.
6. The resource server finds that the user authentication performed during the acquisition of the new access token complies with its requirements, and returns the requested protected resource.

The validation operations mentioned in step 2 and 6 imply that the resource server has a way of evaluating the authentication level by which the access token was obtained. This document will describe how the resource server can perform that determination when the access token is a JWT Access token [@RFC9068] or is validated via introspection [@RFC7662]. 
Other methods of determining the authentication level by which the access token was obtained are possible, per agreement by the authorization server and the protected resource, but are beyond the scope of this specification.

Although the case in which the new access token supersedes old tokens by virtue of a higher authentication level is common, in line with the intuition the term "step-up authentication" suggests, it is important to keep in mind that this might not be necessarily hold true in the general case. For example: a resource server might require for a particular request a higher authentication level and a shorter validity, resulting in a token suitable for one-off calls but leading to frequent prompts, hence a suboptimal user experience, if reused for routine operations. In those scenarios, the client would be better served by keeping both the old tokens, associated with a lower authentication level, and the new one- selecting the appropriate token for each API call. This isn't a new requirement for clients, as incremental consent and least privilege principles will require similar heuristics for managing access tokens associated to different scopes and permission levels. This document doesn't recommend any specific token caching strategy, as that will be dependent on the characteristics of every particular scenario.

# Authentication Requirements Challenge {#Challenge}


This specification introduces a new error code value for the `error` parameter of [@!RFC6750] or authentication schemes, such as [@I-D.ietf-oauth-dpop], which use the `error` parameter:

`insufficient_user_authentication`
:   The authentication event associated with the access token presented with the request doesn't meet the authentication requirements of the protected resource.

Note: the logic through which the resource server determines that the current request doesn't meet the authentication requirements of the protected resource, and associated functionality (such as expressing, deploying and publishing such requirements) is out of scope for this document.

Furthermore, this specification defines additional `WWW-Authenticate` auth-param values to convey the authentication requirements back to the client.

`acr_values`
:   A space-separated string listing the authentication context class reference values, in order of preference, one of which the protected resource requires for the authentication event associated with the access token.


`max_age`
:   Indicates the allowable elapsed time in seconds since the last active authentication event associated with the access token.

(#acr-challenge) below is an example of a `WWW-Authenticate` header using the `insufficient_user_authentication` error code value to inform the client that the access token presented isn't sufficient to gain access to the protected resource, and the `acr_values` parameter to let the client know that the expected authentication level corresponds to the authentication context class reference identified by `myACR`.

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

A client receiving an authorization error from the resource server carrying the error code `insufficient_user_authentication` MAY parse the `WWW-Authenticate` header for  `acr_values` and `max_age` and use them, if present, in a request to the authorization server to obtain a new access token complying with the corresponding requirements.
Both `acr_values` and `max_age` authorization request parameters are OPTIONAL parameters defined in Section 3.1.2.1. of [@OIDC]. This document does not introduce any changes in the authorization server behavior defined in [@OIDC] for precessing those parameters, hence any authorization server implementing OpenID Connect will be able to participate in the flow described here with little or no changes. See Section (#AuthzResp) for more details.

The example request below, which might occur after receiving the challenge in (#acr-challenge), indicates to the authorization server that the client would like the authentication to occur according to the authentication context class reference identified by `myACR`.
!---
~~~ 
GET https://as.example.net/authorize?client_id=s6BhdRkqt3
&response_type=code&scope=purchase&acr_values=myACR
~~~
!---
Figure: Authorization Request indicating `acr_values`


Subsequent to the challenge in (#age-challenge), a client might make the following example request that indicates to the authorization server that the user authentication event needs to have occurred no more than five seconds prior.
!---
~~~
GET https://as.example.net/authorize?client_id=s6BhdRkqt3
&response_type=code&scope=purchase&max_age=5
~~~
!---
Figure: Authorization Request indicating `max_age`

# Authorization Response {#AuthzResp}
Section 5.5.1.1 of [@OIDC] establishes that an authorization server receiving a request containing the `acr_values` parameter MAY attempt to authenticate the user in a manner that satisfies the requested Authentication Context Class Reference, and include the corresponding value in the `acr` claim in the resulting ID Token. The same section also establishes that in case the desired authentication level cannot be met, the authorization server SHOULD include in the `acr` claim a value reflecting the authentication level of the current session (if any). The same section also states that if a request includes thee `max_age` parameter, the authorization server MUST include the `auth_time` claim in the issued ID Token.
An authorization server complying with this specification will react to the presence of the `acr_values` and `max_age` parameters by including `acr` and `auth_time` in the access token (see (#authn-info-in-at) for details).
Although [@OIDC] leaves the authorization server free to decide how to handle the inclusion of `acr` in ID Token when requested via `acr_values`, when it comes to access tokens in this specification it is RECOMMENDED that the requested `acr` value is treated as required for successfully fulfilling the request. That is, the requested `acr` value is included in the access token if the authentication operation successfully met its requirements, or that the authorization request fails in all other cases, returning `unmet_authentication_requirements` as defined in [@OIDCUAR]. The recommended behavior will help prevent clients getting stuck in a loop where the authorization server keeps returning tokens that the resource server already identified as not meeting its requirements hence known to be rejected as well.

# Authentication Information Conveyed via Access Token {#authn-info-in-at}

To evaluate whether an access token meets the protected resource's requirements, the resource servers needs a way of accessing information about the authentication event by which that access token was obtained. This specification provides guidance on how to convey that information in conjunction with two common access token validation methods: the one described in [@!RFC9068], where the access token is encoded in JWT format and verified via a set of validation rules, and the one described in [@!RFC7662], where the token is validated and decoded by sending it to an introspection endpoint.
Authorization servers and resource servers MAY elect to use other encoding and validation methods, however those are out of scope for this document. 

## JWT Access Tokens

When access tokens are represented as JSON Web Tokens (JWT) [@RFC7519], the `auth_time` and `acr` claims (per Section 2.2.1 of [@!RFC9068]) are used to convey the time and context of the user authentication event that the authentication server performed during the course of obtaining the access token. It is useful to bear in mind that the values of those two parameters are established at user authentication time and won't change in the event of access token renewals. See the aforementioned Section 2.2.1 of [@!RFC9068] for details. The following is a conceptual example showing the decoded content of such a JWT access token.

!---
~~~ 
Header:

{"typ":"at+JWT","alg":"RS256","kid":"LTacESbw"}
 
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

## OAuth 2.0 Token Introspection {#intro}

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

This specification facilitates the communication of requirements from a resource server to a client, which in turn can enable a smooth step-up authentication experience. However, it's important to realize that the user experience achievable in every specific deployment is a function of the policies each resource server and authorization server pairs establish. Imposing constraints on those policies is out of scope for this specification, hence it is perfectly possible for resource servers and authorization servers to impose requirements that are impossible for users to comply with, or leading to any undesirable user experience outcomes. 
The authentication prompts presented by the authorization server as a result of the requirements propagation method described here might require the user to perform some specific actions such as using multiple devices, having access to devices complying with specific security requirements, and so on. Those extra requirements, concerning more about how to comply with a particular requirement rather than indicating the identifier of the requirement itself, are out of scope for this specification.

# Security Considerations {#Security}

This document should, in no circumstance, be used to position OAuth as an authentication protocol. The specification focuses on the authentication event of the user with the authorization server by which the access token was obtained, so that its characteristics can be evaluated by a resource server to determine whether they meet its requirements, but relies on a separate authentication layer to take care of the mechanics leading to that event. In line with other specifications of the OAuth family, this document assumes the existence of a session without going into the details of how it is established or maintained, what protocols are used to implement that layer (e.g., OpenID Connect), and so forth.
Depending on the policies adopted by the resource server, the `acr_values` parameter introduced in {#Challenge} might unintentionally disclose information about the authenticated user, the resource itself, the authorization server, and any other context-specific data that an attacker might use to gain knowledge about their target. Implementers should use care in determining what to disclose in the challenge and in what circumstances.
The logic examining the incoming access token to determine whether a challenge should be returned can execute either before or after the traditional token validation logic, be it based on JWT token validation, introspection, or any other method. The resource server is free to choose whatever method fits best for its needs, however, it's important to remember that returning a challenge without having verified that the caller presented a valid token (according to the validation method of choice) might mean disclosing information to an actor that didn't prove it had the ability to obtain a valid token for the resource server, albeit of insufficient level.

# IANA Considerations {#IANA}
      
[[TBD]]  

The `insufficient_user_authentication` error code in the "OAuth Extensions Error" registry [@IANA.OAuth.Params].

(#intro) for `acr` and `auth_time` as top-level members of the introspection response in the "OAuth Token Introspection Response" registry [@IANA.OAuth.Params].

The `acr_values` and `max_age` `WWW-Authenticate` auth-params are "new" but doesn't seem like any registration is needed or possible.




<reference anchor="OIDC" target="http://openid.net/specs/openid-connect-core-1_0.html">
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
Ivan Kanakarakis,
Pieter Kasselman,
and
Filip Skokan.

Some early discussion of the motivations and concepts that precipitated the initial version
of this document occurred at the 2021 OAuth Security Workshop. The authors thank the organizers of the
workshop (Guido Schmitz, Steinar Noem, and Daniel Fett) for hosting an event that's conducive to
collaboration and community input.


# Document History

   [[ To be removed from the final specification ]]

-03
* Clarified that `acr_values` and `max_age` can co-occur in the challenge when necessary
* fleshed out deployment and security considerations
* Attempt to clarify that while acr_values can request more then one value, only one of them is used and ends up in the token

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

* Initial Individual Draft (with all the authority thereby bestowed [@I-D.abr-twitter-reply]).
