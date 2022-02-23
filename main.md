%%%
title = "OAuth 2.0 Step-up Authentication Challenge Protocol"
abbrev = "OAuth Authn Challenge"
ipr = "trust200902"
area = "Security"
workgroup = "Web Authorization Protocol"
keyword = ["security", "oauth2", "openid connect", "oauth", "step-up"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-bertocci-oauth-step-up-authn-challenge-00"
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

# Authentication Requirements Challenge

[[TBD]]  ... new error code value for the `error` parameter of [@!RFC6750] or authentication schemes, such as [@I-D.ietf-oauth-dpop], which use the `error` parameter:

`insufficient_user_authentication`
:   The authentication event associated with the access token presented with the request doesn't meet the authentication requirements of the protected resource.


[[TBD]]  ... additional `WWW-Authenticate` auth-param values to convey the authentication requirements 

`acr_values`
:   A space-separated string indicating, in order of preference, the authentication context class reference values that the protected resource requires the authentication event associated with the access token.

`max_age`
:   Indicates the allowable elapsed time in seconds since the last active authentication event associated with the access token.

Examples...  [[TBD]]


# Authorization Request

[[TBD]] ... somehow nicely point to [@OIDC]'s `acr_values` and `max_age` authorization request parameters and say they can be used with a regular old authorization server.

Examples...  [[TBD]]

# Authentication Information Conveyed via Access Token

[[TBD]] ... resource servers needs a way of accessing information about the authentication event by which the access token was obtained ... this is conveyed with/in the access token ... JWT and Introspection ... others out of scope. 

## JWT

https://datatracker.ietf.org/doc/html/rfc9068#section-2.2.1 [[TBD]]

## Token Introspection

auth_time and acr as defined Introspection response parameters [[TBD]]

# Authorization Server Metadata

[[TBD]] ? 

# Security Considerations {#Security}

[[TBD]]

Remember that oauth is not authN, you need a layer like OIDC to handle that part. This is not an encouragement to abuse oauth. This is about the authentication event of the user to the AS by which the access token was obtained.  

[[TBD]]

# IANA Considerations {#IANA}
      
[[TBD]]  

The `insufficient_user_authentication` error code in the "OAuth Extensions Error" registry [@IANA.OAuth.Params].

`acr` and `auth_time` as top-level members of the introspection response in the "OAuth Token Introspection Response" registry [@IANA.OAuth.Params].

The `acr_values` and `max_age` `WWW-Authenticate` auth-params are "new" but doesn't seem like any registration is needed or possible.

[[TBD]]



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


<reference anchor="IANA.OAuth.Params" target="https://www.iana.org/assignments/oauth-parameters">
 <front>
   <title>OAuth Parameters</title>
   <author><organization>IANA</organization></author>
 </front>
</reference>



{backmatter}

# Acknowledgements {#Acknowledgements}
      
I wanted to thank the Academy, the viewers at home, the shampoo manufacturers, etc..

Initially (kinda) discussed at the OAuth Security Workshop 2021 

A number of others already but haven't kept track... 


# RUDE FAQ

[[TBD]]

What about the OIDC Claims parameter?

Why just auth levels and not more?

ACR vs AMR

Bearer, what about other schemes?

[[TBD]]


# Document History

   [[ To be removed from the final specification ]]

   -00

   * Initial Individual Draft (with all the authority thereby conveyed [@I-D.abr-twitter-reply]).