# Using ocserv with OpenIDConnect authentication

OpenID Connect (OIDC) is an identity layer build on top of the OAuth 2.0 protocols. Authentication using OIDC utilizes the following flow:

     +--------+                               +---------------+
     |        |--(A)- Authorization Request ->|   Resource    |
     |        |                               |     Owner     |
     |        |<-(B)-- Authorization Grant ---|   (end user)  |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(C)-- Authorization Grant -->| Authorization |
     | Client |                               |     Server    |
     |        |<-(D)----- Access Token -------|(oidc provide) |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(E)----- Access Token ------>|    Resource   |
     |        |                               |     Server    |
     |        |<-(F)--- Protected Resource ---|    (ocserv)   |
     +--------+                               +---------------+

For as more detailed explanation see the OpenID Connect protocol (<https://openid.net/connect/)>

## Deploying OIDC authentication

An administrator wanting to deployg OIDC as an authentication scheme must do the following:

1) Register an application identity with the OIDC provider
2) Obtain the token endpoint and the OpenID Connect metadata document endpoint for their OIDC provider
3) Determine what claims the OIDC provider supports
4) Author a JSON document tell ocserv how to validate the token
5) Add a line to the ocserv config file pointing to oidc config file: `auth = "oidc[config=<path to config file>]"`

See your OIDC providers documentation to better understand what claims they support.

## OIDC JSON Config file

Oidc.json file format:
```json
{
    "openid_configuration_url": "<uri of openid-configuration doc>",
    "user_name_claim": "preferred_username",
    "required_claims": {
       "aud": "SomeAudience",
       "iss": "SomeIssuer"
    }
}
```

Example openid-configuration doc URIs are:
1) <https://accounts.google.com/.well-known/openid-configuration>
2) <https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration>

Required claims controls what claims must be present in a token to permit access.

See your OpenID Connect provider for details on claims and OpenID Connect metadata document URL.

## Sample token

An OIDC token is returned as a base64url encoded blob.
`eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJFUzI1NiIsICJraWQiOiAiTXkgRmFrZSBLZXkifQ.eyJhdWQiOiAiU29tZUF1ZGllbmNlIiwgImlzcyI6ICJTb21lSXNzdWVyIiwgImlhdCI6IDE1ODE5ODAzMzcsICJuYmYiOiAxNTgxOTgwMzM3LCAiZXhwIjogMTU4MTk4Mzk5NywgInByZWZlcnJlZF91c2VybmFtZSI6ICJTb21lVXNlciJ9.dBGYHphmSHx_IQp09LpK9wkxAcIqnNRkX2Z59PPe0q7aU8yr2QZrq2fqtqRgk3fJ-LyRFaL5HyKHOHq3xebdXg`

You can view the contents of the token using <https://jwt.ms>.
```
{
  "typ": "JWT",
  "alg": "ES256",
  "kid": "My Fake Key"
}.{
  "aud": "SomeAudience",
  "iss": "SomeIssuer",
  "iat": 1581980337,
  "nbf": 1581980337,
  "exp": 1581983997,
  "preferred_username": "SomeUser"
}.[Signature]
```

|Claim type|Value|Notes|
|--------------|:--------|----:|
|aud|SomeAudience|The "aud" (audience) claim identifies the recipients that the JWT is intended for. Each principal intended to process the JWT MUST identify itself with a value in the audience claim. If the principal processing the claim does not identify itself with a value in the "aud" claim when this claim is present, then the JWT MUST be rejected. [RFC 7519, Section 4.1.3]|
|iss|SomeIssuer|The "iss" (issuer) claim identifies the principal that issued the JWT. The processing of this claim is generally application specific. The "iss" value is a case-sensitive string containing a StringOrURI value. [RFC 7519, Section 4.1.1]|
|iat|Mon Feb 17 2020 15:58:57 GMT-0700 (Mountain Standard Time)|The "iat" (issued at) claim identifies the time at which the JWT was issued. This claim can be used to determine the age of the JWT. [RFC 7519, Section 4.1.6]|
|nbf|Mon Feb 17 2020 15:58:57 GMT-0700 (Mountain Standard Time)|The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing. Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew. [RFC 7519, Section 4.1.5]|
|exp|Mon Feb 17 2020 16:59:57 GMT-0700 (Mountain Standard Time)|The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing. Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew. [RFC 7519, Section 4.1.4]|
|preferred_username|SomeUser|Shorthand name by which the End-User wishes to be referred to at the RP, such as janedoe or j.doe. This value MAY be any valid JSON string including special characters such as @, /, or whitespace. The RP MUST NOT rely upon this value being unique, as discussed in OpenID Connect Core 1.0 Section 5.7. [OpenID Connect Core 1.0, Section 5.1]|