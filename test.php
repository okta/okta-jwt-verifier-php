<?php

require __DIR__ . '/vendor/autoload.php';

$jwt = 'eyJraWQiOiJDTmxsNmUtNFRQZ05fSXFVTEhGcnpOaUxGWjlJR1NGS1JlUE9TNE8tZGRBIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiIwMHVnNG9kM2lzcDlLVzZJSzBoNyIsImVtYWlsIjoieXVyaXlAcmVudHRyYWNrLmNvbSIsInZlciI6MSwiaXNzIjoiaHR0cHM6Ly9kZXYtMzMyNDE3Lm9rdGFwcmV2aWV3LmNvbS9vYXV0aDIvZGVmYXVsdCIsImF1ZCI6IjBvYWc0cDh5eWJ5b05odDczMGg3IiwiaWF0IjoxNTM2MDU2NDUzLCJleHAiOjE1MzYwNjAwNTMsImp0aSI6IklELmM3T0hDNXM2MktQV0p3NTVOS2tLaGU4azFwM2ttbTN4ckxKWlNqR3lMREkiLCJhbXIiOlsicHdkIl0sImlkcCI6IjAwb2c0b2QzZzRmdmpGaHpBMGg3Iiwibm9uY2UiOiJZc0c3NmpvIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF1dGhfdGltZSI6MTUzNjA1Mzc4NX0.RHKEY-vC8avShDnYgP5xzddcbGsIkLiJze84yQtPE7N78lEtqaYuSaYJQk9J2PutJdx4MN427aAsrFnyQ3B1zxrvXeIR17iQwleb_93VQjVrxbtHq7wXHtPVUF7yHbId3mre3fAMvBtnG8PA01RQDCTqLXbySXCPDazJxqOhYs4E5KIKdpxDGwsWP5r0ROpeSD7KE3yPudoBBG4pQ9CSyH0-a38L5veeX7BTHPCeJsIN-WMSsBk8ZwO_3hmYT2hVd_pLT1gPt0GtGWlgf2H4XWQuKZ5KHO6UvqjWLtINSeUmTsF9dhd-XD122SThhjg0q1ofm-rdHC_xCotvmkFVfQ';

$jwtVerifier = (new \Okta\JwtVerifier\JwtVerifierBuilder())
    ->setDiscovery(new \Okta\JwtVerifier\Discovery\Oauth) // This is not needed if using oauth.  The other option is OIDC
    ->setAdaptor(new \Okta\JwtVerifier\Adaptors\LcobucciJwt)
    ->setNonce('YsG76jo')
    ->setAudience('0oag4p8yybyoNht730h7')
    ->setIssuer('https://dev-332417.oktapreview.com/oauth2/default')
    ->build();

$jwt = $jwtVerifier->verify($jwt);

var_dump($jwt); //Returns instance of \Okta\JwtVerifier\JWT

var_dump($jwt->toJson()); // Returns Claims as JSON Object

var_dump($jwt->getClaims()); // Returns Claims as they come from the JWT Package used

var_dump($jwt->getIssuedAt()); //returns timestamp of Expiration Time

var_dump($jwt->getExpirationTime()); //returns timestamp of Expiration Time

/*
Response from https://dev-332417.oktapreview.com/oauth2/default/.well-known/oauth-authorization-server

{
    "issuer":"https://dev-332417.oktapreview.com/oauth2/default",
   "authorization_endpoint":"https://dev-332417.oktapreview.com/oauth2/default/v1/authorize",
   "token_endpoint":"https://dev-332417.oktapreview.com/oauth2/default/v1/token",
   "registration_endpoint":"https://dev-332417.oktapreview.com/oauth2/v1/clients",
   "jwks_uri":"https://dev-332417.oktapreview.com/oauth2/default/v1/keys",
   "response_types_supported":[
    "code",
    "token",
    "code token"
],
   "response_modes_supported":[
    "query",
    "fragment",
    "form_post",
    "okta_post_message"
],
   "grant_types_supported":[
    "authorization_code",
    "implicit",
    "refresh_token",
    "password",
    "client_credentials"
],
   "subject_types_supported":[
    "public"
],
   "scopes_supported":[
    "openid",
    "profile",
    "email",
    "address",
    "phone",
    "offline_access"
],
   "token_endpoint_auth_methods_supported":[
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "none"
],
   "claims_supported":[
    "ver",
    "jti",
    "iss",
    "aud",
    "iat",
    "exp",
    "cid",
    "uid",
    "scp",
    "sub"
],
   "code_challenge_methods_supported":[
    "S256"
],
   "introspection_endpoint":"https://dev-332417.oktapreview.com/oauth2/default/v1/introspect",
   "introspection_endpoint_auth_methods_supported":[
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "none"
],
   "revocation_endpoint":"https://dev-332417.oktapreview.com/oauth2/default/v1/revoke",
   "revocation_endpoint_auth_methods_supported":[
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "none"
],
   "end_session_endpoint":"https://dev-332417.oktapreview.com/oauth2/default/v1/logout",
   "request_parameter_supported":true,
   "request_object_signing_alg_values_supported":[
    "HS256",
    "HS384",
    "HS512"
]
}
*/
