output "user_pool_id" {
  value = aws_cognito_user_pool.main.id
}

output "client_id" {
  value = aws_cognito_user_pool_client.web.id
}

# What Cognito puts in a token's `iss`. app/core/auth.py passes this to
# jwt.decode as issuer=, and python-jose skips the issuer check entirely when
# it is not supplied - so an unset TOKEN_ISSUER is not a lax deployment, it is
# a refused one: assert_production_auth() treats the dev default as a
# refuse-to-start condition and the API task crash-looped without this.
# See docs/audits/audit-02-frontend-worker-observability.md F15.
output "issuer" {
  value = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.main.id}"
}

# app/api/auth.py fetches this and caches it for JWKS_CACHE_SECONDS.
output "jwks_url" {
  value = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.main.id}/.well-known/jwks.json"
}
