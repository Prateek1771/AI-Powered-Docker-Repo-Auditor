# Put these in the repository's Actions secrets. They are role ARNs, not
# credentials - useless without a token minted for this repo.
output "build_role_arn" {
  value = aws_iam_role.build.arn
}

output "deploy_role_arn" {
  value = aws_iam_role.deploy.arn
}

output "oidc_provider_arn" {
  value = aws_iam_openid_connect_provider.github.arn
}
