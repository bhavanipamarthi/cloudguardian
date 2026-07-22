# ---------- Secrets Manager (equivalent to Azure Key Vault) ----------
# The DB password flows in exactly once, via TF_VAR_db_password, and is written
# here. The web tier's IAM role is granted read-only access to this one secret -
# it never receives the password as a plaintext environment variable or file.
resource "aws_secretsmanager_secret" "db_password" {
  name                    = "${local.name}-db-password"
  recovery_window_in_days = 0 # 0 = destroy immediately on `terraform destroy`, easier lab cleanup
  tags                    = local.tags
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({
    username = var.db_username
    password = var.db_password
    engine   = var.db_engine
    host     = aws_db_instance.main.address
    port     = aws_db_instance.main.port
    dbname   = var.db_name
  })
}

resource "aws_iam_role_policy" "web_secrets" {
  name = "${local.name}-web-secrets-access"
  role = aws_iam_role.web.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [aws_secretsmanager_secret.db_password.arn]
    }]
  })
}
