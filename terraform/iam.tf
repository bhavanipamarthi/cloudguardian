# --- MC-02 / MC-03: overprivileged IAM user, missing MFA ------------------
resource "aws_iam_user" "cloudguardian" {
  name = "cloudguardian"
  tags = { Project = "CloudGuardian", Finding = "MC-02,MC-03" }
}

# Vulnerable baseline: broad AdministratorAccess-style policy.
# Remediated: scoped policy limited to the demo workload's actual needs.
data "aws_iam_policy_document" "scoped" {
  statement {
    sid    = "S3DemoAccess"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
    ]
    resources = [
      aws_s3_bucket.data.arn,
      "${aws_s3_bucket.data.arn}/*",
      aws_s3_bucket.legacy.arn,
      "${aws_s3_bucket.legacy.arn}/*",
    ]
  }

  dynamic "statement" {
    for_each = var.enable_misconfigurations ? [1] : []
    content {
      sid       = "MC02OverprivilegedWildcard"
      effect    = "Allow"
      actions   = ["ec2:*", "rds:*", "iam:*"]
      resources = ["*"]
    }
  }
}

resource "aws_iam_policy" "scoped" {
  name        = "CloudGuardian-ScopedPolicy"
  description = "Policy attached to the cloudguardian IAM user (MC-02 in its unremediated form)"
  policy      = data.aws_iam_policy_document.scoped.json
}

resource "aws_iam_user_policy_attachment" "cloudguardian" {
  user       = aws_iam_user.cloudguardian.name
  policy_arn = aws_iam_policy.scoped.arn
}

# MC-03: MFA enforcement. In the vulnerable baseline no MFA device is
# attached and no policy requires one. The remediated variant attaches a
# deny-without-MFA guardrail policy (the human-approval Lambda path also
# checks this at remediation time).
data "aws_iam_policy_document" "deny_without_mfa" {
  count = var.enable_misconfigurations ? 0 : 1

  statement {
    sid       = "DenyAllExceptMFAWhenUnauthenticated"
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]
    condition {
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }
  }
}

resource "aws_iam_policy" "deny_without_mfa" {
  count       = var.enable_misconfigurations ? 0 : 1
  name        = "CloudGuardian-DenyWithoutMFA"
  description = "Guardrail: deny all actions unless MFA is present"
  policy      = data.aws_iam_policy_document.deny_without_mfa[0].json
}

resource "aws_iam_user_policy_attachment" "deny_without_mfa" {
  count      = var.enable_misconfigurations ? 0 : 1
  user       = aws_iam_user.cloudguardian.name
  policy_arn = aws_iam_policy.deny_without_mfa[0].arn
}
