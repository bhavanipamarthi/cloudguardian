resource "aws_db_subnet_group" "main" {
  name       = "${local.name}-db-subnets"
  subnet_ids = [aws_subnet.data.id, aws_subnet.data_b.id]
  tags       = merge(local.tags, { Name = "${local.name}-db-subnets" })
}

# The defining security choice, mirroring the Azure design: publicly_accessible = false.
# The RDS instance has no public endpoint. The only path to it is from the web
# tier's security group, over the private VPC network.
resource "aws_db_instance" "main" {
  identifier     = "${local.name}-db"
  engine         = var.db_engine
  engine_version = var.db_engine == "postgres" ? "16" : "8.0"
  instance_class = var.db_instance_class

  allocated_storage = 20
  storage_type      = "gp3"
  # MISCONFIG #5 (encryption): storage_encrypted flipped to false for the
  # CloudGuardian capstone exercise. Prowler baseline had "RDS DB instance
  # storage is encrypted at rest" as a PASS (high severity); this flips it to
  # FAIL. To revert: set back to true (note -- AWS does not allow toggling
  # encryption on an existing RDS instance in place; a real revert would need
  # a snapshot-and-restore, not just a plan/apply).
  storage_encrypted = false

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.data.id]
  # MISCONFIG #3 (networking): publicly_accessible flipped to true for the
  # CloudGuardian capstone exercise. Prowler baseline had "RDS instance is not
  # publicly exposed to the Internet" as a PASS (critical severity); this flips
  # it to FAIL. To revert: set back to false.
  publicly_accessible = true
  multi_az            = false

  backup_retention_period = 0    # this account's Free Plan restricts backup retention beyond 0; disabling backups is fine for a lab that gets torn down anyway
  skip_final_snapshot     = true # lab only - use a final snapshot in a real deployment
  deletion_protection     = false

  tags = merge(local.tags, { Name = "${local.name}-db" })
}
