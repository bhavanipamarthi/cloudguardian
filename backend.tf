terraform {
  backend "s3" {
    bucket         = "tfstate-51579"
    key            = "3tier/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "tfstate-lock"
    encrypt        = true
  }
}
