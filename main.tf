terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }

  required_version = ">= 1.2.0"
}

provider "aws" {
  region = "eu-west-1"
}

resource "aws_instance" "example" {
  ami           = "ami-00385a401487aefa4"
  instance_type = "t2.nano"

  tags = {
    Name  = "Example",
    Owner = "ruslan.korniichuk@gmail.com"
  }
}
