variable "region" { type = string default = "us-east-1" }
variable "ecr_repo" { type = string default = "odin-gateway" }
variable "cluster_name" { type = string default = "odin-cluster" }
variable "image" { type = string description = "Container image URI" }
variable "cpu" { type = string default = "512" }
variable "memory" { type = string default = "1024" }
variable "env" { type = map(string) default = {} }
variable "subnets" { type = list(string) }
variable "security_group" { type = string }
variable "vpc_id" { type = string }
