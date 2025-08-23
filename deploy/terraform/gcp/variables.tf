variable "project_id" {
	type = string
}

variable "region" {
	type    = string
	default = "us-central1"
}

variable "artifact_repo" {
	type    = string
	default = "odin"
}

variable "service_name" {
	type    = string
	default = "odin-gateway"
}

variable "image" {
	type        = string
	description = "Container image URI"
}

variable "env" {
	type    = map(string)
	default = {}
}
