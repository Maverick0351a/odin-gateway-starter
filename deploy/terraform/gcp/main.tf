terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_artifact_registry_repository" "odin" {
  location      = var.region
  repository_id = var.artifact_repo
  format        = "DOCKER"
  description   = "ODIN images"
}

resource "google_cloud_run_service" "gateway" {
  name     = var.service_name
  location = var.region

  template {
    spec {
      containers {
        image = var.image
        env = [
          for k, v in var.env : {
            name  = k
            value = v
          }
        ]
      }
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }
}

resource "google_project_iam_member" "run_invoker" {
  project = var.project_id
  role    = "roles/run.invoker"
  member  = "allUsers"
  condition {
    title       = "public-access"
    description = "Allow public invocation"
    expression  = "true"
  }
}
