# =============================================================================
# Main - Infraestructura Portal Financiero XYZ (GCP)
# Referencia: Task 6 - Arquitectura Cloud + OnPremise
# =============================================================================

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }

  backend "gcs" {
    bucket = "xyz-financial-terraform-state"
    prefix = "infrastructure"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Habilitar APIs necesarias
resource "google_project_service" "apis" {
  for_each = toset([
    "compute.googleapis.com",
    "container.googleapis.com",
    "sqladmin.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudkms.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
}
