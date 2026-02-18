# =============================================================================
# Variables - Infraestructura Portal Financiero XYZ
# =============================================================================

variable "project_id" {
  description = "ID del proyecto en GCP"
  type        = string
}

variable "region" {
  description = "Region de GCP"
  type        = string
  default     = "us-east1"
}

variable "environment" {
  description = "Ambiente de despliegue"
  type        = string
  default     = "production"
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment debe ser development, staging o production."
  }
}

variable "onprem_ip_range" {
  description = "Rango de IPs del datacenter OnPremise para VPN"
  type        = string
  default     = "10.0.0.0/16"
}

variable "onprem_gateway_ip" {
  description = "IP publica del gateway VPN OnPremise"
  type        = string
}

variable "vpn_shared_secret_id" {
  description = "ID del secret en GCP Secret Manager para el shared secret de VPN"
  type        = string
  default     = "vpn-shared-secret"
}
