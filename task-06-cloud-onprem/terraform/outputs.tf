# =============================================================================
# Outputs
# =============================================================================

output "vpc_id" {
  description = "ID de la VPC principal"
  value       = google_compute_network.main.id
}

output "subnet_dmz_id" {
  description = "ID del subnet DMZ"
  value       = google_compute_subnetwork.dmz.id
}

output "subnet_app_id" {
  description = "ID del subnet de Aplicacion"
  value       = google_compute_subnetwork.app.id
}

output "subnet_data_id" {
  description = "ID del subnet de Datos"
  value       = google_compute_subnetwork.data.id
}

output "vpn_gateway_ip" {
  description = "IP del VPN Gateway"
  value       = google_compute_ha_vpn_gateway.main.vpn_interfaces[0].ip_address
}
