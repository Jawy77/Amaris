# =============================================================================
# VPN Site-to-Site - Interconexion Cloud-OnPremise (Seccion 6.4)
# =============================================================================

# HA VPN Gateway (alta disponibilidad)
resource "google_compute_ha_vpn_gateway" "main" {
  name    = "xyz-vpn-gateway"
  region  = var.region
  network = google_compute_network.main.id
}

# Peer VPN Gateway (OnPremise)
resource "google_compute_external_vpn_gateway" "onprem" {
  name            = "onprem-vpn-gateway"
  redundancy_type = "SINGLE_IP_INTERNALLY_REDUNDANT"

  interface {
    id         = 0
    ip_address = var.onprem_gateway_ip
  }
}

# Cloud Router para BGP
resource "google_compute_router" "vpn_router" {
  name    = "vpn-router"
  region  = var.region
  network = google_compute_network.main.id

  bgp {
    asn               = 64514
    advertise_mode    = "CUSTOM"
    advertised_groups = ["ALL_SUBNETS"]
  }
}

# Shared secret desde Secret Manager (no hardcodeado)
data "google_secret_manager_secret_version" "vpn_secret" {
  secret = var.vpn_shared_secret_id
}

# Tunel VPN con IPSec
resource "google_compute_vpn_tunnel" "tunnel_0" {
  name                  = "vpn-tunnel-0"
  region                = var.region
  vpn_gateway           = google_compute_ha_vpn_gateway.main.id
  peer_external_gateway = google_compute_external_vpn_gateway.onprem.id
  shared_secret         = data.google_secret_manager_secret_version.vpn_secret.secret_data
  router                = google_compute_router.vpn_router.id

  vpn_gateway_interface = 0
  peer_external_gateway_interface = 0

  # IKEv2 con cifrado fuerte
  ike_version = 2
}

# BGP Session
resource "google_compute_router_interface" "vpn_interface" {
  name       = "vpn-interface"
  router     = google_compute_router.vpn_router.name
  region     = var.region
  ip_range   = "169.254.0.1/30"
  vpn_tunnel = google_compute_vpn_tunnel.tunnel_0.name
}

resource "google_compute_router_peer" "onprem_peer" {
  name                      = "onprem-bgp-peer"
  router                    = google_compute_router.vpn_router.name
  region                    = var.region
  peer_ip_address           = "169.254.0.2"
  peer_asn                  = 64515
  advertised_route_priority = 100
  interface                 = google_compute_router_interface.vpn_interface.name
}
