# =============================================================================
# Firewall Rules - Deny-All + Allow-List (Seccion 6.2)
# =============================================================================

# --- Regla base: Deny ALL por defecto ---
resource "google_compute_firewall" "deny_all_ingress" {
  name    = "deny-all-ingress"
  network = google_compute_network.main.id

  deny {
    protocol = "all"
  }

  direction     = "INGRESS"
  priority      = 65534
  source_ranges = ["0.0.0.0/0"]
  description   = "Deny-all default - solo se permite trafico explicitamente autorizado"
}

# --- DMZ: Permitir HTTPS desde internet ---
resource "google_compute_firewall" "allow_https_to_dmz" {
  name    = "allow-https-to-dmz"
  network = google_compute_network.main.id

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  direction          = "INGRESS"
  priority           = 1000
  source_ranges      = ["0.0.0.0/0"]
  target_tags        = ["dmz"]
  description        = "Permitir HTTPS desde internet a DMZ"
}

# --- DMZ -> App: Solo puertos de aplicacion ---
resource "google_compute_firewall" "allow_dmz_to_app" {
  name    = "allow-dmz-to-app"
  network = google_compute_network.main.id

  allow {
    protocol = "tcp"
    ports    = ["8080", "8443"]
  }

  direction   = "INGRESS"
  priority    = 1100
  source_tags = ["dmz"]
  target_tags = ["app"]
  description = "Permitir DMZ -> App en puertos de aplicacion"
}

# --- App -> Data: Solo puertos de BD ---
resource "google_compute_firewall" "allow_app_to_data" {
  name    = "allow-app-to-data"
  network = google_compute_network.main.id

  allow {
    protocol = "tcp"
    ports    = ["5432", "6379"]  # PostgreSQL, Redis
  }

  direction   = "INGRESS"
  priority    = 1200
  source_tags = ["app"]
  target_tags = ["data"]
  description = "Permitir App -> Data solo en puertos de BD (5432) y Redis (6379)"
}

# --- Health Checks de GCP ---
resource "google_compute_firewall" "allow_health_checks" {
  name    = "allow-gcp-health-checks"
  network = google_compute_network.main.id

  allow {
    protocol = "tcp"
    ports    = ["8080", "443"]
  }

  direction     = "INGRESS"
  priority      = 900
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  target_tags   = ["dmz", "app"]
  description   = "Health checks de GCP Load Balancer"
}

# --- VPN: Permitir trafico desde OnPrem ---
resource "google_compute_firewall" "allow_vpn_onprem" {
  name    = "allow-vpn-onprem"
  network = google_compute_network.main.id

  allow {
    protocol = "tcp"
    ports    = ["443", "8080", "8443"]
  }

  direction     = "INGRESS"
  priority      = 1050
  source_ranges = [var.onprem_ip_range]
  target_tags   = ["app"]
  description   = "Permitir trafico desde OnPrem via VPN"
}

# --- IAP (Identity-Aware Proxy) para SSH de administracion ---
resource "google_compute_firewall" "allow_iap_ssh" {
  name    = "allow-iap-ssh"
  network = google_compute_network.main.id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  direction     = "INGRESS"
  priority      = 1300
  source_ranges = ["35.235.240.0/20"]  # Rango IAP de GCP
  description   = "SSH via IAP (bastion virtual) - requiere MFA"
}
