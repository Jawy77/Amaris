# =============================================================================
# VPC y Subnets - Segmentacion de Red (Seccion 6.2)
# 3 zonas: DMZ, Aplicacion, Datos
# =============================================================================

resource "google_compute_network" "main" {
  name                    = "xyz-financial-vpc"
  auto_create_subnetworks = false
  description             = "VPC principal del portal financiero XYZ"
}

# --- Subnet DMZ (WAF, Load Balancer) ---
resource "google_compute_subnetwork" "dmz" {
  name          = "subnet-dmz"
  ip_cidr_range = "10.1.0.0/24"
  region        = var.region
  network       = google_compute_network.main.id
  description   = "Zona DMZ - WAF y Load Balancer"

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# --- Subnet Aplicacion (GKE, API Gateway) ---
resource "google_compute_subnetwork" "app" {
  name          = "subnet-app"
  ip_cidr_range = "10.2.0.0/20"
  region        = var.region
  network       = google_compute_network.main.id
  description   = "Zona de Aplicacion - GKE y microservicios"

  private_ip_google_access = true

  secondary_ip_range {
    range_name    = "gke-pods"
    ip_cidr_range = "10.10.0.0/16"
  }

  secondary_ip_range {
    range_name    = "gke-services"
    ip_cidr_range = "10.20.0.0/20"
  }

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# --- Subnet Datos (Cloud SQL, Redis) - SIN acceso a internet ---
resource "google_compute_subnetwork" "data" {
  name          = "subnet-data"
  ip_cidr_range = "10.3.0.0/24"
  region        = var.region
  network       = google_compute_network.main.id
  description   = "Zona de Datos - BD y cache (aislada)"

  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1.0
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# --- Cloud NAT (egress controlado desde subnets privadas) ---
resource "google_compute_router" "main" {
  name    = "xyz-financial-router"
  region  = var.region
  network = google_compute_network.main.id
}

resource "google_compute_router_nat" "nat" {
  name                               = "xyz-financial-nat"
  router                             = google_compute_router.main.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.app.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}
