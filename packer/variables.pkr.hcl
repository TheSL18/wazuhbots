## WazuhBOTS LXC Template — Variable Definitions
## All variables can be overridden in variables.auto.pkrvars.hcl

# ─── Proxmox / Template ─────────────────────────────────────────────

variable "vmid" {
  type        = number
  default     = 9000
  description = "Proxmox VMID for the LXC template"
}

variable "template_name" {
  type        = string
  default     = "wazuhbots-lxc"
  description = "Name for the output template"
}

variable "hostname" {
  type        = string
  default     = "wazuhbots"
  description = "Hostname inside the LXC container"
}

variable "storage" {
  type        = string
  default     = "local"
  description = "Proxmox storage target for the template"
}

# ─── LXC Resources ──────────────────────────────────────────────────

variable "cores" {
  type        = number
  default     = 8
  description = "CPU cores for the LXC container"
}

variable "memory" {
  type        = number
  default     = 16384
  description = "Memory in MB for the LXC container"
}

variable "disk_size" {
  type        = string
  default     = "120G"
  description = "Root disk size for the LXC container"
}

# ─── Source ──────────────────────────────────────────────────────────

variable "lxc_distro" {
  type        = string
  default     = "ubuntu"
  description = "LXC image distribution"
}

variable "lxc_release" {
  type        = string
  default     = "jammy"
  description = "LXC image release codename"
}

variable "lxc_arch" {
  type        = string
  default     = "amd64"
  description = "LXC image architecture"
}

# ─── Docker ──────────────────────────────────────────────────────────

variable "docker_subnet" {
  type        = string
  default     = "172.26.0.0/16"
  description = "Docker daemon default address pool"
}

# ─── Project ─────────────────────────────────────────────────────────

variable "project_src" {
  type        = string
  default     = ".."
  description = "Path to the WazuhBOTS project root (relative to packer/)"
}

variable "project_dest" {
  type        = string
  default     = "/opt/wazuhbots"
  description = "Installation path inside the LXC container"
}
