## WazuhBOTS — Packer LXC Template for Proxmox
##
## Builds a rootfs tarball with Ubuntu 22.04, Docker CE, Python3,
## and the full WazuhBOTS project pre-loaded. A systemd first-boot
## service completes deployment on first clone.
##
## Usage:
##   packer init .
##   packer validate .
##   packer build .

packer {
  required_plugins {
    lxc = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/lxc"
    }
  }
}

# ─── LXC Builder ────────────────────────────────────────────────────

source "lxc" "wazuhbots" {
  config_file      = "lxc-config.conf"
  template_name    = "download"
  template_parameters = [
    "--dist", var.lxc_distro,
    "--release", var.lxc_release,
    "--arch", var.lxc_arch,
  ]
  output_directory = "output"

  init_timeout = 120
}

# ─── Build Pipeline ─────────────────────────────────────────────────

build {
  name    = "wazuhbots"
  sources = ["source.lxc.wazuhbots"]

  # ── Copy project into container ──────────────────────────────────

  provisioner "shell" {
    inline = ["mkdir -p ${var.project_dest}"]
  }

  provisioner "file" {
    source      = "${var.project_src}/docker-compose.yml"
    destination = "${var.project_dest}/docker-compose.yml"
  }

  provisioner "file" {
    source      = "${var.project_src}/generate-indexer-certs.yml"
    destination = "${var.project_dest}/generate-indexer-certs.yml"
  }

  provisioner "file" {
    source      = "${var.project_src}/.env.example"
    destination = "${var.project_dest}/.env.example"
  }

  provisioner "file" {
    source      = "${var.project_src}/scripts"
    destination = "${var.project_dest}/scripts"
  }

  provisioner "file" {
    source      = "${var.project_src}/config"
    destination = "${var.project_dest}/config"
  }

  provisioner "file" {
    source      = "${var.project_src}/docker"
    destination = "${var.project_dest}/docker"
  }

  provisioner "file" {
    source      = "${var.project_src}/datasets"
    destination = "${var.project_dest}/datasets"
  }

  provisioner "file" {
    source      = "${var.project_src}/ctfd"
    destination = "${var.project_dest}/ctfd"
  }

  provisioner "file" {
    source      = "${var.project_src}/wazuh"
    destination = "${var.project_dest}/wazuh"
  }

  provisioner "file" {
    source      = "${var.project_src}/docs"
    destination = "${var.project_dest}/docs"
  }

  # ── Copy firstboot and config files ──────────────────────────────

  provisioner "file" {
    source      = "files/wazuhbots-firstboot.service"
    destination = "/etc/systemd/system/wazuhbots-firstboot.service"
  }

  provisioner "file" {
    source      = "files/wazuhbots-firstboot.sh"
    destination = "${var.project_dest}/firstboot.sh"
  }

  provisioner "file" {
    source      = "files/docker-daemon.json"
    destination = "/tmp/docker-daemon.json"
  }

  provisioner "file" {
    source      = "files/wazuhbots.motd"
    destination = "/tmp/wazuhbots.motd"
  }

  provisioner "file" {
    source      = "files/sysctl-wazuhbots.conf"
    destination = "/tmp/sysctl-wazuhbots.conf"
  }

  # ── Build-time provisioning scripts ──────────────────────────────

  provisioner "shell" {
    scripts = [
      "scripts/01-system-base.sh",
      "scripts/02-project-setup.sh",
      "scripts/03-docker-prep.sh",
      "scripts/04-firstboot-install.sh",
      "scripts/05-cleanup.sh",
    ]
    environment_vars = [
      "DEBIAN_FRONTEND=noninteractive",
      "PROJECT_DIR=${var.project_dest}",
    ]
  }

  # ── Post-processor: import into Proxmox ──────────────────────────

  post-processor "shell-local" {
    inline = [
      "bash post-processors/import-proxmox.sh '${var.vmid}' '${var.storage}' '${var.cores}' '${var.memory}' '${var.disk_size}' '${var.hostname}'",
    ]
  }
}
