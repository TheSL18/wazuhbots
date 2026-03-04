# WazuhBOTS — Packer LXC Template Makefile
# Usage:
#   make validate   — Check HCL syntax
#   make build      — Build the LXC template
#   make clean      — Remove build artifacts

.PHONY: validate build clean init

init:
	packer init .

validate: init
	packer validate .

build: init
	packer build .

clean:
	rm -rf output/
	@echo "Build artifacts cleaned."
