#!/usr/bin/env bash
# ================================================================
# WazuhBOTS — Export SVG assets to PNG/ICO formats
# Requires: inkscape or rsvg-convert, imagemagick (for ICO)
# ================================================================

set -euo pipefail

BRAND_DIR="$(cd "$(dirname "$0")" && pwd)"
EXPORT_DIR="${BRAND_DIR}/exports"

# Colors for output
BLUE='\033[38;2;59;130;246m'
CYAN='\033[38;2;6;182;212m'
GREEN='\033[38;2;34;197;94m'
DIM='\033[38;2;148;163;184m'
RESET='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════╗${RESET}"
echo -e "${BLUE}║${RESET}  ${CYAN}WazuhBOTS Asset Export${RESET}              ${BLUE}║${RESET}"
echo -e "${BLUE}╚══════════════════════════════════════╝${RESET}"
echo ""

# Detect available converter
CONVERTER=""
if command -v inkscape &>/dev/null; then
    CONVERTER="inkscape"
    echo -e "${GREEN}✓${RESET} Using Inkscape for SVG conversion"
elif command -v rsvg-convert &>/dev/null; then
    CONVERTER="rsvg"
    echo -e "${GREEN}✓${RESET} Using rsvg-convert for SVG conversion"
else
    echo -e "${DIM}⚠ No SVG converter found. Install inkscape or librsvg2-bin${RESET}"
    echo "  sudo pacman -S inkscape   # or"
    echo "  sudo pacman -S librsvg"
    exit 1
fi

# Create export directories
mkdir -p "${EXPORT_DIR}"/{logos,icons,favicons,banners,badges,social}

convert_svg() {
    local input="$1"
    local output="$2"
    local width="$3"
    local height="${4:-$width}"

    if [[ "$CONVERTER" == "inkscape" ]]; then
        inkscape -w "$width" -h "$height" "$input" -o "$output" 2>/dev/null
    else
        rsvg-convert -w "$width" -h "$height" "$input" > "$output"
    fi
}

echo ""
echo -e "${CYAN}── Logos ──${RESET}"

convert_svg "${BRAND_DIR}/logo/wazuhbots-logo.svg" "${EXPORT_DIR}/logos/logo-dark-800.png" 800 240
echo -e "  ${GREEN}✓${RESET} logo-dark-800.png"

convert_svg "${BRAND_DIR}/logo/wazuhbots-logo.svg" "${EXPORT_DIR}/logos/logo-dark-1600.png" 1600 480
echo -e "  ${GREEN}✓${RESET} logo-dark-1600.png"

convert_svg "${BRAND_DIR}/logo/wazuhbots-logo-light.svg" "${EXPORT_DIR}/logos/logo-light-800.png" 800 240
echo -e "  ${GREEN}✓${RESET} logo-light-800.png"

convert_svg "${BRAND_DIR}/logo/wazuhbots-logo-light.svg" "${EXPORT_DIR}/logos/logo-light-1600.png" 1600 480
echo -e "  ${GREEN}✓${RESET} logo-light-1600.png"

echo ""
echo -e "${CYAN}── Icons ──${RESET}"

for size in 64 128 256 512; do
    convert_svg "${BRAND_DIR}/logo/wazuhbots-icon.svg" "${EXPORT_DIR}/icons/icon-${size}.png" "$size"
    echo -e "  ${GREEN}✓${RESET} icon-${size}.png"
done

echo ""
echo -e "${CYAN}── Favicons ──${RESET}"

for size in 16 32 48 64 128 192 256 512; do
    convert_svg "${BRAND_DIR}/logo/wazuhbots-favicon.svg" "${EXPORT_DIR}/favicons/favicon-${size}.png" "$size"
    echo -e "  ${GREEN}✓${RESET} favicon-${size}.png"
done

# Generate ICO if ImageMagick is available
if command -v convert &>/dev/null; then
    convert "${EXPORT_DIR}/favicons/favicon-16.png" \
            "${EXPORT_DIR}/favicons/favicon-32.png" \
            "${EXPORT_DIR}/favicons/favicon-48.png" \
            "${EXPORT_DIR}/favicons/favicon.ico"
    echo -e "  ${GREEN}✓${RESET} favicon.ico"
fi

echo ""
echo -e "${CYAN}── Banners ──${RESET}"

convert_svg "${BRAND_DIR}/banners/banner-github.svg" "${EXPORT_DIR}/banners/banner-github.png" 1280 320
echo -e "  ${GREEN}✓${RESET} banner-github.png (1280×320)"

convert_svg "${BRAND_DIR}/banners/banner-social.svg" "${EXPORT_DIR}/social/og-image.png" 1200 630
echo -e "  ${GREEN}✓${RESET} og-image.png (1200×630)"

echo ""
echo -e "${CYAN}── Badges ──${RESET}"

for scenario in s1-dark-harvest s2-iron-gate s3-ghost-shell s4-supply-chain; do
    convert_svg "${BRAND_DIR}/badges/scenarios/${scenario}.svg" "${EXPORT_DIR}/badges/${scenario}.png" 280 80
    echo -e "  ${GREEN}✓${RESET} ${scenario}.png"
done

for level in pup hunter alpha fenrir; do
    convert_svg "${BRAND_DIR}/badges/difficulty/${level}.svg" "${EXPORT_DIR}/badges/${level}.png" 160
    echo -e "  ${GREEN}✓${RESET} ${level}.png"
done

echo ""
echo -e "${GREEN}══════════════════════════════════════${RESET}"
echo -e "${GREEN}✓ All assets exported to:${RESET}"
echo -e "  ${CYAN}${EXPORT_DIR}/${RESET}"
echo ""
echo -e "${DIM}Total files: $(find "${EXPORT_DIR}" -type f | wc -l)${RESET}"
