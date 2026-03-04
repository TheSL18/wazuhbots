# WazuhBOTS Brand Guide

## Brand Identity

**WazuhBOTS** is an open-source Boss of the SOC (BOTS) CTF platform built on Wazuh SIEM.
The brand combines cybersecurity aesthetics with Norse wolf mythology, reflecting the
progression system (Pup → Hunter → Alpha → Fenrir) and the SOC analyst's journey.

---

## Logo System

### Primary Logo
- **File:** `logo/wazuhbots-logo.svg` — Full horizontal logo (dark background)
- **File:** `logo/wazuhbots-logo-light.svg` — Full horizontal logo (light background)
- **Usage:** Website headers, documentation, presentations

### Icon Mark
- **File:** `logo/wazuhbots-icon.svg` — Circular wolf mark
- **Usage:** Avatars, app icons, small placements
- **Minimum size:** 32x32px

### Favicon
- **File:** `logo/wazuhbots-favicon.svg` — Optimized for small sizes
- **Usage:** Browser tabs, bookmarks
- **Recommended export:** 16x16, 32x32, 48x48, 192x192 PNG

### Clear Space
- Maintain a clear space of at least 1x the wolf icon height around the logo
- Never stretch, rotate, or modify the logo proportions

---

## Color Palette

### Primary Colors
| Name        | Hex       | RGB              | Usage                          |
|-------------|-----------|------------------|--------------------------------|
| Accent Blue | `#3b82f6` | `59, 130, 246`   | Primary brand, links, CTAs     |
| Accent Cyan | `#06b6d4` | `6, 182, 212`    | Secondary accent, highlights   |

### Background Colors
| Name        | Hex       | RGB              | Usage                          |
|-------------|-----------|------------------|--------------------------------|
| BG Dark     | `#0a0e17` | `10, 14, 23`     | Primary background             |
| BG Card     | `#111827` | `17, 24, 39`     | Card/panel backgrounds         |
| BG Card 2   | `#1a2236` | `26, 34, 54`     | Elevated surfaces              |
| Border      | `#1e293b` | `30, 41, 59`     | Borders, dividers              |

### Text Colors
| Name        | Hex       | RGB              | Usage                          |
|-------------|-----------|------------------|--------------------------------|
| Text        | `#e2e8f0` | `226, 232, 240`  | Primary text                   |
| Text Dim    | `#94a3b8` | `148, 163, 184`  | Secondary/muted text           |
| Text Subtle | `#64748b` | `100, 116, 139`  | Hints, metadata                |

### Difficulty Level Colors
| Level   | Hex       | RGB              | Star Rating |
|---------|-----------|------------------|-------------|
| Pup     | `#22c55e` | `34, 197, 94`    | ★☆☆☆        |
| Hunter  | `#3b82f6` | `59, 130, 246`   | ★★☆☆        |
| Alpha   | `#f59e0b` | `245, 158, 11`   | ★★★☆        |
| Fenrir  | `#ef4444` | `239, 68, 68`    | ★★★★        |

### Scenario Colors
| Scenario       | Hex       | Category                   |
|----------------|-----------|----------------------------|
| Dark Harvest   | `#ef4444` | Web Application Attack     |
| Iron Gate      | `#a855f7` | Active Directory Compromise|
| Ghost Shell    | `#22c55e` | Linux Server Intrusion     |
| Supply Chain   | `#f59e0b` | Advanced Persistent Threat |

### Utility Colors
| Name    | Hex       | Usage                                |
|---------|-----------|--------------------------------------|
| Green   | `#22c55e` | Success, correct answers             |
| Amber   | `#f59e0b` | Warnings, hints                      |
| Red     | `#ef4444` | Errors, critical, high severity      |
| Purple  | `#a855f7` | Special, premium, AD-related         |

---

## Typography

### Font Stack
```css
/* Primary (UI) */
font-family: 'Segoe UI', 'SF Pro Display', system-ui, -apple-system, sans-serif;

/* Monospace (code, data, terminals) */
font-family: 'SF Mono', 'Cascadia Code', 'JetBrains Mono', 'Fira Code', monospace;

/* Display/Certificates */
font-family: 'Georgia', 'Times New Roman', serif;
```

### Font Weights
- **800-900:** Headlines, logo text "BOTS"
- **700:** Section titles, labels
- **600:** Subtitles, emphasis, tags
- **400:** Body text, descriptions

### Size Scale
| Element         | Size     | Weight |
|-----------------|----------|--------|
| Logo text       | 72px     | 800    |
| H1              | 2.2rem   | 800    |
| H2              | 1.5rem   | 700    |
| H3              | 1.2rem   | 600    |
| Body            | 1rem     | 400    |
| Labels          | 0.75rem  | 700    |
| Code/Mono       | 0.875rem | 400    |

---

## Gradients

### Primary Gradient
```css
background: linear-gradient(135deg, #3b82f6, #06b6d4);
```
Used for: Text gradients, accent borders, CTAs

### Fenrir Fire Gradient
```css
background: linear-gradient(to top, #ef4444, #f97316, #fbbf24);
```
Used for: Fenrir difficulty only

### Gold Gradient (Certificates)
```css
background: linear-gradient(135deg, #fbbf24, #f59e0b, #d97706);
```
Used for: Certificate borders, achievement seals

### Glow Effect
```css
box-shadow: 0 0 40px rgba(59, 130, 246, 0.15);
```
Used for: Card hover, active elements

---

## Design Elements

### Grid Pattern
- 60px grid on hero sections, 40px on banners, 30px on certificates
- Color: `#1e293b` at 3-5% opacity
- Masked with radial gradient for fade effect

### Circuit Lines
- 1px stroke, `#3b82f6` at 15-30% opacity
- Terminal dots: 2-3px radius at line endpoints
- Used sparingly for cybersecurity aesthetic

### Corner Decorations
- L-shaped brackets at corners (20px arms)
- Stroke: `url(#wolfGrad)` or `#3b82f6` at 20% opacity

### Border Radius
- Cards: `12px`
- Buttons/Pills: `9999px` (fully rounded)
- Tags/Badges: `9-13px`
- Inputs: `8px`

---

## Asset Inventory

### Logos
```
branding/
├── logo/
│   ├── wazuhbots-logo.svg          # Primary horizontal (dark bg)
│   ├── wazuhbots-logo-light.svg    # Primary horizontal (light bg)
│   ├── wazuhbots-icon.svg          # Circular icon mark
│   └── wazuhbots-favicon.svg       # Favicon optimized
```

### Badges
```
├── badges/
│   ├── scenarios/
│   │   ├── s1-dark-harvest.svg     # Red - Web Attack
│   │   ├── s2-iron-gate.svg        # Purple - AD
│   │   ├── s3-ghost-shell.svg      # Green - Linux
│   │   └── s4-supply-chain.svg     # Amber - APT
│   └── difficulty/
│       ├── pup.svg                 # Green - 100pts ★☆☆☆
│       ├── hunter.svg              # Blue - 200pts ★★☆☆
│       ├── alpha.svg               # Amber - 300pts ★★★☆
│       └── fenrir.svg              # Red - 500pts ★★★★
```

### Banners
```
├── banners/
│   ├── banner-github.svg           # 1280×320 README banner
│   └── banner-social.svg           # 1200×630 OG/Twitter card
```

### Certificates
```
├── certificates/
│   └── certificate-template.svg    # Completion certificate
│       Placeholders: {{PARTICIPANT_NAME}}, {{ACHIEVEMENT_LEVEL}},
│       {{SCORE}}, {{RANK}}, {{SOLVED}}, {{DATE}}, {{CERT_ID}}
```

### ASCII Art
```
├── ascii/
│   ├── banner.txt                  # Full ASCII banner with wolf
│   ├── banner-compact.txt          # Compact single-line banner
│   └── wolf.txt                    # Wolf art standalone
```

---

## Usage Guidelines

### Do
- Use the logo on dark backgrounds (`#0a0e17` to `#111827`)
- Maintain the blue-cyan gradient as the primary brand identifier
- Use difficulty colors consistently across all interfaces
- Keep the geometric/polygonal wolf style for all wolf representations

### Don't
- Place the dark logo on light backgrounds (use `-light` variant)
- Mix difficulty colors (green ≠ Fenrir, red ≠ Pup)
- Use the wolf icon smaller than 32x32px
- Add effects like drop shadows or outlines to the logo
- Rotate or stretch the logo
- Modify the wolf icon geometry

### CTFd Integration
- Use `wazuhbots-favicon.svg` as the CTFd site icon
- Apply the color palette via CTFd custom CSS
- Use scenario badges in challenge descriptions
- Use difficulty badges for level indicators

### Terminal/CLI
- Use `ascii/banner-compact.txt` for script headers
- Use `ascii/banner.txt` for welcome screens
- ANSI color codes: Blue=`\033[38;2;59;130;246m`, Cyan=`\033[38;2;6;182;212m`

---

## CSS Variables (Copy-Paste Ready)

```css
:root {
  /* Backgrounds */
  --bg:        #0a0e17;
  --bg-card:   #111827;
  --bg-card2:  #1a2236;
  --border:    #1e293b;

  /* Text */
  --text:      #e2e8f0;
  --text-dim:  #94a3b8;
  --text-sub:  #64748b;

  /* Brand */
  --accent:    #3b82f6;
  --accent2:   #06b6d4;

  /* Difficulty */
  --pup:       #22c55e;
  --hunter:    #3b82f6;
  --alpha:     #f59e0b;
  --fenrir:    #ef4444;

  /* Scenarios */
  --s1:        #ef4444;
  --s2:        #a855f7;
  --s3:        #22c55e;
  --s4:        #f59e0b;

  /* Utilities */
  --green:     #22c55e;
  --amber:     #f59e0b;
  --red:       #ef4444;
  --purple:    #a855f7;

  /* Effects */
  --radius:    12px;
  --glow:      0 0 40px rgba(59, 130, 246, 0.15);
}
```

---

## Export Guide

### SVG → PNG Conversion
```bash
# Using Inkscape (recommended)
inkscape -w 1280 -h 320 banner-github.svg -o banner-github.png
inkscape -w 256 -h 256 wazuhbots-icon.svg -o icon-256.png
inkscape -w 32 -h 32 wazuhbots-favicon.svg -o favicon-32.png

# Using rsvg-convert
rsvg-convert -w 1280 banner-github.svg > banner-github.png

# Generate ICO from favicon
convert favicon-32.png favicon-16.png favicon-48.png favicon.ico
```

### Favicon Set
```bash
# Generate all favicon sizes
for size in 16 32 48 64 128 192 256 512; do
  inkscape -w $size -h $size wazuhbots-favicon.svg -o "favicon-${size}.png"
done
```

---

*WazuhBOTS Brand Guide v1.0 — Created by MrHacker (Kevin Muñoz)*
*Wazuh Technology Ambassador Program*
