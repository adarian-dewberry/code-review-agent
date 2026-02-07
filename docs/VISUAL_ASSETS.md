# Visual Assets Guide

## Header Image for README

### Design Specifications

**Dimensions**: 1200px × 400px  
**Format**: PNG with transparency or JPG  
**File location**: `docs/images/header.png`

### Suggested Design Elements

**Core Components:**
1. **Title**: "Code Review Agent" (bold, professional sans-serif like Inter or Helvetica)
2. **Tagline**: "Shift-Left Security for AI-Powered Development"
3. **Visual Elements**:
   - Shield icon (security)
   - Code bracket symbols `{ }`
   - Checkmark or validation icon
   - Subtle gradient (blue to purple or dark blue)

**Color Palette:**
- Primary: `#0066CC` (Trust Blue)
- Secondary: `#6C3FD9` (Security Purple)
- Accent: `#00C853` (Success Green for checkmarks)
- Background: `#F8F9FA` (Light Gray) or Dark Theme `#1A1A1A`

### Tools to Create

**Free/Easy:**
1. **Canva** (https://canva.com)
   - Template: "LinkedIn Banner" → resize to 1200x400
   - Search "cybersecurity" or "code" templates
   - Customize text and colors

2. **Figma** (https://figma.com)
   - Professional design tool
   - More control over layout
   - Export as PNG at 2x resolution for retina displays

3. **Adobe Express** (https://adobe.com/express)
   - Quick banner creator
   - Many tech/security templates

### Example Text Layout

```
┌──────────────────────────────────────────────────────────┐
│                                                          │
│    🛡️  CODE REVIEW AGENT                                │
│                                                          │
│    Shift-Left Security: Catch Vulnerabilities           │
│    Before They Cost $100K to Fix                        │
│                                                          │
│    [OWASP Top 10]  [CWE Mapped]  [AI-Powered]          │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### Once Created

1. Save as `docs/images/header.png`
2. Update README.md line 3 to:
   ```markdown
   ![Code Review Agent Header](docs/images/header.png)
   ```
3. Commit: `git add docs/images/header.png README.md && git commit -m "feat: add branded header image"`

### Alternative: ASCII Art (No Image Needed)

If you prefer text-only (works everywhere, including terminals):

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     ██████╗ ██████╗ ██████╗ ███████╗                     ║
║    ██╔════╝██╔═══██╗██╔══██╗██╔════╝                     ║
║    ██║     ██║   ██║██║  ██║█████╗                       ║
║    ██║     ██║   ██║██║  ██║██╔══╝                       ║
║    ╚██████╗╚██████╔╝██████╔╝███████╗                     ║
║     ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝                     ║
║                                                           ║
║     REVIEW AGENT - Shift-Left Security                   ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
```

### Brand Consistency

**Fonts:**
- Headers: Inter Bold or SF Pro Display
- Body: Inter Regular or System UI

**Voice:**
- Professional but approachable
- Focus on ROI and business outcomes
- Use quantified metrics (95% reduction, $244K savings)

**Key Messaging:**
- "Shift-Left Security"
- "Remediation Cost Multiplier"
- "Catch vulnerabilities before they cost $100K"
- "OWASP/CWE mapped for audit readiness"
