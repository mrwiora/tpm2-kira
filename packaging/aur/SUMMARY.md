# AUR Preparation Summary

This document summarizes the changes made to prepare tpm2-kira for AUR (Arch User Repository) submission.

## Changes Made

### 1. Directory Restructure
- **Renamed**: `packaging/archlinux/` → `packaging/aur/`
- **Reason**: AUR is the proper distribution channel for Arch Linux packages

### 2. Files in packaging/aur/

#### PKGBUILD (existing, unchanged)
The main build script that:
- Uses `pkgver()` function to automatically extract version from git tags
- Removes 'v' prefix from tags (e.g., v1.2.3 → 1.2.3)
- Falls back to 0.0.0 if no tag is found
- Builds from git source: `source=("$pkgname::git+https://github.com/mrwiora/tpm2-kira.git")`
- Uses `sha256sums=('SKIP')` for git sources (standard practice)
- Includes all necessary dependencies and build steps

#### .SRCINFO (generated)
Metadata file required by AUR:
- Generated from PKGBUILD using: `makepkg --printsrcinfo > .SRCINFO`
- **MUST** be regenerated every time PKGBUILD is modified
- Contains package metadata in a parseable format for AUR web interface

#### README.md (new)
Comprehensive guide covering:
- What AUR is and how it works
- Prerequisites for AUR submission
- How version detection works via `pkgver()` function
- Step-by-step first-time submission
- Updating existing packages
- PKGBUILD structure explanation
- Common commands and troubleshooting
- Best practices

#### QUICKSTART.md (new)
Condensed quick-reference guide:
- One-time setup steps
- First submission commands
- Update workflow
- Key points and essential commands
- Common troubleshooting

## Updated Files

### .github/workflows/release.yml
Changed all references from `packaging/archlinux` to `packaging/aur`:
- Lines 122, 132, 141, 146, 167, 176-177

### Makefile
Updated `pkgbuild` target to use new directory:
- Build directory: `build/archlinux` → `build/aur`
- Source path: `packaging/archlinux` → `packaging/aur`
- Lines 166-174

### README.md
Updated installation instructions:
- Changed path from `packaging/archlinux` to `packaging/aur`
- Line 54

## How Version Works

The PKGBUILD uses a `pkgver()` function that automatically determines the version:

```bash
pkgver() {
    cd "$pkgname"
    local git_tag=$(git describe --tags --exact-match 2>/dev/null)
    if [ -n "$git_tag" ]; then
        echo "${git_tag#v}"  # Remove 'v' prefix
    else
        echo "0.0.0"  # Fallback
    fi
}
```

**This means:**
- When you tag a release (e.g., `git tag v1.0.0`), the package version becomes `1.0.0`
- No manual version updates needed in PKGBUILD
- The pkgver in PKGBUILD (set to 0.0.0) is just a placeholder
- Actual version is determined dynamically during build

## AUR Submission Process

### Initial Submission
1. Generate .SRCINFO: `makepkg --printsrcinfo > .SRCINFO`
2. Test locally: `makepkg -f && sudo pacman -U tpm2-kira-*.pkg.tar.zst`
3. Clone AUR repo: `git clone ssh://aur@aur.archlinux.org/tpm2-kira.git`
4. Copy PKGBUILD and .SRCINFO
5. Push: `git add PKGBUILD .SRCINFO && git commit -m "..." && git push`

### Updates
1. Modify PKGBUILD if needed (usually just increment `pkgrel`)
2. Regenerate .SRCINFO: `makepkg --printsrcinfo > .SRCINFO`
3. Test build
4. Push changes

## Key Points

- **Version is automatic**: Extracted from git tags via `pkgver()` function
- **.SRCINFO is critical**: Must regenerate after any PKGBUILD change
- **pkgrel usage**: 
  - Increment when fixing PKGBUILD without version change
  - Reset to 1 when upstream version changes
- **Git source**: Uses git repository directly (not release tarballs)
- **No checksums needed**: `SKIP` is standard for git sources

## Files Structure

```
packaging/aur/
├── PKGBUILD         # Build script (the core file)
├── .SRCINFO         # Generated metadata (for AUR)
├── README.md        # Comprehensive guide
├── QUICKSTART.md    # Quick reference
└── SUMMARY.md       # This file
```

## GitHub Workflow

The release workflow (`release.yml`):
1. Triggers on git tag push
2. Temporarily updates PKGBUILD version for the build
3. Builds the package in Arch Linux container
4. Tests and validates the package
5. Uploads to GitHub releases

This workflow tests the PKGBUILD but doesn't affect AUR. AUR updates are manual.

## Next Steps

1. **Create AUR account**: https://aur.archlinux.org/register/
2. **Add SSH key**: https://aur.archlinux.org/account/
3. **Test SSH**: `ssh aur@aur.archlinux.org`
4. **Follow QUICKSTART.md** for submission

## Resources

- AUR Homepage: https://aur.archlinux.org/
- AUR Guidelines: https://wiki.archlinux.org/title/AUR_submission_guidelines
- Package Guidelines: https://wiki.archlinux.org/title/Arch_package_guidelines
- Your future package: https://aur.archlinux.org/packages/tpm2-kira

## Notes

- The package name `tpm2-kira` must be available on AUR (check first)
- Consider creating a `-git` variant later for development versions
- Monitor package comments on AUR for user feedback
- Keep .SRCINFO in sync with PKGBUILD always