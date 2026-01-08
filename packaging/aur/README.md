# AUR Submission Guide for tpm2-kira

This directory contains the PKGBUILD for submitting `tpm2-kira` to the Arch User Repository (AUR).

## What is AUR?

The Arch User Repository (AUR) is a community-driven repository for Arch Linux users. It contains package descriptions (PKGBUILDs) that allow users to compile packages from source.

## Prerequisites

1. **AUR Account**: Register at https://aur.archlinux.org/register/
2. **SSH Key**: Add your SSH public key to your AUR account at https://aur.archlinux.org/account/
3. **Git**: Ensure git is installed
4. **makepkg**: Part of `base-devel` package group

## Files in This Directory

- **PKGBUILD**: The build script that describes how to build and package tpm2-kira
- **.SRCINFO**: Metadata file generated from PKGBUILD (must be kept in sync)

## How Version is Determined

The PKGBUILD uses the `pkgver()` function to automatically extract version from git tags:

```bash
pkgver() {
    cd "$pkgname"
    local git_tag=$(git describe --tags --exact-match 2>/dev/null)
    if [ -n "$git_tag" ]; then
        echo "${git_tag#v}"  # Removes 'v' prefix (e.g., v1.2.3 -> 1.2.3)
    else
        echo "0.0.0"  # Fallback if no tag
    fi
}
```

This means the package version automatically matches your git release tags.

## First-Time Submission to AUR

### Step 1: Test the PKGBUILD Locally

```bash
cd packaging/aur

# Build the package
makepkg -f

# Test installation
sudo pacman -U tpm2-kira-*.pkg.tar.zst

# Verify it works
tpm2-kira version

# Clean up
makepkg -c
sudo pacman -R tpm2-kira
```

### Step 2: Generate .SRCINFO

```bash
makepkg --printsrcinfo > .SRCINFO
```

**Important**: You must regenerate `.SRCINFO` every time you modify `PKGBUILD`.

### Step 3: Submit to AUR

```bash
# Clone the empty AUR repository
git clone ssh://aur@aur.archlinux.org/tpm2-kira.git ~/aur-tpm2-kira
cd ~/aur-tpm2-kira

# Copy PKGBUILD and .SRCINFO
cp /path/to/tpm2-kira/packaging/aur/PKGBUILD .
cp /path/to/tpm2-kira/packaging/aur/.SRCINFO .

# Commit and push
git add PKGBUILD .SRCINFO
git commit -m "Initial import of tpm2-kira"
git push origin master
```

### Step 4: Verify

Visit your package page: https://aur.archlinux.org/packages/tpm2-kira

Users can now install with:
```bash
# Using an AUR helper (yay, paru, etc.)
yay -S tpm2-kira

# Or manually
git clone https://aur.archlinux.org/tpm2-kira.git
cd tpm2-kira
makepkg -si
```

## Updating the Package

When you create a new git tag and release, the `pkgver()` function will automatically pick up the new version. However, you may need to update the PKGBUILD for dependency changes or build fixes.

### For New Versions

If only the version changed (new git tag):

```bash
cd ~/aur-tpm2-kira

# Increment pkgrel or make any necessary changes
nano PKGBUILD

# Regenerate .SRCINFO
makepkg --printsrcinfo > .SRCINFO

# Test build
makepkg -f

# Commit and push
git add PKGBUILD .SRCINFO
git commit -m "Update to version X.Y.Z"
git push origin master
```

### For Build Fixes (Same Version)

If you need to fix the PKGBUILD without changing the upstream version:

```bash
# Edit PKGBUILD and increment pkgrel
nano PKGBUILD  # Change pkgrel=1 to pkgrel=2

# Regenerate .SRCINFO
makepkg --printsrcinfo > .SRCINFO

# Test and push
makepkg -f
git add PKGBUILD .SRCINFO
git commit -m "Fix: description of fix"
git push origin master
```

## PKGBUILD Structure

### Key Variables

- `pkgname`: Package name (tpm2-kira)
- `pkgver`: Set to 0.0.0 initially, auto-updated by pkgver() function
- `pkgrel`: Release number, increment for PKGBUILD fixes
- `arch`: Supported architectures (x86_64)
- `depends`: Runtime dependencies
- `makedepends`: Build-time dependencies
- `source`: Source location (git repository)

### Key Functions

- `pkgver()`: Automatically extract version from git tags
- `prepare()`: Download dependencies before build
- `build()`: Compile the software
- `check()`: Run tests (optional but recommended)
- `package()`: Install files to package directory

## Common Commands

```bash
# Build package
makepkg -f

# Build and install
makepkg -si

# Generate .SRCINFO
makepkg --printsrcinfo > .SRCINFO

# Update checksums (not needed for git sources with SKIP)
updpkgsums

# Check package quality
namcap PKGBUILD
namcap *.pkg.tar.zst

# Clean build directory
makepkg -c
```

## Troubleshooting

### SSH Permission Denied

Ensure your SSH key is added to your AUR account:
```bash
# Test connection
ssh aur@aur.archlinux.org
# Should respond with: "Hi <username>, you've successfully authenticated..."
```

### Build Fails

```bash
# Install missing dependencies
makepkg -s

# Clean and rebuild
makepkg -c
makepkg -f
```

### .SRCINFO Out of Sync

Always regenerate after PKGBUILD changes:
```bash
makepkg --printsrcinfo > .SRCINFO
```

## GitHub Workflow Integration

The `.github/workflows/release.yml` workflow automatically:
1. Builds the package when you create a git tag
2. Tests the build
3. Uploads the package to GitHub releases

The workflow uses this same PKGBUILD file, so any changes here will affect the GitHub Actions build.

## Best Practices

1. **Test locally** before pushing to AUR
2. **Always regenerate .SRCINFO** after PKGBUILD changes
3. **Increment pkgrel** when fixing PKGBUILD without version change
4. **Reset pkgrel to 1** when version changes
5. **Monitor comments** on your AUR package page
6. **Respond promptly** to user-reported issues
7. **Follow Arch packaging guidelines**: https://wiki.archlinux.org/title/Arch_package_guidelines

## Resources

- **AUR Homepage**: https://aur.archlinux.org/
- **AUR Submission Guidelines**: https://wiki.archlinux.org/title/AUR_submission_guidelines
- **Arch Package Guidelines**: https://wiki.archlinux.org/title/Arch_package_guidelines
- **PKGBUILD Man Page**: `man PKGBUILD`
- **makepkg Man Page**: `man makepkg`

## Support

For help with:
- **AUR questions**: #archlinux-aur on Libera.Chat IRC
- **Packaging questions**: https://bbs.archlinux.org/
- **tpm2-kira issues**: https://github.com/mrwiora/tpm2-kira/issues

## License

This PKGBUILD is part of the tpm2-kira project and is licensed under BSD-3-Clause.