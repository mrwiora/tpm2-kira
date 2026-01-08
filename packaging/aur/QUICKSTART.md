# AUR Quick Start for tpm2-kira

## One-Time Setup (5 minutes)

1. **Create AUR account**: https://aur.archlinux.org/register/
2. **Add SSH key to AUR**: https://aur.archlinux.org/account/
3. **Test SSH**: `ssh aur@aur.archlinux.org`

## First Submission

```bash
# 1. Generate .SRCINFO
cd packaging/aur
makepkg --printsrcinfo > .SRCINFO

# 2. Test build
makepkg -f
sudo pacman -U tpm2-kira-*.pkg.tar.zst
tpm2-kira version
makepkg -c && sudo pacman -R tpm2-kira

# 3. Submit to AUR
git clone ssh://aur@aur.archlinux.org/tpm2-kira.git ~/aur-tpm2-kira
cd ~/aur-tpm2-kira
cp /path/to/tpm2-kira/packaging/aur/{PKGBUILD,.SRCINFO} .
git add PKGBUILD .SRCINFO
git commit -m "Initial import of tpm2-kira"
git push origin master
```

## Updating Package

```bash
# When you need to update PKGBUILD
cd ~/aur-tpm2-kira
nano PKGBUILD  # Make changes, increment pkgrel if needed
makepkg --printsrcinfo > .SRCINFO
makepkg -f  # Test
git add PKGBUILD .SRCINFO
git commit -m "Update: description of changes"
git push origin master
```

## Key Points

- **Version**: Automatically extracted from git tags via `pkgver()` function
- **.SRCINFO**: MUST regenerate after ANY PKGBUILD change
- **pkgrel**: Increment for fixes, reset to 1 for new versions
- **Test**: Always test build locally before pushing

## Essential Commands

```bash
makepkg -f                        # Build package
makepkg -si                       # Build and install
makepkg --printsrcinfo > .SRCINFO # Generate .SRCINFO
namcap PKGBUILD                   # Check quality
makepkg -c                        # Clean build files
```

## Troubleshooting

**SSH fails**: Check your SSH key is added to AUR account  
**Build fails**: Run `makepkg -s` to install dependencies  
**.SRCINFO mismatch**: Always regenerate: `makepkg --printsrcinfo > .SRCINFO`

## Resources

- Full guide: [README.md](README.md)
- AUR guidelines: https://wiki.archlinux.org/title/AUR_submission_guidelines
- Your package: https://aur.archlinux.org/packages/tpm2-kira

## After Submission

Users install with:
```bash
yay -S tpm2-kira
# or
git clone https://aur.archlinux.org/tpm2-kira.git && cd tpm2-kira && makepkg -si
```
