# Installation Guide for tpm2-kira

## Overview

`tpm2-kira` is a TPM2-based TOTP authenticator that can be installed on:
- **Arch Linux** and derivatives (Manjaro, EndeavourOS, etc.)

It is the successor of tpm2-totp and currently in alpha phase. Please use with CAUTION!

## Security

This project uses automated AI-powered penetration testing with [Strix](https://strix.ai) to identify and validate security vulnerabilities on every pull request. For more information, see our [Security Policy](SECURITY.md).

## System Requirements

### Hardware Requirements
- **TPM 2.0** chip (hardware TPM recommended, software TPM supported for testing)
- x86_64, i686, aarch64, or armv7h architecture

### Software Requirements
- Linux kernel with TPM 2.0 support
- TPM 2.0 Software Stack (TSS 2.x)
- TPM 2.0 tools

## Pre-Installation Setup

### 1. Enable TPM in BIOS/UEFI
1. Boot into your system's BIOS/UEFI settings
2. Navigate to Security settings
3. Enable TPM 2.0 (may be called "Security Chip" or "fTPM")
4. Save and reboot

### 2. Verify TPM Availability
```bash
# Check if TPM device exists
ls /dev/tpm*

# Should show: /dev/tpm0 and possibly /dev/tpmrm0

# Check TPM version
sudo dmesg | grep -i tpm
```

## Installation Methods

### Arch Linux Installation

#### Method 1: Build from Source
```bash
# Install build dependencies
sudo pacman -S base-devel go git tpm2-tools tpm2-tss

# Clone repository
git clone https://github.com/mrwiora/tpm2-kira.git
cd tpm2-kira

# Build package
cd packaging/aur
makepkg

# Install built package
sudo pacman -U tpm2-kira-*.pkg.tar.zst
```

## Post-Installation Setup

### 1. Verify Installation
```bash
# Check version
tpm2-kira version

# Test TPM access
tpm2-kira nvram list

# Check TPM status
tpm2-kira info
```

### 2. Initial Setup
```bash
# Seal your first TOTP secret (you'll be prompted for an optional password)
tpm2-kira seal

# The command will display a QR code and secret key
# Add this to your authenticator app (Google Authenticator, Authy, etc.)

# Test TOTP generation
tpm2-kira reveal
```

## Integration Options

### Early Boot Integration (Optional)

For using tpm2-kira during early boot (e.g., for disk encryption):

#### Arch Linux with mkinitcpio
```bash
# Edit mkinitcpio configuration
sudo nano /etc/mkinitcpio.conf

# For systemd-based initramfs:
# HOOKS=(base systemd autodetect modconf block keyboard sd-tpm2-kira sd-encrypt filesystems fsck)

# Rebuild initramfs
sudo mkinitcpio -P
```

## Configuration

### Default Configuration
- TPM Device: `/dev/tpm0`
- NVRAM Index: `0x01803010`
- Default PCRs: `0,2,4,7` (firmware, boot config, bootloader, Secure Boot)

### Custom Configuration
```bash
# Use different TPM device (you'll be prompted for password)
tpm2-kira --tpm /dev/tpmrm0 seal

# Use different NVRAM index (you'll be prompted for password)
tpm2-kira --nvram 0x01800001 seal

# Use different PCRs (you'll be prompted for password)
tpm2-kira seal --pcrs "0,1,2,3,7"
```

## Common Workflows

### Daily Usage
```bash
# Generate TOTP code
tpm2-kira reveal

# If PCRs changed (after system update), you'll be prompted for password:
tpm2-kira reveal
```

### After System Updates
```bash
# Check if reseal is needed
tpm2-kira info

# Reseal with current PCR values (you'll be prompted for password)
tpm2-kira reseal
```

### Backup and Recovery
```bash
# Display secret information for backup
tpm2-kira info

# After hardware change or TPM reset:
# 1. Import secret to new authenticator app
# 2. Seal new secret (you'll be prompted for password):
tpm2-kira seal
```

## Troubleshooting

### Permission Issues
```bash
# Check TPM device permissions
ls -la /dev/tpm*
```

### TPM Access Issues
```bash
# Test basic TPM functionality
tpm2_getrandom 8

# Check TPM ownership
tpm2_getcap properties-fixed

# Clear TPM if necessary (CAUTION: destroys all TPM data)
# tpm2_clear
```

### PCR Issues
```bash
# Check current PCR values
tpm2_pcrread

# Compare with sealed values
tpm2-kira info

# Reseal after updates (you'll be prompted for password)
tpm2-kira reseal
```

### General Debugging
```bash
# Enable debug output
tpm2-kira --debug reveal

# Check system logs
journalctl -u tpm2-kira
sudo dmesg | grep -i tpm
```

## Uninstallation

### Arch Linux
```bash
# Remove package
sudo pacman -R tpm2-kira

# Clean up TPM data (optional)
tpm2-kira nvram delete  # Run before uninstalling
```
