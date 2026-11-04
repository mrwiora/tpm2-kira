# The vault of tools/vmtest.py: tpm2-kira-vault with a software TPM of its
# own. vmtest.py builds tpm2-kira-vault (static) into this directory's
# build context and runs the image with the vault's port published.
FROM archlinux:latest
RUN pacman -Sy --noconfirm --needed swtpm && pacman -Scc --noconfirm
COPY tpm2-kira-vault /usr/bin/tpm2-kira-vault
COPY entrypoint.sh /entrypoint.sh
EXPOSE 8443 8444
ENTRYPOINT ["/entrypoint.sh"]
