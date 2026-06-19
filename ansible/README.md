# Ansible — Backup Admin Deployment

Deploys a backup admin account to every Linux and Windows machine at once.
Run this early in competition so you always have a recovery account if red team locks you out.

---

## Before Competition — One-Time Setup

### 1. Install Ansible (on your attack/ops machine)
```bash
# Ubuntu/Debian
sudo apt install ansible

# pip (any OS)
pip install ansible pywinrm
```

### 2. Generate your backup SSH keypair
```bash
ssh-keygen -t ed25519 -f ~/.ssh/ccdc_backup -C "ccdc_backup"
# This creates:
#   ~/.ssh/ccdc_backup      (private key — never share this)
#   ~/.ssh/ccdc_backup.pub  (public key — paste into vars.yml)
```

### 3. Edit `vars.yml`
```yaml
backup_admin_username: "ccdc_backup"
backup_admin_password: "YourStrongPassword!"
backup_admin_ssh_pubkey: "ssh-ed25519 AAAA... ccdc_backup"   # paste .pub contents here
backup_admin_nopasswd_sudo: true
```

### 4. Edit `inventory.ini`
Fill in actual IPs for all Linux and Windows boxes.
Set the Windows `ansible_password` to your Windows Administrator password.

---

## Competition Usage

```bash
# Deploy to ALL machines at once
ansible-playbook -i inventory.ini create_admin.yml

# Linux only
ansible-playbook -i inventory.ini create_admin.yml --limit linux

# Windows only
ansible-playbook -i inventory.ini create_admin.yml --limit windows

# Single machine
ansible-playbook -i inventory.ini create_admin.yml --limit web01

# Dry run (check what would happen, no changes made)
ansible-playbook -i inventory.ini create_admin.yml --check
```

---

## Connecting with the backup account after deployment

```bash
# Linux — SSH with key (no password needed)
ssh -i ~/.ssh/ccdc_backup ccdc_backup@10.0.0.10

# Linux — become root immediately
ssh -i ~/.ssh/ccdc_backup ccdc_backup@10.0.0.10 "sudo -i"

# Windows — RDP
# Use mstsc or Remmina with username: ccdc_backup and your password
```

---

## Windows WinRM — if it's not already enabled

Run this on the Windows machine manually if WinRM isn't accepting connections:
```powershell
# Enable WinRM
winrm quickconfig -force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# Or use the Ansible setup script
Invoke-WebRequest -Uri https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1 -OutFile ConfigureRemotingForAnsible.ps1
powershell -ExecutionPolicy RemoteSigned .\ConfigureRemotingForAnsible.ps1
```

---

## What gets created

**On Linux:**
- User account with home directory and bash shell
- Added to `sudo` (Debian) or `wheel` (RHEL) group
- `/etc/sudoers.d/ccdc_backup` granting full sudo (NOPASSWD if configured)
- SSH authorized key for passwordless access

**On Windows:**
- Local user account with non-expiring password
- Added to `Administrators` group
- Added to `Remote Desktop Users` group
- Account unlocked and enabled
