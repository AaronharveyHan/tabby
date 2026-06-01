import * as keytar from 'keytar'
import { Injectable, Inject, Optional } from '@angular/core'
import { VaultService } from 'tabby-core'
import { SSHProfile, SSH_VAULT_BACKEND, SSHVaultBackend } from '../api'

export const VAULT_SECRET_TYPE_PASSWORD = 'ssh:password'
export const VAULT_SECRET_TYPE_PASSPHRASE = 'ssh:key-passphrase'

@Injectable({ providedIn: 'root' })
export class PasswordStorageService {
    constructor (
        private vault: VaultService,
        @Optional() @Inject(SSH_VAULT_BACKEND) private vaultBackend: SSHVaultBackend | null,
    ) { }

    async savePassword (profile: SSHProfile, password: string, username?: string): Promise<void> {
        const account = username ?? profile.options.user
        if (this.vaultBackend) {
            await this.vaultBackend.savePassword(this.getBackendKeyForConnection(profile, account), password)
            return
        }
        if (this.vault.isEnabled()) {
            const key = this.getVaultKeyForConnection(profile, account)
            this.vault.addSecret({ type: VAULT_SECRET_TYPE_PASSWORD, key, value: password })
        } else {
            if (!account) {
                return
            }
            const key = this.getKeytarKeyForConnection(profile)
            return keytar.setPassword(key, account, password)
        }
    }

    async deletePassword (profile: SSHProfile, username?: string): Promise<void> {
        const account = username ?? profile.options.user
        if (this.vaultBackend) {
            await this.vaultBackend.deletePassword(this.getBackendKeyForConnection(profile, account))
            return
        }
        if (this.vault.isEnabled()) {
            const key = this.getVaultKeyForConnection(profile, account)
            this.vault.removeSecret(VAULT_SECRET_TYPE_PASSWORD, key)
        } else {
            if (!account) {
                return
            }
            const key = this.getKeytarKeyForConnection(profile)
            await keytar.deletePassword(key, account)
        }
    }

    async loadPassword (profile: SSHProfile, username?: string): Promise<string|null> {
        const account = username ?? profile.options.user
        if (this.vaultBackend) {
            return this.vaultBackend.loadPassword(this.getBackendKeyForConnection(profile, account))
        }
        if (this.vault.isEnabled()) {
            const key = this.getVaultKeyForConnection(profile, account)
            return (await this.vault.getSecret(VAULT_SECRET_TYPE_PASSWORD, key))?.value ?? null
        } else {
            if (!account) {
                return null
            }
            const key = this.getKeytarKeyForConnection(profile)
            try {
                return await keytar.getPassword(key, account)
            } catch (e) {
                console.warn(`Failed to load stored password for ${account}@${profile.options.host}:${profile.options.port ?? 22}`, e)
                return null
            }
        }
    }

    async savePrivateKeyPassword (id: string, password: string): Promise<void> {
        if (this.vaultBackend) {
            await this.vaultBackend.saveKeyPassphrase(id, password)
            return
        }
        if (this.vault.isEnabled()) {
            const key = this.getVaultKeyForPrivateKey(id)
            this.vault.addSecret({ type: VAULT_SECRET_TYPE_PASSPHRASE, key, value: password })
        } else {
            const key = this.getKeytarKeyForPrivateKey(id)
            return keytar.setPassword(key, 'user', password)
        }
    }

    async deletePrivateKeyPassword (id: string): Promise<void> {
        if (this.vaultBackend) {
            await this.vaultBackend.deleteKeyPassphrase(id)
            return
        }
        if (this.vault.isEnabled()) {
            const key = this.getVaultKeyForPrivateKey(id)
            this.vault.removeSecret(VAULT_SECRET_TYPE_PASSPHRASE, key)
        } else {
            const key = this.getKeytarKeyForPrivateKey(id)
            await keytar.deletePassword(key, 'user')
        }
    }

    async loadPrivateKeyPassword (id: string): Promise<string|null> {
        if (this.vaultBackend) {
            return this.vaultBackend.loadKeyPassphrase(id)
        }
        if (this.vault.isEnabled()) {
            const key = this.getVaultKeyForPrivateKey(id)
            return (await this.vault.getSecret(VAULT_SECRET_TYPE_PASSPHRASE, key))?.value ?? null
        } else {
            const key = this.getKeytarKeyForPrivateKey(id)
            return keytar.getPassword(key, 'user')
        }
    }

    private getBackendKeyForConnection (profile: SSHProfile, username?: string): string {
        const user = username ?? profile.options.user ?? ''
        const port = profile.options.port ?? 22
        return `${user}@${profile.options.host}:${port}`
    }

    private getKeytarKeyForConnection (profile: SSHProfile): string {
        let key = `ssh@${profile.options.host}`
        if (profile.options.port) {
            key = `ssh@${profile.options.host}:${profile.options.port}`
        }
        return key
    }

    private getKeytarKeyForPrivateKey (id: string): string {
        return `ssh-private-key:${id}`
    }

    private getVaultKeyForConnection (profile: SSHProfile, username?: string) {
        return {
            user: username ?? profile.options.user,
            host: profile.options.host,
            port: profile.options.port,
        }
    }

    private getVaultKeyForPrivateKey (id: string) {
        return { hash: id }
    }
}
