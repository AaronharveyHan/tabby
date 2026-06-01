import { Injectable } from '@angular/core'
import { VaultwardenService } from './vaultwarden.service'
import { SSH_VAULT_BACKEND, SSHVaultBackend } from 'tabby-ssh'

/**
 * Implements the SSH_VAULT_BACKEND injection token using Vaultwarden.
 * Secrets are stored as Bitwarden Login ciphers with names prefixed by "tabby:".
 */
@Injectable()
export class VaultwardenPasswordStorageService implements SSHVaultBackend {
    constructor (private vw: VaultwardenService) {}

    async savePassword (key: string, value: string): Promise<void> {
        await this.vw.setSecret(`tabby:ssh:password:${key}`, value)
    }

    async loadPassword (key: string): Promise<string | null> {
        await this.vw.ensureSession()
        return this.vw.getSecret(`tabby:ssh:password:${key}`)
    }

    async deletePassword (key: string): Promise<void> {
        await this.vw.deleteSecret(`tabby:ssh:password:${key}`)
    }

    async saveKeyPassphrase (hash: string, value: string): Promise<void> {
        await this.vw.setSecret(`tabby:ssh:passphrase:${hash}`, value)
    }

    async loadKeyPassphrase (hash: string): Promise<string | null> {
        await this.vw.ensureSession()
        return this.vw.getSecret(`tabby:ssh:passphrase:${hash}`)
    }

    async deleteKeyPassphrase (hash: string): Promise<void> {
        await this.vw.deleteSecret(`tabby:ssh:passphrase:${hash}`)
    }
}
