import { InjectionToken } from '@angular/core'

/**
 * Optional injection token for an external secret storage backend.
 * When provided (e.g. by tabby-vaultwarden), PasswordStorageService
 * delegates all reads/writes to this backend instead of the local vault
 * or OS keychain.
 */
export interface SSHVaultBackend {
    savePassword (key: string, value: string): Promise<void>
    loadPassword (key: string): Promise<string | null>
    deletePassword (key: string): Promise<void>
    saveKeyPassphrase (hash: string, value: string): Promise<void>
    loadKeyPassphrase (hash: string): Promise<string | null>
    deleteKeyPassphrase (hash: string): Promise<void>
}

export const SSH_VAULT_BACKEND = new InjectionToken<SSHVaultBackend>('SSHVaultBackend')
