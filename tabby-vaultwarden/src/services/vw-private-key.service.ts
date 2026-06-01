import { Injectable } from '@angular/core'
import { AutoPrivateKeyLocator } from 'tabby-ssh'
import { VaultwardenService } from './vaultwarden.service'

const KEY_PREFIX = 'tabby:ssh:key:'

/**
 * Exposes SSH private keys stored in Vaultwarden as local key candidates.
 * Registered as multi-provider for AutoPrivateKeyLocator.
 */
@Injectable()
export class VaultwardenPrivateKeyLocator extends AutoPrivateKeyLocator {
    constructor (private vw: VaultwardenService) {
        super()
    }

    async getKeys (): Promise<[string, Buffer][]> {
        if (!this.vw.isConfigured()) {
            console.log('[vaultwarden-key] not configured, skipping')
            return []
        }
        try {
            await this.vw.ensureSession()
            const names = await this.vw.getFileNames()
            console.log('[vaultwarden-key] found vault key names:', names)
            const results: [string, Buffer][] = []
            for (const name of names) {
                const data = await this.vw.downloadFile(name)
                if (data) {
                    const displayName = name.replace(KEY_PREFIX, '')
                    const preview = data.toString('utf8', 0, 40).replace(/\n/g, '\\n')
                    console.log(`[vaultwarden-key] loaded key "${displayName}" (${data.length} bytes), starts with: ${preview}`)
                    results.push([displayName, data])
                } else {
                    console.warn(`[vaultwarden-key] downloadFile returned null for "${name}"`)
                }
            }
            console.log(`[vaultwarden-key] returning ${results.length} key(s) for SSH auth`)
            return results
        } catch (e: any) {
            console.warn('[vaultwarden-key] error in getKeys:', e.message)
            return []
        }
    }
}
