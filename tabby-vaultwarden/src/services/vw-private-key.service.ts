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
            return []
        }
        try {
            await this.vw.ensureSession()
            const names = await this.vw.getFileNames()
            const results: [string, Buffer][] = []
            for (const name of names) {
                const data = await this.vw.downloadFile(name)
                if (data) {
                    const displayName = name.replace(KEY_PREFIX, '')
                    results.push([displayName, data])
                }
            }
            return results
        } catch (e: any) {
            console.warn('Vaultwarden private key locator error:', e.message)
            return []
        }
    }
}
