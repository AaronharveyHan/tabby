import { Injectable } from '@angular/core'
import { AutoPrivateKeyLocator } from 'tabby-ssh'
import { VaultwardenService } from './vaultwarden.service'

const KEY_PREFIX = 'tabby:ssh:key:'

/**
 * Exposes SSH private keys stored in Vaultwarden as local key candidates.
 * Registered as multi-provider for AutoPrivateKeyLocator.
 *
 * When the SSH session passes hintNames (basenames of configured private key paths),
 * only matching vault keys are downloaded.  This avoids fetching every key in the
 * vault for every connection.
 */
@Injectable()
export class VaultwardenPrivateKeyLocator extends AutoPrivateKeyLocator {
    constructor (private vw: VaultwardenService) {
        super()
    }

    async getKeys (hintNames?: string[]): Promise<[string, Buffer][]> {
        if (!this.vw.isConfigured()) {
            return []
        }
        try {
            await this.vw.ensureSession()
            const allNames = await this.vw.getFileNames()

            // If the caller gave us hint names, only fetch keys whose display name
            // (the part after the KEY_PREFIX) matches one of the hints.
            const names = hintNames?.length
                ? allNames.filter(n => {
                    const display = n.replace(KEY_PREFIX, '')
                    return hintNames.some(hint => hint === display || hint === display.replace(/\.pub$/, ''))
                })
                : allNames

            if (hintNames?.length && names.length === 0) {
                console.log(`[vaultwarden-key] no vault keys match hints: ${hintNames.join(', ')} (available: ${allNames.map(n => n.replace(KEY_PREFIX, '')).join(', ')})`)
            }

            const results: [string, Buffer][] = []
            for (const name of names) {
                const data = await this.vw.downloadFile(name)
                if (data) {
                    const displayName = name.replace(KEY_PREFIX, '')
                    console.log(`[vaultwarden-key] loaded key "${displayName}" (${data.length} bytes)`)
                    results.push([displayName, data])
                } else {
                    console.warn(`[vaultwarden-key] downloadFile returned null for "${name}"`)
                }
            }
            return results
        } catch (e: any) {
            console.warn('[vaultwarden-key] error in getKeys:', e.message)
            return []
        }
    }
}
