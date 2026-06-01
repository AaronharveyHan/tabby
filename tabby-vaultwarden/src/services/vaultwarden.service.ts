import * as keytar from 'keytar'
import { Injectable } from '@angular/core'
import { ConfigService } from 'tabby-core'
import {
    BitwardenApiClient,
    CipherType,
    RawCipher,
    RawAttachment,
    SyncResponse,
} from '../api/bitwarden-client'
import {
    KdfParams,
    SymmetricKey,
    deriveMasterKey,
    deriveMasterPasswordHash,
    stretchMasterKey,
    decryptAccountKey,
    encryptString,
    decryptString,
    encryptBufferRaw,
    decryptBufferRaw,
    generateAttachmentKey,
    decryptAttachmentKey,
} from '../api/bitwarden-crypto'

const KEYTAR_SERVICE = 'tabby-vaultwarden'
const KEYTAR_TOKEN_ACCOUNT = 'access_token'
const KEYTAR_REFRESH_ACCOUNT = 'refresh_token'
const KEYTAR_ENC_KEY_ACCOUNT = 'enc_key'
const KEYTAR_MAC_KEY_ACCOUNT = 'mac_key'
const KEYTAR_MASTER_PWD_ACCOUNT = 'master_password'

export interface VaultwardenConfig {
    url: string
    email: string
    folderName: string
}

export interface DecryptedCipher {
    id: string
    type: CipherType
    name: string
    notes?: string
    loginUsername?: string
    loginPassword?: string
    attachments?: DecryptedAttachmentMeta[]
    folderId?: string
    // raw encrypted key for this cipher's symmetric key (if it has a dedicated key)
    _encKey?: string
}

export interface DecryptedAttachmentMeta {
    id: string
    fileName: string
    size: string
    url: string
    encryptedKey: string
}

@Injectable({ providedIn: 'root' })
export class VaultwardenService {
    private client: BitwardenApiClient | null = null
    private symmetricKey: SymmetricKey | null = null
    private accessToken: string | null = null
    private refreshToken: string | null = null
    private cachedCiphers: DecryptedCipher[] | null = null
    private tabbyFolderId: string | null = null

    constructor (
        private config: ConfigService,
    ) {}

    get vwConfig (): VaultwardenConfig {
        return this.config.store.vaultwarden ?? {}
    }

    isConfigured (): boolean {
        return !!(this.vwConfig.url && this.vwConfig.email)
    }

    /**
     * Returns true if we have a valid session (tokens + symmetric key in memory).
     */
    isSessionActive (): boolean {
        return !!(this.symmetricKey && this.accessToken)
    }

    /**
     * Ensures we have an active session, restoring from keytar or prompting.
     * Throws if session cannot be established.
     */
    async ensureSession (): Promise<void> {
        if (this.isSessionActive()) {
            return
        }
        await this.restoreSession()
    }

    /**
     * Logs in with the master password. Stores tokens and derived keys in OS Keychain.
     */
    async login (masterPassword: string): Promise<void> {
        const { url, email } = this.vwConfig
        if (!url || !email) {
            throw new Error('Vaultwarden URL and email must be configured first')
        }

        this.client = new BitwardenApiClient(url)

        const prelogin = await this.client.prelogin(email)
        const kdfParams: KdfParams = {
            kdfType: prelogin.kdf,
            kdfIterations: prelogin.kdfIterations,
            kdfMemory: prelogin.kdfMemory,
            kdfParallelism: prelogin.kdfParallelism,
        }

        const masterKey = await deriveMasterKey(masterPassword, email, kdfParams)
        const masterPasswordHash = deriveMasterPasswordHash(masterKey, masterPassword)
        const stretchedKey = stretchMasterKey(masterKey)

        const loginResp = await this.client.login(email, masterPasswordHash)

        const symmetricKey = decryptAccountKey(loginResp.Key, stretchedKey)

        // Store tokens and key material in OS Keychain
        await keytar.setPassword(KEYTAR_SERVICE, KEYTAR_TOKEN_ACCOUNT, loginResp.access_token)
        await keytar.setPassword(KEYTAR_SERVICE, KEYTAR_REFRESH_ACCOUNT, loginResp.refresh_token)
        await keytar.setPassword(KEYTAR_SERVICE, KEYTAR_ENC_KEY_ACCOUNT, symmetricKey.encKey.toString('base64'))
        await keytar.setPassword(KEYTAR_SERVICE, KEYTAR_MAC_KEY_ACCOUNT, symmetricKey.macKey.toString('base64'))
        await keytar.setPassword(KEYTAR_SERVICE, KEYTAR_MASTER_PWD_ACCOUNT, masterPassword)

        this.accessToken = loginResp.access_token
        this.refreshToken = loginResp.refresh_token
        this.symmetricKey = symmetricKey
        this.cachedCiphers = null
    }

    /**
     * Restores session from OS Keychain.
     */
    async restoreSession (): Promise<void> {
        const { url } = this.vwConfig
        if (!url) {
            throw new Error('Vaultwarden not configured')
        }

        const encKeyB64 = await keytar.getPassword(KEYTAR_SERVICE, KEYTAR_ENC_KEY_ACCOUNT)
        const macKeyB64 = await keytar.getPassword(KEYTAR_SERVICE, KEYTAR_MAC_KEY_ACCOUNT)
        const accessToken = await keytar.getPassword(KEYTAR_SERVICE, KEYTAR_TOKEN_ACCOUNT)
        const refreshToken = await keytar.getPassword(KEYTAR_SERVICE, KEYTAR_REFRESH_ACCOUNT)

        if (!encKeyB64 || !macKeyB64 || !accessToken) {
            throw new Error('No saved Vaultwarden session. Please log in from Settings → Vaultwarden.')
        }

        this.client = new BitwardenApiClient(url)
        this.symmetricKey = {
            encKey: Buffer.from(encKeyB64, 'base64'),
            macKey: Buffer.from(macKeyB64, 'base64'),
        }
        this.accessToken = accessToken
        this.refreshToken = refreshToken

        // Validate token by doing a lightweight check; refresh if expired
        try {
            await this.getOrSyncCiphers()
        } catch (e: any) {
            if (e.message?.includes('401') && this.refreshToken) {
                try {
                    await this.refreshAccessToken()
                    this.cachedCiphers = null
                    await this.getOrSyncCiphers()
                } catch {
                    // Both tokens expired — clear session so user is prompted to log in again
                    await this.logout()
                    throw new Error('Vaultwarden session expired. Please log in again from Settings → Vaultwarden.')
                }
            } else {
                throw e
            }
        }
    }

    async logout (): Promise<void> {
        await keytar.deletePassword(KEYTAR_SERVICE, KEYTAR_TOKEN_ACCOUNT)
        await keytar.deletePassword(KEYTAR_SERVICE, KEYTAR_REFRESH_ACCOUNT)
        await keytar.deletePassword(KEYTAR_SERVICE, KEYTAR_ENC_KEY_ACCOUNT)
        await keytar.deletePassword(KEYTAR_SERVICE, KEYTAR_MAC_KEY_ACCOUNT)
        await keytar.deletePassword(KEYTAR_SERVICE, KEYTAR_MASTER_PWD_ACCOUNT)
        this.symmetricKey = null
        this.accessToken = null
        this.refreshToken = null
        this.cachedCiphers = null
        this.tabbyFolderId = null
    }

    async forceSync (): Promise<void> {
        this.cachedCiphers = null
        await this.getOrSyncCiphers()
    }

    // --- Secret storage API ---

    async getSecret (name: string): Promise<string | null> {
        const ciphers = await this.getOrSyncCiphers()
        const match = ciphers.find(c => c.name === name && c.type === CipherType.Login)
        return match?.loginPassword ?? null
    }

    async setSecret (name: string, value: string, username = 'tabby'): Promise<void> {
        await this.ensureSession()
        const ciphers = await this.getOrSyncCiphers()
        const existing = ciphers.find(c => c.name === name && c.type === CipherType.Login)
        const folderId = await this.ensureTabbyFolder()
        const key = this.symmetricKey!

        const payload = {
            type: CipherType.Login,
            name: encryptString(name, key),
            folderId,
            login: {
                username: encryptString(username, key),
                password: encryptString(value, key),
            },
            secureNote: null,
            card: null,
            identity: null,
        }

        if (existing) {
            const updated = await this.client!.updateCipher(existing.id, payload, this.accessToken!)
            const idx = ciphers.findIndex(c => c.id === existing.id)
            ciphers[idx] = this.decryptCipher(updated)
        } else {
            const created = await this.client!.createCipher(payload, this.accessToken!)
            ciphers.push(this.decryptCipher(created))
        }
    }

    async deleteSecret (name: string): Promise<void> {
        await this.ensureSession()
        const ciphers = await this.getOrSyncCiphers()
        const match = ciphers.find(c => c.name === name && c.type === CipherType.Login)
        if (!match) {
            return
        }
        await this.client!.deleteCipher(match.id, this.accessToken!)
        this.cachedCiphers = ciphers.filter(c => c.id !== match.id)
    }

    // --- File (private key) storage API ---

    async getFileNames (): Promise<string[]> {
        const ciphers = await this.getOrSyncCiphers()
        return ciphers
            .filter(c => c.type === CipherType.SecureNote && c.name.startsWith('tabby:ssh:key:'))
            .map(c => c.name)
    }

    async uploadFile (name: string, data: Buffer): Promise<void> {
        await this.ensureSession()
        const ciphers = await this.getOrSyncCiphers()
        const folderId = await this.ensureTabbyFolder()
        const key = this.symmetricKey!

        // Remove existing entry with same name
        const existing = ciphers.find(c => c.name === name && c.type === CipherType.SecureNote)

        const notePaylod = {
            type: CipherType.SecureNote,
            name: encryptString(name, key),
            folderId,
            secureNote: { type: 0 },
            login: null,
            card: null,
            identity: null,
        }

        let cipherId: string
        if (existing) {
            await this.client!.updateCipher(existing.id, notePaylod, this.accessToken!)
            cipherId = existing.id
        } else {
            const created = await this.client!.createCipher(notePaylod, this.accessToken!)
            cipherId = created.Id
        }
        console.log('[vaultwarden] uploadFile cipherId:', cipherId)

        // Generate per-attachment key
        const { key: attachKey, encryptedKey } = generateAttachmentKey(key)
        const encryptedFileName = encryptString(name, key)
        const encryptedData = encryptBufferRaw(data, attachKey)

        await this.client!.uploadAttachment(cipherId, encryptedFileName, encryptedKey, encryptedData, this.accessToken!)
        this.cachedCiphers = null
    }

    async downloadFile (name: string): Promise<Buffer | null> {
        const ciphers = await this.getOrSyncCiphers()
        const cipher = ciphers.find(c => c.name === name && c.type === CipherType.SecureNote)
        if (!cipher?.attachments?.length) {
            return null
        }

        const att = cipher.attachments[0]
        const encryptedData = await this.client!.downloadAttachment(att.url, this.accessToken!)

        const attachKey = decryptAttachmentKey(att.encryptedKey, this.symmetricKey!)
        return decryptBufferRaw(encryptedData, attachKey)
    }

    async deleteFile (name: string): Promise<void> {
        await this.ensureSession()
        const ciphers = await this.getOrSyncCiphers()
        const cipher = ciphers.find(c => c.name === name && c.type === CipherType.SecureNote)
        if (!cipher) {
            return
        }
        await this.client!.deleteCipher(cipher.id, this.accessToken!)
        this.cachedCiphers = ciphers.filter(c => c.id !== cipher.id)
    }

    // --- Internal ---

    private async getOrSyncCiphers (): Promise<DecryptedCipher[]> {
        await this.ensureSession()
        if (this.cachedCiphers) {
            return this.cachedCiphers
        }

        let sync: SyncResponse
        try {
            sync = await this.client!.sync(this.accessToken!)
        } catch (e: any) {
            if (e.message?.includes('401') && this.refreshToken) {
                await this.refreshAccessToken()
                sync = await this.client!.sync(this.accessToken!)
            } else {
                throw e
            }
        }

        // Find or note Tabby folder id
        const folderName = this.vwConfig.folderName || 'Tabby'
        for (const folder of sync.Folders ?? []) {
            try {
                const decName = decryptString(folder.Name, this.symmetricKey!)
                if (decName === folderName) {
                    this.tabbyFolderId = folder.Id
                    break
                }
            } catch { /* skip undecryptable folders */ }
        }

        this.cachedCiphers = (sync.Ciphers ?? []).map(c => {
            try {
                return this.decryptCipher(c)
            } catch {
                return null
            }
        }).filter(Boolean) as DecryptedCipher[]

        return this.cachedCiphers
    }

    private decryptCipher (raw: RawCipher): DecryptedCipher {
        const key = this.symmetricKey!
        const result: DecryptedCipher = {
            id: raw.Id,
            type: raw.Type,
            name: decryptString(raw.Name, key),
            folderId: raw.FolderId ?? undefined,
        }

        if (raw.Notes) {
            try { result.notes = decryptString(raw.Notes, key) } catch { /* ok */ }
        }

        if (raw.Login) {
            if (raw.Login.Username) {
                try { result.loginUsername = decryptString(raw.Login.Username, key) } catch { /* ok */ }
            }
            if (raw.Login.Password) {
                try { result.loginPassword = decryptString(raw.Login.Password, key) } catch { /* ok */ }
            }
        }

        if (raw.Attachments?.length) {
            result.attachments = raw.Attachments.map((a: RawAttachment) => ({
                id: a.Id,
                fileName: (() => { try { return decryptString(a.FileName, key) } catch { return '' } })(),
                size: a.Size,
                url: a.Url,
                encryptedKey: a.Key ?? '',
            }))
        }

        return result
    }

    private async ensureTabbyFolder (): Promise<string | null> {
        if (this.tabbyFolderId) {
            return this.tabbyFolderId
        }
        const folderName = this.vwConfig.folderName || 'Tabby'
        const encName = encryptString(folderName, this.symmetricKey!)
        const folder = await this.client!.createFolder(encName, this.accessToken!)
        this.tabbyFolderId = folder.Id
        return folder.Id
    }

    private async refreshAccessToken (): Promise<void> {
        if (!this.refreshToken) {
            throw new Error('No refresh token available. Please log in again.')
        }
        const resp = await this.client!.refreshToken(this.refreshToken)
        this.accessToken = resp.access_token
        if (resp.refresh_token) {
            this.refreshToken = resp.refresh_token
        }
        await keytar.setPassword(KEYTAR_SERVICE, KEYTAR_TOKEN_ACCOUNT, this.accessToken)
        if (resp.refresh_token) {
            await keytar.setPassword(KEYTAR_SERVICE, KEYTAR_REFRESH_ACCOUNT, resp.refresh_token)
        }
    }
}
