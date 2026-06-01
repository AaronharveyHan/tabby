import * as crypto from 'crypto'
import * as https from 'https'
import * as http from 'http'
import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import { KdfType } from './bitwarden-crypto'

export interface PreloginResponse {
    kdf: KdfType
    kdfIterations: number
    kdfMemory?: number
    kdfParallelism?: number
}

export interface LoginResponse {
    access_token: string
    refresh_token: string
    token_type: string
    // Returned in profile
    Key: string
    PrivateKey: string
}

export interface ProfileResponse {
    Key: string
    PrivateKey: string
    Email: string
}

export enum CipherType {
    Login = 1,
    SecureNote = 2,
    Card = 3,
    Identity = 4,
}

export interface CipherView {
    id: string
    type: CipherType
    name: string
    notes?: string
    login?: {
        username?: string
        password?: string
        uris?: Array<{ uri: string }>
    }
    attachments?: AttachmentView[]
    folderId?: string
}

export interface AttachmentView {
    id: string
    fileName: string
    size: string
    url: string
    key?: string
}

export interface RawCipher {
    Id: string
    Type: CipherType
    Name: string
    Notes?: string
    Login?: {
        Username?: string
        Password?: string
        Uris?: Array<{ Uri: string }>
    }
    Attachments?: RawAttachment[]
    FolderId?: string
}

export interface RawAttachment {
    Id: string
    FileName: string
    Size: string
    Url: string
    Key?: string
}

export interface SyncResponse {
    Ciphers: RawCipher[]
    Folders: Array<{ Id: string, Name: string }>
    Profile: ProfileResponse
}

/**
 * Low-level HTTP client for the Bitwarden/Vaultwarden REST API.
 * All encryption/decryption happens in the caller (VaultwardenService).
 */
export class BitwardenApiClient {
    private deviceIdentifier = ''

    constructor (private baseUrl: string) {
        this.deviceIdentifier = this.getOrCreateDeviceId()
    }

    async prelogin (email: string): Promise<PreloginResponse> {
        const data = await this.post('/api/accounts/prelogin', { email }, null)
        return {
            kdf: data.Kdf ?? data.kdf ?? KdfType.PBKDF2_SHA256,
            kdfIterations: data.KdfIterations ?? data.kdfIterations ?? 600000,
            kdfMemory: data.KdfMemory ?? data.kdfMemory,
            kdfParallelism: data.KdfParallelism ?? data.kdfParallelism,
        }
    }

    async login (email: string, masterPasswordHash: string): Promise<LoginResponse> {
        const body = new URLSearchParams({
            grant_type: 'password',
            username: email,
            password: masterPasswordHash,
            scope: 'api offline_access',
            client_id: 'web',
            deviceType: '10',  // 10 = Unknown Browser
            deviceIdentifier: this.deviceIdentifier,
            deviceName: 'tabby',
        }).toString()

        return this.postForm('/identity/connect/token', body)
    }

    async refreshToken (refreshToken: string): Promise<LoginResponse> {
        const body = new URLSearchParams({
            grant_type: 'refresh_token',
            client_id: 'web',
            refresh_token: refreshToken,
        }).toString()

        return this.postForm('/identity/connect/token', body)
    }

    async sync (accessToken: string): Promise<SyncResponse> {
        return this.get('/api/sync?excludeDomains=true', accessToken)
    }

    async createCipher (cipher: object, accessToken: string): Promise<RawCipher> {
        return this.post('/api/ciphers', cipher, accessToken)
    }

    async updateCipher (id: string, cipher: object, accessToken: string): Promise<RawCipher> {
        return this.put(`/api/ciphers/${id}`, cipher, accessToken)
    }

    async deleteCipher (id: string, accessToken: string): Promise<void> {
        await this.delete(`/api/ciphers/${id}`, accessToken)
    }

    async createFolder (encryptedName: string, accessToken: string): Promise<{ Id: string, Name: string }> {
        return this.post('/api/folders', { name: encryptedName }, accessToken)
    }

    /**
     * Uploads an encrypted file as an attachment to an existing cipher.
     * Returns the attachment metadata.
     */
    async uploadAttachment (
        cipherId: string,
        encryptedFileName: string,
        encryptedKey: string,
        encryptedData: Buffer,
        accessToken: string,
    ): Promise<RawAttachment> {
        // Try v2 API first (modern Vaultwarden), fall back to v1 if not supported
        try {
            return await this.uploadAttachmentV2(cipherId, encryptedFileName, encryptedKey, encryptedData, accessToken)
        } catch (e: any) {
            if (e.message?.includes('422') || e.message?.includes('404')) {
                console.log('[vaultwarden] v2 attachment API failed, falling back to v1:', e.message)
                return this.uploadAttachmentV1(cipherId, encryptedFileName, encryptedKey, encryptedData, accessToken)
            }
            throw e
        }
    }

    private async uploadAttachmentV2 (
        cipherId: string,
        encryptedFileName: string,
        encryptedKey: string,
        encryptedData: Buffer,
        accessToken: string,
    ): Promise<RawAttachment> {
        const initBody = {
            fileName: encryptedFileName,
            key: encryptedKey,
            fileSize: encryptedData.length,
            adminRequest: false,
        }
        console.log('[vaultwarden] v2 init request body:', JSON.stringify(initBody).slice(0, 200))
        const initResp = await this.post(`/api/ciphers/${cipherId}/attachment/v2`, initBody, accessToken)
        console.log('[vaultwarden] v2 init response:', JSON.stringify(initResp).slice(0, 500))

        const attachmentId: string = initResp.AttachmentId ?? initResp.attachmentId
        const uploadUrl: string = initResp.Url ?? initResp.url
        const fileUploadType: number = initResp.FileUploadType ?? initResp.fileUploadType ?? 1
        console.log('[vaultwarden] attachmentId:', attachmentId, 'uploadUrl:', uploadUrl, 'fileUploadType:', fileUploadType)

        if (fileUploadType === 0) {
            await this.putRaw(uploadUrl, encryptedData, {
                'x-ms-blob-type': 'BlockBlob',
                'Content-Type': 'application/octet-stream',
            })
        } else {
            const multipart = this.buildMultipart(encryptedData)
            const uploadPath = uploadUrl.startsWith('http')
                ? new URL(uploadUrl).pathname + new URL(uploadUrl).search
                : uploadUrl
            console.log('[vaultwarden] v2 direct POST to:', uploadPath)
            await this.request('POST', uploadPath, multipart.body, accessToken, {
                'Content-Type': `multipart/form-data; boundary=${multipart.boundary}`,
            })
        }

        const cipherResp = initResp.CipherResponse ?? initResp.cipherResponse
        return cipherResp?.Attachments?.find((a: RawAttachment) => a.Id === attachmentId)
            ?? { Id: attachmentId, FileName: encryptedFileName, Size: String(encryptedData.length), Url: uploadUrl, Key: encryptedKey }
    }

    private async uploadAttachmentV1 (
        cipherId: string,
        encryptedFileName: string,
        encryptedKey: string,
        encryptedData: Buffer,
        accessToken: string,
    ): Promise<RawAttachment> {
        const boundary = `----TabbyBoundary${crypto.randomBytes(8).toString('hex')}`
        const CRLF = '\r\n'
        const keyPart = [
            `--${boundary}`,
            'Content-Disposition: form-data; name="key"',
            '',
            encryptedKey,
        ].join(CRLF)
        const filePart = [
            `--${boundary}`,
            `Content-Disposition: form-data; name="data"; filename="attachment"`,
            'Content-Type: application/octet-stream',
            '',
        ].join(CRLF)
        const body = Buffer.concat([
            Buffer.from(keyPart + CRLF + filePart + CRLF),
            encryptedData,
            Buffer.from(CRLF + `--${boundary}--` + CRLF),
        ])
        console.log('[vaultwarden] v1 POST /api/ciphers/{id}/attachment, body size:', body.length)
        const resp = await this.request('POST', `/api/ciphers/${cipherId}/attachment`, body, accessToken, {
            'Content-Type': `multipart/form-data; boundary=${boundary}`,
        })
        console.log('[vaultwarden] v1 response:', JSON.stringify(resp).slice(0, 300))
        const att = resp?.Id ? resp : resp?.Attachments?.[0]
        return att ?? { Id: '', FileName: encryptedFileName, Size: String(encryptedData.length), Url: '', Key: encryptedKey }
    }

    private buildMultipart (data: Buffer): { boundary: string, body: Buffer } {
        const boundary = `----TabbyBoundary${crypto.randomBytes(8).toString('hex')}`
        const CRLF = '\r\n'
        const filePart = [
            `--${boundary}`,
            'Content-Disposition: form-data; name="data"; filename="attachment"',
            'Content-Type: application/octet-stream',
            '',
        ].join(CRLF)
        const body = Buffer.concat([
            Buffer.from(filePart + CRLF),
            data,
            Buffer.from(CRLF + `--${boundary}--` + CRLF),
        ])
        return { boundary, body }
    }

    /**
     * Downloads the raw (still-encrypted) bytes of an attachment.
     */
    async downloadAttachment (url: string, accessToken: string): Promise<Buffer> {
        return this.downloadRaw(url, accessToken)
    }

    async deleteAttachment (cipherId: string, attachmentId: string, accessToken: string): Promise<void> {
        await this.delete(`/api/ciphers/${cipherId}/attachment/${attachmentId}`, accessToken)
    }

    // --- HTTP helpers ---

    private async get (path: string, accessToken: string | null): Promise<any> {
        return this.request('GET', path, null, accessToken)
    }

    private async post (path: string, body: object, accessToken: string | null): Promise<any> {
        return this.request('POST', path, Buffer.from(JSON.stringify(body)), accessToken, {
            'Content-Type': 'application/json',
        })
    }

    private async put (path: string, body: object, accessToken: string): Promise<any> {
        return this.request('PUT', path, Buffer.from(JSON.stringify(body)), accessToken, {
            'Content-Type': 'application/json',
        })
    }

    private async delete (path: string, accessToken: string): Promise<void> {
        await this.request('DELETE', path, null, accessToken)
    }

    private async postForm (path: string, body: string): Promise<any> {
        return this.request('POST', path, Buffer.from(body), null, {
            'Content-Type': 'application/x-www-form-urlencoded',
        })
    }

    private request (
        method: string,
        urlPath: string,
        body: Buffer | null,
        accessToken: string | null,
        extraHeaders: Record<string, string> = {},
    ): Promise<any> {
        return new Promise((resolve, reject) => {
            const url = new URL(urlPath, this.baseUrl.endsWith('/') ? this.baseUrl : this.baseUrl + '/')
            const isHttps = url.protocol === 'https:'
            const transport = isHttps ? https : http

            const headers: Record<string, string> = {
                Accept: 'application/json',
                ...extraHeaders,
            }
            if (accessToken) {
                headers.Authorization = `Bearer ${accessToken}`
            }
            if (body) {
                headers['Content-Length'] = String(body.length)
            }

            const req = transport.request({
                hostname: url.hostname,
                port: url.port ? parseInt(url.port) : (isHttps ? 443 : 80),
                path: url.pathname + url.search,
                method,
                headers,
            }, res => {
                const chunks: Buffer[] = []
                res.on('data', (c: Buffer) => chunks.push(c))
                res.on('end', () => {
                    const raw = Buffer.concat(chunks)
                    if (res.statusCode === 204 || raw.length === 0) {
                        resolve(null)
                        return
                    }
                    try {
                        const json = JSON.parse(raw.toString('utf8'))
                        if (res.statusCode && res.statusCode >= 400) {
                            const msg = json.ErrorModel?.Message ?? json.error_description ?? json.error?.description ?? json.message ?? JSON.stringify(json)
                            reject(new Error(`Vaultwarden API error ${res.statusCode}: ${msg}`))
                        } else {
                            resolve(json)
                        }
                    } catch {
                        if (res.statusCode && res.statusCode >= 400) {
                            reject(new Error(`Vaultwarden API error ${res.statusCode}`))
                        } else {
                            resolve(raw)
                        }
                    }
                })
                res.on('error', reject)
            })

            req.on('error', reject)
            if (body) {
                req.write(body)
            }
            req.end()
        })
    }

    private putRaw (rawUrl: string, data: Buffer, headers: Record<string, string> = {}): Promise<void> {
        return new Promise((resolve, reject) => {
            const url = new URL(rawUrl)
            const isHttps = url.protocol === 'https:'
            const transport = isHttps ? https : http
            const req = transport.request({
                hostname: url.hostname,
                port: url.port ? parseInt(url.port) : (isHttps ? 443 : 80),
                path: url.pathname + url.search,
                method: 'PUT',
                headers: { 'Content-Length': String(data.length), ...headers },
            }, res => {
                const chunks: Buffer[] = []
                res.on('data', (c: Buffer) => chunks.push(c))
                res.on('end', () => {
                    if (res.statusCode && res.statusCode >= 400) {
                        reject(new Error(`Upload failed with status ${res.statusCode}`))
                    } else {
                        resolve()
                    }
                })
                res.on('error', reject)
            })
            req.on('error', reject)
            req.write(data)
            req.end()
        })
    }

    private downloadRaw (rawUrl: string, accessToken: string): Promise<Buffer> {
        return new Promise((resolve, reject) => {
            const url = new URL(rawUrl)
            const isHttps = url.protocol === 'https:'
            const transport = isHttps ? https : http

            const req = transport.request({
                hostname: url.hostname,
                port: url.port ? parseInt(url.port) : (isHttps ? 443 : 80),
                path: url.pathname + url.search,
                method: 'GET',
                headers: { Authorization: `Bearer ${accessToken}` },
            }, res => {
                const chunks: Buffer[] = []
                res.on('data', (c: Buffer) => chunks.push(c))
                res.on('end', () => resolve(Buffer.concat(chunks)))
                res.on('error', reject)
            })
            req.on('error', reject)
            req.end()
        })
    }

    private getOrCreateDeviceId (): string {
        const idFile = path.join(os.tmpdir(), '.tabby-vaultwarden-device-id')
        try {
            return fs.readFileSync(idFile, 'utf8').trim()
        } catch {
            const id = crypto.randomUUID()
            try {
                fs.writeFileSync(idFile, id, 'utf8')
            } catch { /* ignore write errors */ }
            return id
        }
    }
}
