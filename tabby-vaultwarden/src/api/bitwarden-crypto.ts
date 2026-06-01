import * as crypto from 'crypto'

export enum KdfType {
    PBKDF2_SHA256 = 0,
    Argon2id = 1,
}

export interface KdfParams {
    kdfType: KdfType
    kdfIterations: number
    kdfMemory?: number
    kdfParallelism?: number
}

export interface SymmetricKey {
    encKey: Buffer
    macKey: Buffer
}

/**
 * Derives the master key from the user's master password.
 * Uses PBKDF2-SHA256 or Argon2id depending on account settings.
 */
export async function deriveMasterKey (password: string, email: string, params: KdfParams): Promise<Buffer> {
    if (params.kdfType === KdfType.PBKDF2_SHA256) {
        return new Promise((resolve, reject) => {
            crypto.pbkdf2(
                Buffer.from(password, 'utf8'),
                Buffer.from(email.trim().toLowerCase(), 'utf8'),
                params.kdfIterations,
                32,
                'sha256',
                (err, key) => err ? reject(err) : resolve(key),
            )
        })
    } else if (params.kdfType === KdfType.Argon2id) {
        // Argon2id requires the argon2 native module. Salt = first 16 bytes of SHA256(email).
        let argon2: any
        try {
            argon2 = require('argon2')
        } catch {
            throw new Error('Argon2id KDF requires the argon2 native module. Run: npm install argon2')
        }
        const salt = crypto.createHash('sha256').update(email.trim().toLowerCase()).digest().slice(0, 16)
        const hash = await argon2.hash(password, {
            type: argon2.argon2id,
            salt,
            memoryCost: (params.kdfMemory ?? 64) * 1024,
            timeCost: params.kdfIterations,
            parallelism: params.kdfParallelism ?? 4,
            hashLength: 32,
            raw: true,
        })
        return Buffer.from(hash)
    }
    throw new Error(`Unsupported KDF type: ${params.kdfType}`)
}

/**
 * Derives the master password hash sent to the server for authentication.
 * masterPasswordHash = PBKDF2(masterKey, password, 1 iteration, SHA256)
 */
export function deriveMasterPasswordHash (masterKey: Buffer, password: string): string {
    const hash = crypto.pbkdf2Sync(masterKey, Buffer.from(password, 'utf8'), 1, 32, 'sha256')
    return hash.toString('base64')
}

/**
 * Stretches the 32-byte master key to 64 bytes (enc + mac keys) via HKDF.
 */
export function stretchMasterKey (masterKey: Buffer): SymmetricKey {
    const encKey = hkdfExpand(masterKey, Buffer.from('enc', 'utf8'), 32)
    const macKey = hkdfExpand(masterKey, Buffer.from('mac', 'utf8'), 32)
    return { encKey, macKey }
}

/**
 * Decrypts the account symmetric key returned by the server.
 * The key is encrypted with the stretched master key.
 */
export function decryptAccountKey (encryptedKey: string, stretchedKey: SymmetricKey): SymmetricKey {
    const raw = decryptCipherString(encryptedKey, stretchedKey)
    return {
        encKey: raw.slice(0, 32),
        macKey: raw.slice(32, 64),
    }
}

/**
 * Encrypts plaintext using AES-256-CBC + HMAC-SHA256.
 * Returns a Bitwarden cipher string: "2.{base64_iv}|{base64_ciphertext}|{base64_mac}"
 */
export function encryptString (plaintext: string, key: SymmetricKey): string {
    const iv = crypto.randomBytes(16)
    const cipher = crypto.createCipheriv('aes-256-cbc', key.encKey, iv)
    const encrypted = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()])
    const mac = computeMac(iv, encrypted, key.macKey)
    return `2.${iv.toString('base64')}|${encrypted.toString('base64')}|${mac.toString('base64')}`
}

/**
 * Encrypts a Buffer (binary data) using AES-256-CBC + HMAC-SHA256.
 * Returns a Bitwarden cipher string (used for key fields, not file data).
 */
export function encryptBuffer (data: Buffer, key: SymmetricKey): string {
    const iv = crypto.randomBytes(16)
    const cipher = crypto.createCipheriv('aes-256-cbc', key.encKey, iv)
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()])
    const mac = computeMac(iv, encrypted, key.macKey)
    return `2.${iv.toString('base64')}|${encrypted.toString('base64')}|${mac.toString('base64')}`
}

/**
 * Encrypts a Buffer as raw binary for attachment file data.
 * Format: [0x02][16 bytes IV][32 bytes MAC][ciphertext]
 */
export function encryptBufferRaw (data: Buffer, key: SymmetricKey): Buffer {
    const iv = crypto.randomBytes(16)
    const cipher = crypto.createCipheriv('aes-256-cbc', key.encKey, iv)
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()])
    const mac = computeMac(iv, encrypted, key.macKey)
    return Buffer.concat([Buffer.from([0x02]), iv, mac, encrypted])
}

/**
 * Decrypts raw binary attachment data (EncArrayBuffer format).
 * Format: [0x02][16 bytes IV][32 bytes MAC][ciphertext]
 */
export function decryptBufferRaw (data: Buffer, key: SymmetricKey): Buffer {
    const type = data[0]
    if (type !== 2) {
        throw new Error(`Unsupported attachment encryption type: ${type}`)
    }
    const iv = data.slice(1, 17)
    const mac = data.slice(17, 49)
    const ct = data.slice(49)
    const expectedMac = computeMac(iv, ct, key.macKey)
    if (!crypto.timingSafeEqual(mac, expectedMac)) {
        throw new Error('Attachment MAC validation failed')
    }
    const decipher = crypto.createDecipheriv('aes-256-cbc', key.encKey, iv)
    return Buffer.concat([decipher.update(ct), decipher.final()])
}

/**
 * Decrypts a Bitwarden cipher string to a Buffer.
 */
export function decryptCipherString (cipherString: string, key: SymmetricKey): Buffer {
    if (!cipherString) {
        throw new Error('Empty cipher string')
    }
    const parts = cipherString.split('|')
    if (parts.length < 2) {
        throw new Error(`Invalid cipher string format: ${cipherString.slice(0, 30)}`)
    }

    let ivBase64: string
    let ctBase64: string
    let macBase64: string | undefined

    // Type prefix: "2...." means AES-256-CBC w/ MAC
    const firstPart = parts[0]
    if (firstPart.includes('.')) {
        const [typeStr, ivPart] = firstPart.split('.')
        const type = parseInt(typeStr, 10)
        if (type !== 2) {
            throw new Error(`Unsupported cipher type: ${type}`)
        }
        ivBase64 = ivPart
    } else {
        ivBase64 = firstPart
    }

    ctBase64 = parts[1]
    macBase64 = parts[2]

    const iv = Buffer.from(ivBase64, 'base64')
    const ct = Buffer.from(ctBase64, 'base64')

    if (macBase64) {
        const mac = Buffer.from(macBase64, 'base64')
        const expectedMac = computeMac(iv, ct, key.macKey)
        if (!crypto.timingSafeEqual(mac, expectedMac)) {
            throw new Error('MAC validation failed — data may be corrupted or key is wrong')
        }
    }

    const decipher = crypto.createDecipheriv('aes-256-cbc', key.encKey, iv)
    return Buffer.concat([decipher.update(ct), decipher.final()])
}

/**
 * Decrypts a Bitwarden cipher string to a UTF-8 string.
 */
export function decryptString (cipherString: string, key: SymmetricKey): string {
    return decryptCipherString(cipherString, key).toString('utf8')
}

// --- Attachment key helpers ---

/**
 * Generates a fresh random 64-byte attachment key and returns its cipher string
 * (encrypted with the parent cipher's symmetric key).
 */
export function generateAttachmentKey (cipherKey: SymmetricKey): { key: SymmetricKey, encryptedKey: string } {
    const rawKey = crypto.randomBytes(64)
    const attachmentKey: SymmetricKey = {
        encKey: rawKey.slice(0, 32),
        macKey: rawKey.slice(32, 64),
    }
    const encryptedKey = encryptBuffer(rawKey, cipherKey)
    return { key: attachmentKey, encryptedKey }
}

/**
 * Decrypts an attachment key.
 */
export function decryptAttachmentKey (encryptedKey: string, cipherKey: SymmetricKey): SymmetricKey {
    const raw = decryptCipherString(encryptedKey, cipherKey)
    return { encKey: raw.slice(0, 32), macKey: raw.slice(32, 64) }
}

// --- Internal helpers ---

function hkdfExpand (key: Buffer, info: Buffer, length: number): Buffer {
    // HKDF-Expand using HMAC-SHA256
    const hashLen = 32
    const n = Math.ceil(length / hashLen)
    const okm = Buffer.alloc(length)
    let t = Buffer.alloc(0)
    let offset = 0
    for (let i = 1; i <= n; i++) {
        const hmac = crypto.createHmac('sha256', key)
        hmac.update(t)
        hmac.update(info)
        hmac.update(Buffer.from([i]))
        t = hmac.digest()
        t.copy(okm, offset, 0, Math.min(hashLen, length - offset))
        offset += hashLen
    }
    return okm
}

function computeMac (iv: Buffer, ct: Buffer, macKey: Buffer): Buffer {
    const hmac = crypto.createHmac('sha256', macKey)
    hmac.update(iv)
    hmac.update(ct)
    return hmac.digest()
}
