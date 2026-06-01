import { Component, OnInit } from '@angular/core'
import { ConfigService } from 'tabby-core'
import { VaultwardenService } from '../../services/vaultwarden.service'

const KEY_PREFIX = 'tabby:ssh:key:'

@Component({
    selector: 'vaultwarden-settings',
    templateUrl: './vaultwarden-settings.component.pug',
    styleUrls: ['./vaultwarden-settings.component.scss'],
})
export class VaultwardenSettingsComponent implements OnInit {
    masterPassword = ''
    loginInProgress = false
    loginError = ''
    syncInProgress = false
    syncSuccess = false
    syncError = ''
    keyNames: string[] = []
    newKeyName = ''
    uploadError = ''
    uploadSuccess = false

    constructor (
        public config: ConfigService,
        public vw: VaultwardenService,
    ) {}

    async ngOnInit (): Promise<void> {
        if (!this.config.store.vaultwarden) {
            this.config.store.vaultwarden = { url: '', email: '', folderName: 'Tabby' }
        }
        if (this.vw.isSessionActive()) {
            await this.loadKeyNames()
        }
    }

    async login (): Promise<void> {
        this.loginInProgress = true
        this.loginError = ''
        try {
            await this.vw.login(this.masterPassword)
            this.masterPassword = ''
            await this.loadKeyNames()
        } catch (e: any) {
            this.loginError = e.message
        } finally {
            this.loginInProgress = false
        }
    }

    async logout (): Promise<void> {
        await this.vw.logout()
        this.keyNames = []
    }

    async sync (): Promise<void> {
        this.syncInProgress = true
        this.syncSuccess = false
        this.syncError = ''
        try {
            await this.vw.forceSync()
            await this.loadKeyNames()
            this.syncSuccess = true
            setTimeout(() => { this.syncSuccess = false }, 3000)
        } catch (e: any) {
            this.syncError = e.message
        } finally {
            this.syncInProgress = false
        }
    }

    async onKeyFileSelected (event: Event): Promise<void> {
        const input = event.target as HTMLInputElement
        const file = input.files?.[0]
        if (!file) {
            return
        }
        this.uploadError = ''
        this.uploadSuccess = false
        const name = (this.newKeyName.trim() || file.name).replace(/[^a-zA-Z0-9._-]/g, '-')
        try {
            const buffer = Buffer.from(await file.arrayBuffer())
            await this.vw.uploadFile(`${KEY_PREFIX}${name}`, buffer)
            this.newKeyName = ''
            this.uploadSuccess = true
            setTimeout(() => { this.uploadSuccess = false }, 3000)
            await this.loadKeyNames()
        } catch (e: any) {
            this.uploadError = e.message
        }
        input.value = ''
    }

    async deleteKey (name: string): Promise<void> {
        try {
            await this.vw.deleteFile(name)
            await this.loadKeyNames()
        } catch (e: any) {
            this.syncError = e.message
        }
    }

    private async loadKeyNames (): Promise<void> {
        try {
            const names = await this.vw.getFileNames()
            this.keyNames = names.map(n => n.replace(KEY_PREFIX, ''))
        } catch {
            this.keyNames = []
        }
    }
}
