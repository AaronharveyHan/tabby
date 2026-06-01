import { NgModule } from '@angular/core'
import { CommonModule } from '@angular/common'
import { FormsModule } from '@angular/forms'
import { NgbModule } from '@ng-bootstrap/ng-bootstrap'

import TabbyCoreModule, { ConfigProvider } from 'tabby-core'
import { SettingsTabProvider } from 'tabby-settings'
import { SSH_VAULT_BACKEND, AutoPrivateKeyLocator } from 'tabby-ssh'

import { VaultwardenSettingsComponent } from './components/vaultwarden-settings/vaultwarden-settings.component'
import { VaultwardenSettingsTabProvider } from './settings'
import { VaultwardenConfigProvider } from './config'
import { VaultwardenPasswordStorageService } from './services/vw-password-storage.service'
import { VaultwardenPrivateKeyLocator } from './services/vw-private-key.service'

@NgModule({
    imports: [
        CommonModule,
        FormsModule,
        NgbModule,
        TabbyCoreModule,
    ],
    providers: [
        { provide: ConfigProvider, useClass: VaultwardenConfigProvider, multi: true },
        { provide: SettingsTabProvider, useClass: VaultwardenSettingsTabProvider, multi: true },
        { provide: SSH_VAULT_BACKEND, useClass: VaultwardenPasswordStorageService },
        { provide: AutoPrivateKeyLocator, useClass: VaultwardenPrivateKeyLocator, multi: true },
    ],
    declarations: [
        VaultwardenSettingsComponent,
    ],
})
export default class VaultwardenModule {
    constructor () {
        console.log('[vaultwarden] module loaded — build: fetch-api-v3')
    }
}
