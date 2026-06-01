import { Injectable } from '@angular/core'
import { SettingsTabProvider } from 'tabby-settings'
import { VaultwardenSettingsComponent } from './components/vaultwarden-settings/vaultwarden-settings.component'

@Injectable()
export class VaultwardenSettingsTabProvider extends SettingsTabProvider {
    id = 'vaultwarden'
    icon = 'cloud'
    title = 'Vaultwarden'

    getComponentType (): any {
        return VaultwardenSettingsComponent
    }
}
