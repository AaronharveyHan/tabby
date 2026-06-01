import { Injectable } from '@angular/core'
import { ConfigProvider } from 'tabby-core'

@Injectable()
export class VaultwardenConfigProvider extends ConfigProvider {
    defaults = {
        vaultwarden: {
            url: '',
            email: '',
            folderName: 'Tabby',
        },
    }

    platformDefaults = {}
}
