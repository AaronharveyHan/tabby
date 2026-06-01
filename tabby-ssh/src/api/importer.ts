import { PartialProfile } from 'tabby-core'
import { SSHProfile } from './interfaces'

export abstract class SSHProfileImporter {
    abstract getProfiles (): Promise<PartialProfile<SSHProfile>[]>
}

export abstract class AutoPrivateKeyLocator {
    /**
     * Return SSH private key data.
     * @param hintNames - optional list of key base-names the caller is interested in
     *   (e.g. ["id_ed25519", "my-server-key"]).  Implementations may use this to
     *   fetch only the relevant key(s) instead of everything they hold.
     *   When omitted or empty the implementation should return all available keys.
     */
    abstract getKeys (hintNames?: string[]): Promise<[string, Buffer][]>
}
