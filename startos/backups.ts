import { sdk } from './sdk'

/**
 * `main` carries core's database and master key (so a restore brings every
 * identity and NWC pairing back), the relay's event store and the guard's
 * state, and the static site if there is one. `credentials/` and `run/` are
 * regenerated at start and left out, as is `upload/`, which only ever holds
 * a site archive on its way to being unpacked.
 * `startos` carries the primary URL and the admin password hash.
 */
export const { createBackup, restoreInit } = sdk.setupBackups(async () =>
  sdk.Backups.ofVolumes('main', 'startos').setOptions({
    exclude: ['credentials/**', 'run/**', 'upload/**', '*.tmp'],
  }),
)
