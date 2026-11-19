import { FileHelper, z } from '@start9labs/start-sdk'
import { sdk } from '../sdk'

const shape = z.looseObject({
  /** The public URL chosen with Set Primary Domain (https://<domain>). */
  primaryUrl: z.string().optional().catch(undefined),
  /** scrypt hash of the admin password; the password itself is never stored. */
  adminPasswordHash: z.string().optional().catch(undefined),
})

/**
 * Package-owned state on the mountless `startos` volume. Nothing inside the
 * container can read this file; `main` reads it and hands the processes the
 * derived values (an env var with the hash, the base URL).
 */
export const storeJson = FileHelper.json(
  { base: sdk.volumes.startos, subpath: './store.json' },
  shape,
)
