import { utils } from '@start9labs/start-sdk'
import { storeJson } from '../fileModels/store.json'
import { i18n } from '../i18n'
import { sdk } from '../sdk'
import { hashPassword } from '../utils'

/**
 * Mints the admin password, stores only its scrypt hash, and shows the
 * password once. Re-running it rotates the password; core picks the new hash
 * up on its next start (main reads the hash with `.const()`).
 */
export const setAdminPassword = sdk.Action.withoutInput(
  'set-admin-password',
  async ({ effects }) => ({
    name: i18n('Set Admin Password'),
    description: i18n(
      'Generate a new random password for the Admin UI. Replaces any existing password.',
    ),
    warning: (await storeJson.read((s) => s.adminPasswordHash).const(effects))
      ? i18n(
          'Replaces the current admin password; open sessions stay signed in until they expire.',
        )
      : null,
    allowedStatuses: 'any',
    group: null,
    visibility: 'enabled',
  }),
  async ({ effects }) => {
    const password = utils.getDefaultString({ charset: 'a-z,A-Z,0-9', len: 32 })
    await storeJson.merge(effects, {
      adminPasswordHash: hashPassword(password),
    })
    return {
      version: '1',
      title: i18n('Admin Password'),
      message: i18n(
        'Copy this password now. It is not stored and cannot be shown again.',
      ),
      result: {
        type: 'single',
        name: i18n('Password'),
        description: null,
        value: password,
        copyable: true,
        qr: false,
        masked: true,
        launchable: false,
      },
    }
  },
)
