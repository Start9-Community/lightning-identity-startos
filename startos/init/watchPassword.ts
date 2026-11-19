import { setAdminPassword } from '../actions/setAdminPassword'
import { storeJson } from '../fileModels/store.json'
import { i18n } from '../i18n'
import { manifest } from '../manifest'
import { sdk } from '../sdk'

/** Keeps a critical task raised until an admin password exists. */
export const watchPassword = sdk.setupOnInit(async (effects) => {
  const hash = await storeJson.read((s) => s.adminPasswordHash).const(effects)
  if (!hash) {
    await sdk.action.createOwnTask(effects, setAdminPassword, 'critical', {
      reason: i18n('Set an admin password to sign in to the Admin UI.'),
    })
  } else {
    await sdk.action.clearTask(effects, `${manifest.id}:${setAdminPassword.id}`)
  }
})
