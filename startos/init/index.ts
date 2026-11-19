import { actions } from '../actions'
import { restoreInit } from '../backups'
import { dependencies } from '../dependencies'
import { i18n } from '../i18n'
import { setInterfaces } from '../interfaces'
import { primaryUrl } from '../primaryUrl'
import { sdk } from '../sdk'
import { versionGraph } from '../versions'
import { watchPassword } from './watchPassword'

export const init = sdk.setupInit(
  restoreInit,
  versionGraph,
  setInterfaces,
  actions,
  dependencies,
  watchPassword,
  // Nothing works without a domain — no address resolves, no connection
  // string can be made — so this is Required (gates starting), stays raised
  // until a domain is chosen, and comes back if the chosen domain
  // disappears. A domain can be added to the Public interface while the
  // service is stopped.
  primaryUrl.setupTask('critical', {
    reason: i18n(
      'Choose the public domain your Lightning Addresses and NIP-05 names live on.',
    ),
  }),
)

export const uninit = sdk.setupUninit(versionGraph)
