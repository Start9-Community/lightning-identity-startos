import { storeJson } from './fileModels/store.json'
import { i18n } from './i18n'
import { sdk } from './sdk'
import { publicHostId, publicInterfaceId } from './utils'

/**
 * Which of the Public interface's addresses is *the* domain: the host part of
 * every Lightning Address and NIP-05 name, the base of every LNURL callback,
 * and the relay URL in every NWC connection string. Only a public domain
 * works — a wallet on the other side of the world has to fetch it — so the
 * select is narrowed to domains and the service does not advertise addresses
 * while nothing is chosen (`fallback: false`).
 */
export const primaryUrl = sdk.setupPrimaryUrl({
  id: 'set-primary-domain',
  hostId: publicHostId,
  interfaceId: publicInterfaceId,
  metadata: {
    name: i18n('Set Primary Domain'),
    description: i18n(
      'Choose the public domain your Lightning Addresses and NIP-05 names live on. Add a public domain to the Public interface first; Tor and .local addresses cannot be resolved by the wallets paying you. Changing it restarts the service.',
    ),
    warning: null,
    allowedStatuses: 'any',
    group: null,
    visibility: 'enabled',
  },
  field: {
    name: i18n('Domain'),
    description: i18n('Addresses become name@<this domain>.'),
  },
  get: storeJson.read((s) => s.primaryUrl),
  set: (effects, url) => storeJson.merge(effects, { primaryUrl: url }),
  filter: { kind: 'domain' },
  ssl: true,
  fallback: false,
})
