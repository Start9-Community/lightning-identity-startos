import { i18n } from './i18n'
import { primaryUrl } from './primaryUrl'
import { sdk } from './sdk'
import {
  adminHostId,
  adminInterfaceId,
  adminPort,
  publicHostId,
  publicInterfaceId,
  publicPort,
} from './utils'

/**
 * Two interfaces on two hosts, and the split is the security model:
 *
 * - `public` is the one that gets a public domain. It serves only the LNURL,
 *   NIP-05 and relay endpoints from the credential-less edge process. The OS
 *   terminates TLS and adds X-Forwarded-For (`protocol: 'http'` sets
 *   addXForwardedHeaders).
 * - `admin` is the operator UI from the core process. Never give it a domain;
 *   reach it over LAN or Tor.
 */
export const setInterfaces = sdk.setupInterfaces(async ({ effects }) => {
  const publicMulti = sdk.MultiHost.of(effects, publicHostId)
  const publicOrigin = await publicMulti.bindPort(publicPort, {
    protocol: 'http',
  })
  const publicIface = sdk.createInterface(effects, {
    name: i18n('Public'),
    id: publicInterfaceId,
    description: i18n(
      'Lightning Address, NIP-05 and Nostr relay endpoints. Add your public domain here.',
    ),
    type: 'api',
    masked: false,
    schemeOverride: null,
    username: null,
    path: '',
    query: {},
  })

  const adminMulti = sdk.MultiHost.of(effects, adminHostId)
  const adminOrigin = await adminMulti.bindPort(adminPort, {
    protocol: 'http',
  })
  const adminIface = sdk.createInterface(effects, {
    name: i18n('Admin UI'),
    id: adminInterfaceId,
    description: i18n(
      'Manage identities and Nostr Wallet Connect connections. Keep this off the public internet.',
    ),
    type: 'ui',
    masked: false,
    schemeOverride: null,
    username: null,
    path: '',
    query: {},
  })

  // The launcher should open the admin UI, never the public domain.
  void primaryUrl
  return [
    await publicOrigin.export([publicIface]),
    await adminOrigin.export([adminIface]),
  ]
})
