import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.1.0:0-alpha',
  releaseNotes: {
    en_US:
      'Initial release: multiple Lightning Addresses, NIP-05, zap receipts, an embedded policy-locked relay and Nostr Wallet Connect on top of LND.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
