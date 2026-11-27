import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.1.0:0-alpha',
  releaseNotes: {
    en_US:
      'Initial release: multiple Lightning Addresses, NIP-05, zap receipts, an embedded policy-locked relay and Nostr Wallet Connect on top of LND.',
    es_ES:
      'Versión inicial: varias Lightning Addresses, NIP-05, recibos de zap, un relay integrado bloqueado por políticas y Nostr Wallet Connect sobre LND.',
    de_DE:
      'Erstveröffentlichung: mehrere Lightning Addresses, NIP-05, Zap-Belege, ein eingebettetes, per Richtlinie gesperrtes Relay und Nostr Wallet Connect auf Basis von LND.',
    pl_PL:
      'Pierwsze wydanie: wiele Lightning Addresses, NIP-05, potwierdzenia zapów, wbudowany przekaźnik zablokowany politykami oraz Nostr Wallet Connect na bazie LND.',
    fr_FR:
      'Version initiale : plusieurs Lightning Addresses, NIP-05, reçus de zap, un relais intégré verrouillé par des règles et Nostr Wallet Connect au-dessus de LND.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
