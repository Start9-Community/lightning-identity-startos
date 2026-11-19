import { i18n } from './i18n'
import { sdk } from './sdk'

const lnd = sdk.Dependency.required('lnd', {
  description: i18n(
    'Creates the invoices behind your Lightning Addresses and answers Nostr Wallet Connect. Only the guard process reads its admin macaroon.',
  ),
  metadata: {
    title: 'LND',
    icon: 'https://raw.githubusercontent.com/Start9Labs/lnd-startos/f17336a10769efd8782a347662848c50c6270349/icon.svg',
  },
  // 0.21.6-beta:3 is the first build that exports admin.macaroon on LND's
  // `public` volume (the `admin` tier the guard mounts), so nothing here has
  // to touch LND's `main` volume, where the seed lives. 0.21 also forces
  // rpcmiddleware.enable (needed for the guard's spend caps) and issues a
  // tls.cert whose SANs cover the bridge address.
  versionRange: '>=0.21.6-beta:3',
  kind: 'running',
  healthChecks: ['lnd'],
})

export const dependencies = sdk.Dependencies.of().addDependency(lnd)
