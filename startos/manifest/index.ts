import { setupManifest } from '@start9labs/start-sdk'
import { long, short } from './i18n'

export const manifest = setupManifest({
  // Keep `id` single-quoted on its own line: s9pk.mk scrapes it with awk to
  // name the built s9pk.
  id: 'lightning-identity',
  title: 'Lightning Identity',
  license: 'MIT',
  packageRepo: 'https://github.com/lundog/lightning-identity-startos',
  upstreamRepo: 'https://github.com/lundog/lightning-identity-startos',
  marketingUrl: 'https://github.com/lundog/lightning-identity-startos',
  donationUrl: null,
  description: { short, long },
  // `main` holds every subcontainer's slice (see main.ts for the subpaths);
  // `startos` is mountless package state: the primary URL and the admin
  // password hash, which no process inside the container should read as a
  // file.
  volumes: ['main', 'startos'],
  images: {
    'lightning-identity': {
      // One image, three binaries (edge, core, guard), built from ./Dockerfile.
      // Which binary a subcontainer runs, and what it can see, is decided in
      // main.ts — not by the image.
      source: { dockerBuild: {} },
      arch: ['x86_64', 'aarch64'],
    },
  },
})
