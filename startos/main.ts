import { manifest as lndManifest } from 'lnd-startos/startos/manifest'
import {
  controlHostId as lndControlHostId,
  gRPCHostId as lndGrpcHostId,
  gRPCPort as lndGrpcPort,
  restPort as lndRestPort,
} from 'lnd-startos/startos/interfaces'
import { storeJson } from './fileModels/store.json'
import { i18n } from './i18n'
import { primaryUrl } from './primaryUrl'
import { sdk } from './sdk'
import { adminPort, paths, publicPort, uids } from './utils'

const imageId = 'lightning-identity'

/**
 * Three subcontainers from one image, each seeing only its slice of the
 * `main` volume and running as its own uid. The topology is the security
 * model; see README.md § Processes and trust boundaries.
 */
export const main = sdk.setupMain(async ({ effects }) => {
  console.info(i18n('Starting Lightning Identity!'))

  // ---- inputs that restart the service when they change ----
  const baseUrl = await primaryUrl.bestUsable(effects).const()
  const adminPasswordHash = await storeJson
    .read((s) => s.adminPasswordHash)
    .const(effects)

  // LND's REST port over the bridge (10.0.3.1:<port>). Null until LND has
  // unlocked and bound it; the env var is then omitted and the processes wait.
  const lndRest = await sdk.host
    .getBridgeAddress(effects, {
      packageId: 'lnd',
      hostId: lndControlHostId,
      internalPort: lndRestPort,
    })
    .const()
  // LND's gRPC, TLS passthrough, for the guard's middleware stream only.
  const lndGrpc = await sdk.host
    .getBridgeAddress(effects, {
      packageId: 'lnd',
      hostId: lndGrpcHostId,
      internalPort: lndGrpcPort,
    })
    .const()
  const lndEnv = {
    ...(lndRest && { LND_REST_URL: `https://${lndRest}` }),
  }
  const guardLndEnv = {
    ...lndEnv,
    ...(lndGrpc && { LND_GRPC_ADDRESS: lndGrpc }),
  }

  // The StartOS root CA signs LND's certificate; the two processes that dial
  // LND pin it. It travels as an env var so it never lands on a volume.
  const rootCa = await sdk.getRootCa(effects)

  const domain = baseUrl ? new URL(baseUrl).hostname : ''
  const relayUrl = domain ? `wss://${domain}/relay` : ''

  // ---- mounts ----
  const vol = (subpath: string, mountpoint: string, readonly: boolean) =>
    ({ volumeId: 'main', subpath, mountpoint, readonly }) as const

  const edgeSub = sdk.SubContainer.of(
    effects,
    { imageId },
    sdk.Mounts.of()
      .mountVolume(vol('edge', '/edge', false))
      .mountVolume(vol('identities', '/identities', true))
      .mountVolume(vol('run', paths.runDir, false))
      .mountVolume(vol('site', '/site', true)),
    'edge',
  )
  const coreSub = sdk.SubContainer.of(
    effects,
    { imageId },
    sdk.Mounts.of()
      .mountVolume(vol('core', '/core', false))
      .mountVolume(vol('identities', '/identities', false))
      .mountVolume(vol('run', paths.runDir, false))
      .mountVolume(vol('credentials', '/credentials', true)),
    'core',
  )
  const guardSub = sdk.SubContainer.of(
    effects,
    { imageId },
    sdk.Mounts.of()
      .mountVolume(vol('credentials', '/credentials', false))
      .mountVolume(vol('guard', '/guard', false))
      .mountVolume(vol('run', paths.runDir, false))
      // LND's `public` volume, `admin` tier: admin.macaroon and a copy of
      // tls.cert, and nothing else. LND's `main` volume — store.json (wallet
      // password + cipher seed), tls.key, wallet.db — is not mounted
      // anywhere in this package. LND rewrites the tier on each start once
      // its wallet is unlocked.
      .mountDependency<typeof lndManifest>({
        dependencyId: 'lnd',
        volumeId: 'public',
        subpath: 'admin',
        mountpoint: '/lnd/admin',
        readonly: true,
      }),
    'guard',
  )

  // One root-run oneshot owns the layout: StartOS mounts volumes root-owned,
  // and each process must own exactly its slice. `run` is sticky and
  // world-writable so core and guard can each create their socket; the
  // sockets themselves check the peer uid.
  const prepareSub = sdk.SubContainer.of(
    effects,
    { imageId },
    sdk.Mounts.of().mountVolume({
      volumeId: 'main',
      subpath: null,
      mountpoint: '/data',
      readonly: false,
    }),
    'prepare',
  )

  return (
    sdk.Daemons.of(effects)
      .addOneshot('prepare', {
        subcontainer: prepareSub,
        exec: {
          command: ['/usr/local/bin/prepare-volume.sh', '/data'],
          user: 'root',
          env: {
            EDGE_UID: String(uids.edge),
            CORE_UID: String(uids.core),
            GUARD_UID: String(uids.guard),
          },
        },
        requires: [],
      })
      // Starts as root for one read: LND exports admin.macaroon owned by
      // root and not world-readable, on a read-only mount, so no uid we
      // choose can open it. The guard reads it into memory and
      // drops to `guard` before it creates a file, a socket or a connection;
      // see cmd/guard/main.go. If LND rotates macaroons the guard exits and is
      // restarted here, which reads the new file.
      .addDaemon('guard', {
        subcontainer: guardSub,
        exec: {
          command: ['/usr/local/bin/guard'],
          user: 'root',
          env: {
            ...guardLndEnv,
            GUARD_RUN_AS: 'guard',
            LND_CA_PEM: rootCa,
            LND_ADMIN_MACAROON: '/lnd/admin/admin.macaroon',
            CREDENTIALS_DIR: '/credentials',
            GUARD_DIR: '/guard',
            GUARD_SOCKET: paths.guardSocket,
            GUARD_ALLOWED_UIDS: String(uids.core),
            // No GUARD_IPRANGE: LND's REST sits behind the OS's addSsl proxy,
            // so LND sees the proxy as the client for every REST call and an
            // IP caveat distinguishes nothing (found on the box 2026-10-21;
            // design §5.1). It would only bite on gRPC, which core does not
            // use yet.
          },
        },
        ready: {
          display: i18n('Credentials'),
          fn: () =>
            sdk.healthCheck.runHealthScript(
              ['test', '-s', '/credentials/recv.macaroon'],
              guardSub,
              {
                errorMessage: i18n(
                  'Waiting for LND to unlock so the guard can bake the receive credential',
                ),
                message: () => i18n('Receive credential baked'),
              },
            ),
          gracePeriod: 60_000,
        },
        requires: ['prepare'],
      })
      .addDaemon('core', {
        subcontainer: coreSub,
        exec: {
          command: ['/usr/local/bin/core'],
          user: 'core',
          env: {
            ...lndEnv,
            LND_CA_PEM: rootCa,
            CORE_DATA: '/core',
            CREDENTIALS_DIR: '/credentials',
            IDENTITIES_DIR: '/identities',
            GUARD_SOCKET: paths.guardSocket,
            EDGE_SOCKET: paths.edgeSocket,
            EDGE_UIDS: String(uids.edge),
            ADMIN_LISTEN: `:${adminPort}`,
            LOCAL_RELAY_URL: `ws://127.0.0.1:${publicPort}/relay`,
            ...(baseUrl && { BASE_URL: baseUrl, RELAY_URL: relayUrl }),
            ...(adminPasswordHash && {
              ADMIN_PASSWORD_HASH: adminPasswordHash,
            }),
          },
        },
        ready: {
          display: i18n('Admin UI'),
          fn: () =>
            sdk.healthCheck.checkPortListening(effects, adminPort, {
              successMessage: i18n('The Admin UI is ready'),
              errorMessage: i18n('The Admin UI is not ready'),
            }),
        },
        // Not `guard`: the Admin UI must come up to configure identities even
        // while LND is still locked and no credential exists yet.
        requires: ['prepare'],
      })
      .addDaemon('edge', {
        subcontainer: edgeSub,
        exec: {
          command: ['/usr/local/bin/edge'],
          user: 'edge',
          env: {
            EDGE_LISTEN: `:${publicPort}`,
            EDGE_DATA: '/edge',
            IDENTITIES_DIR: '/identities',
            CORE_SOCKET: paths.edgeSocket,
            SITE_DIR: '/site',
          },
        },
        ready: {
          display: i18n('Public endpoints'),
          fn: () =>
            sdk.healthCheck.checkPortListening(effects, publicPort, {
              successMessage: i18n(
                'Lightning Address, NIP-05 and relay endpoints are serving',
              ),
              errorMessage: i18n('The public endpoints are not serving'),
            }),
        },
        requires: ['core'],
      })
  )
})
