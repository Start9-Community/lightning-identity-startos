import { randomBytes, scryptSync } from 'node:crypto'

/** Ports the binaries listen on inside the container. */
export const publicPort = 8080
export const adminPort = 8081

/** Host ids (`sdk.MultiHost.of`) and the interface ids exported on them. */
export const publicHostId = 'public'
export const publicInterfaceId = 'public'
export const adminHostId = 'admin'
export const adminInterfaceId = 'admin'

/**
 * The uid each subcontainer runs as. They must match the users the
 * Dockerfile creates; the point of three uids is that a subcontainer cannot
 * read another's files through the shared /proc or a stray mount, and that
 * every unix socket checks its peer's uid.
 */
export const uids = { edge: 1001, core: 1002, guard: 1003 } as const

/** Where the binaries expect things inside their subcontainers. */
export const paths = {
  runDir: '/run/lightning-identity',
  guardSocket: '/run/lightning-identity/guard.sock',
  edgeSocket: '/run/lightning-identity/edge-core.sock',
} as const

/**
 * Hash an admin password the way the Go side verifies it (internal/pw):
 * `scrypt$N$r$p$<salt b64>$<key b64>` with N=16384, r=8, p=1, 32-byte key.
 */
export function hashPassword(password: string): string {
  const salt = randomBytes(16)
  const key = scryptSync(password, salt, 32, { N: 16384, r: 8, p: 1 })
  return [
    'scrypt',
    '16384',
    '8',
    '1',
    salt.toString('base64'),
    key.toString('base64'),
  ].join('$')
}
