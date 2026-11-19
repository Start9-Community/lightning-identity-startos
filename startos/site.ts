import { mkdir, readdir, rm, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { T } from '@start9labs/start-sdk'
import { sdk } from './sdk'

/**
 * The optional static site (`site/` on the main volume, which edge mounts
 * read-only and serves at `/`) is managed by two actions. Neither daemon
 * takes part: StartOS receives the archive, and `edge site ...` — the
 * unpacker in service/internal/site — runs once in a throwaway container
 * that mounts the upload and site folders and nothing else.
 */

/** Largest archive StartOS will accept for the upload, in bytes. */
export const maxArchiveBytes = 50 * 1024 * 1024

/**
 * Where an archive lands. Not `site/`: everything there is served to the
 * internet, and an archive would be downloadable until it was unpacked.
 * Nothing mounts this folder except the one-off that unpacks.
 */
const uploadSubpath = 'upload'
const siteSubpath = 'site'
const uploadDir = () => sdk.volumes.main.subpath(`./${uploadSubpath}`)
const siteDir = () => sdk.volumes.main.subpath(`./${siteSubpath}`)

/** An upload is `upload/site-<16 hex>.zip`; anything else is not ours. */
const archiveName = /(?:^|\/)upload\/(site-[0-9a-f]{16}\.zip)$/

/** A volume-relative destination for one upload form. */
export const archivePath = (id: string) => `${uploadSubpath}/site-${id}.zip`

/** The archive's file name, from the destination StartOS reports back. */
export function archiveFile(volumePath: string): string | null {
  return archiveName.exec(volumePath)?.[1] ?? null
}

/**
 * Makes the two folders (StartOS needs the upload's parent to exist, and a
 * mount needs its subpath) and deletes archives nobody came back for. A
 * prepared upload lives 30 minutes and a transfer at most an hour, so
 * anything older than two hours is abandoned.
 */
export async function prepareFolders(): Promise<void> {
  await mkdir(uploadDir(), { recursive: true, mode: 0o700 })
  await mkdir(siteDir(), { recursive: true, mode: 0o755 })
  const cutoff = Date.now() - 2 * 60 * 60 * 1000
  for (const name of await readdir(uploadDir())) {
    const file = join(uploadDir(), name)
    const st = await stat(file).catch(() => null)
    if (st && st.mtimeMs < cutoff)
      await rm(file, { recursive: true, force: true })
  }
}

/** Deletes one uploaded archive, whether or not it was used. */
export async function discardArchive(name: string): Promise<void> {
  await rm(join(uploadDir(), name), { force: true })
}

/**
 * Runs `edge site <args>` as a one-off and returns what it printed. On
 * failure the error is the one sentence the tool wrote to say what was
 * wrong, which is meant for the operator.
 */
export async function runSiteTool<Report>(
  effects: T.Effects,
  args: string[],
): Promise<Report> {
  const mounts = sdk.Mounts.of()
    .mountVolume({
      volumeId: 'main',
      subpath: uploadSubpath,
      mountpoint: '/upload',
      readonly: true,
    })
    .mountVolume({
      volumeId: 'main',
      subpath: siteSubpath,
      mountpoint: '/site',
      readonly: false,
    })
  const res = await sdk.SubContainer.withTemp(
    effects,
    { imageId: 'lightning-identity' },
    mounts,
    'site-tool',
    (sub) =>
      sub.exec(['/usr/local/bin/edge', 'site', ...args], { user: 'root' }),
  )
  if (res.exitCode !== 0) {
    const said = String(res.stderr).trim().split('\n').pop()
    throw new Error(said || `edge site ${args[0]} failed`)
  }
  return JSON.parse(String(res.stdout)) as Report
}
