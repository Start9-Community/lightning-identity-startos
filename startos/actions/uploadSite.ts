import { randomBytes } from 'node:crypto'
import { i18n } from '../i18n'
import { sdk } from '../sdk'
import {
  archiveFile,
  archivePath,
  discardArchive,
  maxArchiveBytes,
  prepareFolders,
  runSiteTool,
} from '../site'

const { InputSpec, Value } = sdk

/** What `edge site install` reports (service/internal/site.Report). */
type InstallReport = {
  files: number
  bytes: number
  wrapper: string
  skipped_hidden: number
  skipped_special: number
  removed: number
  kept: boolean
}

const megabytes = (bytes: number) =>
  bytes < 1024 * 1024
    ? `${Math.max(1, Math.round(bytes / 1024))} KB`
    : `${(bytes / (1024 * 1024)).toFixed(1)} MB`

/**
 * Installs a static site from one zip archive. StartOS receives the upload
 * into `upload/` (which nothing serves), and the unpacker — strict about
 * paths, links, hidden files and size; see service/internal/site — turns it
 * into the site in a throwaway container. Edge notices the new site on the
 * next request; nothing restarts.
 */
export const uploadSite = sdk.Action.withInput(
  'upload-site',
  async () => ({
    name: i18n('Upload Site'),
    description: i18n(
      'Serve a static website at the root of your public domain. Upload one .zip archive with an index.html at its top level (a single folder wrapped around everything is fine). Lightning Address, NIP-05 and relay endpoints keep working alongside it.',
    ),
    warning: i18n(
      'Unless "Keep existing files" is on, the files now in the site folder are deleted and replaced by the archive.',
    ),
    allowedStatuses: 'any',
    group: i18n('Static Site'),
    visibility: 'enabled',
  }),
  InputSpec.of({
    archive: Value.dynamicFile(async ({ effects }) => {
      await prepareFolders()
      return {
        name: i18n('Site archive (.zip)'),
        description: i18n(
          'At most 50 MB, 200 MB unpacked and 2,000 files. Hidden files (names starting with a dot, such as .git or .env) are left out, except a top-level .well-known folder.',
        ),
        extensions: ['.zip'],
        required: true,
        uploadId: await sdk.prepareUpload(effects, {
          volume: 'main',
          path: archivePath(randomBytes(8).toString('hex')),
          maxSize: maxArchiveBytes,
          mode: 0o600,
          uid: 0,
          gid: 0,
        }),
      }
    }),
    keep: Value.toggle({
      name: i18n('Keep existing files'),
      description: i18n(
        'Off: the archive becomes the whole site and the files there now are deleted. On: the archive is added to the current site, replacing files with the same path and removing nothing.',
      ),
      default: false,
      warning: null,
    }),
  }),
  async () => null,
  async ({ effects, input }) => {
    const name = input.archive && archiveFile(input.archive.path)
    if (!name) throw new Error(i18n('No archive was uploaded.'))
    let report: InstallReport
    try {
      report = await runSiteTool<InstallReport>(effects, [
        'install',
        '-archive',
        `/upload/${name}`,
        '-dest',
        '/site',
        '-max-archive',
        String(maxArchiveBytes),
        ...(input.keep ? ['-keep'] : []),
      ])
    } finally {
      await discardArchive(name)
    }
    const notes = [
      i18n(
        '${files} files (${size}) are now served at the root of your public domain.',
        { files: report.files, size: megabytes(report.bytes) },
      ),
    ]
    if (report.kept) {
      notes.push(i18n('The files already there were kept.'))
    } else if (report.removed > 0) {
      notes.push(
        i18n('The ${removed} files of the previous site were deleted.', {
          removed: report.removed,
        }),
      )
    }
    if (report.wrapper) {
      notes.push(
        i18n(
          'The folder "${folder}" that wrapped everything in the archive was removed from the paths.',
          { folder: report.wrapper },
        ),
      )
    }
    if (report.skipped_hidden > 0) {
      notes.push(
        i18n('${count} hidden or system files were left out.', {
          count: report.skipped_hidden,
        }),
      )
    }
    if (report.skipped_special > 0) {
      notes.push(
        i18n('${count} links or special files were left out.', {
          count: report.skipped_special,
        }),
      )
    }
    return {
      version: '1',
      title: i18n('Site installed'),
      message: notes.join(' '),
      result: null,
    }
  },
)
