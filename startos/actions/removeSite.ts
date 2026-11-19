import { i18n } from '../i18n'
import { sdk } from '../sdk'
import { prepareFolders, runSiteTool } from '../site'

/**
 * Deletes everything in the site folder. Edge goes back to its plain
 * default page on the next request; nothing restarts.
 */
export const removeSite = sdk.Action.withoutInput(
  'remove-site',
  async () => ({
    name: i18n('Remove Site'),
    description: i18n(
      'Delete the static website served at the root of your public domain. The domain goes back to a plain default page; Lightning Address, NIP-05 and relay endpoints are unaffected.',
    ),
    warning: i18n(
      'Every file in the site folder is deleted. This cannot be undone; keep your own copy of the site.',
    ),
    allowedStatuses: 'any',
    group: i18n('Static Site'),
    visibility: 'enabled',
  }),
  async ({ effects }) => {
    await prepareFolders()
    const { removed } = await runSiteTool<{ removed: number }>(effects, [
      'remove',
      '-dest',
      '/site',
    ])
    return {
      version: '1',
      title:
        removed > 0
          ? i18n('Site removed')
          : i18n('There was no site to remove'),
      message:
        removed > 0
          ? i18n(
              '${removed} files were deleted. Your public domain shows the default page again.',
              { removed },
            )
          : i18n('The site folder was already empty.'),
      result: null,
    }
  },
)
