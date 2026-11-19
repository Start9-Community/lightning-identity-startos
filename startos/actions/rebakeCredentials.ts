import { i18n } from '../i18n'
import { sdk } from '../sdk'

/**
 * Restarts the service so the guard bakes fresh credentials at once — after
 * LND's "Revoke Macaroons", or after restoring a backup onto another node.
 * The guard renews on its own every hour; this is the impatient path.
 */
export const rebakeCredentials = sdk.Action.withoutInput(
  'rebake-credentials',
  async () => ({
    name: i18n('Rebake Credentials'),
    description: i18n(
      'Restart the service so the guard immediately bakes a fresh receive credential from LND. Use after revoking macaroons in LND or restoring onto a different node.',
    ),
    warning: i18n(
      'The service restarts; addresses are unreachable for a few seconds.',
    ),
    allowedStatuses: 'only-running',
    group: null,
    visibility: 'enabled',
  }),
  async ({ effects }) => {
    await sdk.restart(effects)
    return {
      version: '1',
      title: i18n('Restarting'),
      message: i18n('The guard bakes a new credential as soon as LND answers.'),
      result: null,
    }
  },
)
