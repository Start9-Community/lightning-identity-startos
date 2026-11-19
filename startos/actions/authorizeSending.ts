import { randomBytes } from 'node:crypto'
import { mkdir, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'
import { i18n } from '../i18n'
import { sdk } from '../sdk'

const { InputSpec, Value } = sdk

/**
 * The sending ceremony. This action is the only way to enable sending or to
 * raise a cap: it writes an authorization into `guard/` on the main volume, a
 * directory only the guard subcontainer mounts, so nothing reachable over
 * HTTP can forge it. Lowering caps and disabling are one click in the Admin
 * UI (the safe direction is free). The guard consumes the file within
 * seconds, bakes a spend credential bound to a fresh nonce, and reports the
 * caps it enforces.
 */
export const authorizeSending = sdk.Action.withInput(
  'authorize-sending',
  async () => ({
    name: i18n('Authorize Sending'),
    description: i18n(
      'Enable Nostr Wallet Connect payments from your node, with hard caps the guard enforces inside LND, or change those caps. Disabling and lowering can also be done in the Admin UI; enabling and raising only here.',
    ),
    warning: i18n(
      'While sending is enabled, apps paired over NWC with the pay_invoice permission can spend from your node up to these caps.',
    ),
    allowedStatuses: 'any',
    group: null,
    visibility: 'enabled',
  }),
  InputSpec.of({
    enabled: Value.toggle({
      name: i18n('Sending enabled'),
      description: i18n(
        'Off refuses every payment and removes the spend credential.',
      ),
      default: true,
      warning: null,
    }),
    maxPaymentSat: Value.number({
      name: i18n('Maximum per payment (sats)'),
      description: i18n(
        'A single payment, including its fee reserve, may not exceed this.',
      ),
      required: true,
      default: 25000,
      min: 0,
      max: 100000000,
      integer: true,
      step: null,
      units: 'sats',
      placeholder: null,
      warning: null,
    }),
    max24hSat: Value.number({
      name: i18n('Maximum per 24 hours (sats)'),
      description: i18n(
        'Everything sent in any rolling 24-hour window may not exceed this. Must be at least the per-payment maximum.',
      ),
      required: true,
      default: 100000,
      min: 0,
      max: 1000000000,
      integer: true,
      step: null,
      units: 'sats',
      placeholder: null,
      warning: null,
    }),
  }),
  async () => null,
  async ({ input }) => {
    const maxPaymentMsat = Math.round(input.maxPaymentSat) * 1000
    const max24hMsat = Math.round(input.max24hSat) * 1000
    if (maxPaymentMsat > max24hMsat) {
      throw new Error(
        i18n('The per-payment maximum must not exceed the 24-hour maximum.'),
      )
    }
    const now = new Date()
    const authorization = {
      id: randomBytes(8).toString('hex'),
      created_at: now.toISOString(),
      expires_at: new Date(now.getTime() + 10 * 60 * 1000).toISOString(),
      enabled: input.enabled,
      max_payment_msat: maxPaymentMsat,
      max_24h_msat: max24hMsat,
    }
    const file = sdk.volumes.main.subpath('./guard/authorization.json')
    await mkdir(dirname(file), { recursive: true })
    await writeFile(file, JSON.stringify(authorization, null, 2) + '\n')
    return {
      version: '1',
      title: input.enabled
        ? i18n('Sending authorized')
        : i18n('Sending disabled'),
      message: input.enabled
        ? i18n(
            'The guard applies this within a few seconds and bakes the spend credential once its middleware is registered with LND. The Admin UI dashboard shows the caps in force.',
          )
        : i18n('The guard removes the spend credential within a few seconds.'),
      result: null,
    }
  },
)
