import { primaryUrl } from '../primaryUrl'
import { sdk } from '../sdk'
import { authorizeSending } from './authorizeSending'
import { rebakeCredentials } from './rebakeCredentials'
import { removeSite } from './removeSite'
import { setAdminPassword } from './setAdminPassword'
import { uploadSite } from './uploadSite'

export const actions = sdk.Actions.of()
  .addAction(primaryUrl.action)
  .addAction(setAdminPassword)
  .addAction(rebakeCredentials)
  .addAction(authorizeSending)
  .addAction(uploadSite)
  .addAction(removeSite)
