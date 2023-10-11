/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { createError } from '@poppinss/utils'

/**
 * Invalid token provided
 */
export const E_INVALID_AUTH_TOKEN = createError(
  'Invalid or expired token value',
  'E_INVALID_AUTH_TOKEN',
  401
)
