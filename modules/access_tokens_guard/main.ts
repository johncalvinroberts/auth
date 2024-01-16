/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { accessTokensGuard, accessTokensLucidProvider } from './define_config.js'

export { AccessToken } from './access_token.js'
export { AccessTokensGuard } from './guard.js'
export { DbAccessTokensProvider } from './token_providers/db.js'
export { AccessTokensLucidUserProvider } from './user_providers/lucid.js'

/**
 * Exposes configuration helpers to configure the access tokens
 * guard and the lucid user provider
 */
export const accessTokens = {
  guard: accessTokensGuard,
  lucidUserProvider: accessTokensLucidProvider,
}
