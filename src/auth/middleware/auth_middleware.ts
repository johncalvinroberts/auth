import type { HttpContext } from '@adonisjs/core/http'
import type { NextFn } from '@adonisjs/core/types/http'
import type { Authenticators } from '@adonisjs/auth/types'

/**
 * Options accepted by the middleware options
 */
export type AuthMiddlewareOptions = {
  guards?: (keyof Authenticators)[]
  redirectTo?: string
}

export default class AuthMiddleware {
  async handle(ctx: HttpContext, next: NextFn, options: AuthMiddlewareOptions = {}) {
    await ctx.auth.authenticateUsing(options.guards, options)
    return next()
  }
}
