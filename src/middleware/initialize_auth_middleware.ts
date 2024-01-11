/// <reference types="@adonisjs/core/providers/edge_provider" />

import auth from '@adonisjs/auth/services/main'
import type { HttpContext } from '@adonisjs/core/http'
import type { NextFn } from '@adonisjs/core/types/http'

/**
 * The "InitializeAuthMiddleware" is used to create a request
 * specific authenticator instance for every HTTP request.
 *
 * This middleware does not protect routes from unauthenticated
 * users. Please use the "auth" middleware for that.
 */
export default class InitializeAuthMiddleware {
  async handle(ctx: HttpContext, next: NextFn) {
    /**
     * Initialize the authenticator for the current HTTP
     * request
     */
    ctx.auth = auth.createAuthenticator(ctx)

    /**
     * Sharing authenticator with templates
     */
    if ('view' in ctx) {
      ctx.view.share({ auth: ctx.auth })
    }

    return next()
  }
}

declare module '@adonisjs/core/http' {
  export interface HttpContext {
    auth: ReturnType<(typeof auth)['createAuthenticator']>
  }
}
