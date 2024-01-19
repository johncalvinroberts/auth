/*
 * @adonisjs/lucid
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * A symbol to identify the type of the real user for a given
 * user provider
 */
export const PROVIDER_REAL_USER = Symbol.for('PROVIDER_REAL_USER')

/**
 * A symbol to identify the type for the events emitted by a guard
 */
export const GUARD_KNOWN_EVENTS = Symbol.for('GUARD_KNOWN_EVENTS')
