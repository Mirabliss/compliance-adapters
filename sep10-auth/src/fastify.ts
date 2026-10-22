/**
 * Copyright (c) 2026 stellar-compliance-kit
 * SPDX-License-Identifier: MIT
 */

import type { FastifyInstance, FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import { noopLogger } from '@compliance-adapters/logger';
import {
  Sep10MiddlewareOptions,
  applyRevocationStore,
  assertSep10MiddlewareOptions,
  verifyRequestHeaders,
} from './middleware';

declare module 'fastify' {
  interface FastifyRequest {
    stellarAddress?: string;
  }
  interface FastifyInstance {
    /** `preHandler` that authenticates a single route. See {@link Sep10FastifyOptions.global}. */
    sep10Authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

export interface Sep10FastifyOptions extends Sep10MiddlewareOptions {
  /**
   * Authenticate every route in the scope the plugin is registered in, the
   * counterpart of `app.use(createSep10Middleware(...))` in Express. Set to
   * `false` to only decorate `fastify.sep10Authenticate` and attach it to
   * individual routes as a `preHandler`.
   * @default true
   */
  global?: boolean;
}

/**
 * Fastify plugin that authenticates requests with a signed SEP-10 challenge
 * sent as `Authorization: Bearer <base64-xdr>` and decorates
 * `request.stellarAddress` on success. It shares its authentication logic with
 * {@link createSep10Middleware}, so responses match the Express adapter,
 * including the RFC 6750 `WWW-Authenticate` header on `401`.
 *
 * @example
 * ```ts
 * import Fastify from 'fastify';
 * import { sep10Plugin } from 'sep10-auth/fastify';
 *
 * const app = Fastify();
 * await app.register(sep10Plugin, {
 *   serverAccountId: serverKeypair.publicKey(),
 *   homeDomains: 'example.com',
 *   webAuthDomain: 'example.com',
 * });
 * app.get('/status', async (request) => ({ address: request.stellarAddress }));
 * ```
 */
export const sep10Plugin: FastifyPluginAsync<Sep10FastifyOptions> = fp(
  async (fastify: FastifyInstance, options: Sep10FastifyOptions) => {
    const logger = options.logger ?? noopLogger;
    assertSep10MiddlewareOptions(options);

    fastify.decorateRequest('stellarAddress', undefined);

    const authenticate = async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
      let result = await verifyRequestHeaders(request.headers, options);

      if (result.ok && options.revocationStore) {
        try {
          result = await applyRevocationStore(result, options);
        } catch (error) {
          logger.error('sep10-auth: revocation store lookup failed', error);
          throw error;
        }
      }

      if (!result.ok) {
        logger.warn(result.logMessage, {
          ...result.logContext,
          ip: request.ip,
          path: request.url,
        });
        reply
          .code(401)
          .header('WWW-Authenticate', result.wwwAuthenticate)
          .send({ error: 'unauthorized', reason: result.reason });
        return;
      }

      logger.debug('sep10-auth: request authenticated', {
        address: result.address,
        path: request.url,
      });
      request.stellarAddress = result.address;
    };

    fastify.decorate('sep10Authenticate', authenticate);

    if (options.global !== false) {
      fastify.addHook('onRequest', authenticate);
    }
  },
  { name: 'sep10-auth', fastify: '>=4.0.0' },
);

export default sep10Plugin;
