# A real multi-stage build: the runner never sees node_modules, the source, or
# the build toolchain. None of it can leak from the image because none of it is
# in the image.

# Base images are pinned by digest, not tag. `python:3.12-slim` today and next
# month are different images, so a tag lets a rebuild change the runtime with
# no commit of yours. The cost is that patches stop arriving on their own -
# refresh with `docker inspect --format='{{index .RepoDigests 0}}' <tag>` on a
# schedule and land it as a reviewable commit.
FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS deps

WORKDIR /app

COPY package.json package-lock.json ./

# ci, not install: it installs exactly what the lockfile says and fails if the
# lockfile is stale, which is what a build wants.
RUN npm ci


FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS builder

WORKDIR /app

# NEXT_PUBLIC_ values are inlined into the client bundle at build time, so they
# have to exist during `npm run build` rather than at container start. Anything
# passed this way is visible in `docker history` - URLs yes, keys never.
ARG NEXT_PUBLIC_API_URL
ARG NEXT_PUBLIC_WS_URL

ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL \
    NEXT_PUBLIC_WS_URL=$NEXT_PUBLIC_WS_URL \
    NEXT_TELEMETRY_DISABLED=1

COPY --from=deps /app/node_modules ./node_modules

COPY . .

RUN npm run build


FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS runner

WORKDIR /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

RUN addgroup --system --gid 1001 nodejs \
 && adduser --system --uid 1001 --ingroup nodejs nextjs

COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["node", "-e", "require('http').get('http://127.0.0.1:3000/',r=>process.exit(r.statusCode<400?0:1)).on('error',()=>process.exit(1))"]

CMD ["node", "server.js"]
