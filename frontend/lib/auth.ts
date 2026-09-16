import {
  AuthenticationDetails,
  CognitoUser,
  CognitoUserPool,
  type CognitoUserSession,
} from "amazon-cognito-identity-js";

/**
 * Sign in against the Cognito pool Terraform provisions.
 *
 * Until this existed, `getToken()` in lib/api.ts called `/dev/token` and that
 * was the only authentication path in the frontend. `/dev/token` mints a valid
 * token for ANY tenant to ANY caller, so Terraform correctly leaves DEV_AUTH
 * unset on the API task - which meant the deployed UI called an endpoint that
 * 404s and every page failed. TypeScript was clean and the tests passed
 * throughout, because a token is a `string` either way.
 * See docs/audits/audit-02-frontend-worker-observability.md F1.
 *
 * SRP rather than the hosted UI, because the pool is provisioned with
 * ALLOW_USER_SRP_AUTH and no domain, no callback_urls and no
 * allowed_oauth_flows. A redirect flow would need all three plus a stable
 * frontend hostname, which this deployment does not have. SRP needs none of
 * them and never sends the password.
 */

const POOL_ID = process.env.NEXT_PUBLIC_COGNITO_USER_POOL_ID ?? "";
const CLIENT_ID = process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID ?? "";

/**
 * Whether this build talks to Cognito at all.
 *
 * Unset locally, which selects the DEV_AUTH path and keeps
 * `docker compose up` behaving exactly as it did.
 */
export const cognitoConfigured = Boolean(POOL_ID && CLIENT_ID);

let pool: CognitoUserPool | null = null;

function userPool(): CognitoUserPool {
  // Built lazily and once. Constructing it at module scope would throw during
  // import on a dev build where the ids are empty, taking the whole bundle
  // down rather than falling back.
  pool ??= new CognitoUserPool({
    UserPoolId: POOL_ID,
    ClientId: CLIENT_ID,
  });

  return pool;
}

/**
 * Return the current session, refreshing it if the tokens have aged out.
 *
 * `getSession` is the refresh path: it uses the 30-day refresh token to mint
 * new 60-minute id and access tokens, and only fails once the refresh token
 * itself has expired or been revoked.
 */
function currentSession(): Promise<CognitoUserSession | null> {
  const user = userPool().getCurrentUser();

  if (!user) return Promise.resolve(null);

  return new Promise((resolve) => {
    user.getSession((err: Error | null, session: CognitoUserSession | null) => {
      resolve(err || !session?.isValid() ? null : session);
    });
  });
}

/**
 * The token to send to the API, or null when nobody is signed in.
 *
 * The **ID** token, not the access token. The API sets
 * EXPECTED_TOKEN_USE = "id" and its TOKEN_AUDIENCE is the user pool client
 * id - and `aud` is only the client id on an id token. An access token would
 * be correctly signed by the same pool and rejected for both reasons, which
 * is exactly the confusion app/core/auth.py's token_use check exists to catch.
 */
export async function cognitoIdToken(): Promise<string | null> {
  const session = await currentSession();

  return session?.getIdToken().getJwtToken() ?? null;
}

/** Sign in with email and password. Resolves once a session is stored. */
export function signIn(email: string, password: string): Promise<void> {
  const user = new CognitoUser({ Username: email, Pool: userPool() });

  const details = new AuthenticationDetails({
    Username: email,
    Password: password,
  });

  return new Promise((resolve, reject) => {
    user.authenticateUser(details, {
      onSuccess: () => resolve(),
      onFailure: (err: Error) => reject(err),

      // A pool-created user must set a password before it has a session.
      // Surfaced as its own error rather than a generic failure, because
      // "wrong password" and "you have never set one" need different actions
      // from the person reading it.
      newPasswordRequired: () =>
        reject(
          new Error(
            "This account needs a new password. Set one in the Cognito console, then sign in.",
          ),
        ),
    });
  });
}

/** Forget the stored session. */
export function signOut(): void {
  userPool().getCurrentUser()?.signOut();
}
