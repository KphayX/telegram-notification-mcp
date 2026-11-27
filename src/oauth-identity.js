export const SCOPE = "telegram:publish";
export const USER_ID = 106802443;
const USER_LOGIN = "kphayx";

export function isAllowedIdentity(user) {
  return user?.id === USER_ID && typeof user.login === "string" &&
    user.login.toLowerCase() === USER_LOGIN;
}

export function isAuthorizedGrant(ctx) {
  return isAllowedIdentity({ id: ctx.props?.githubId, login: ctx.props?.githubLogin }) &&
    ctx.auth?.userId === "github-" + USER_ID &&
    Array.isArray(ctx.auth.scope) && ctx.auth.scope.includes(SCOPE);
}

