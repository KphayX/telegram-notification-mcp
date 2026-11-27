import { describe, expect, it } from "vitest";
import { isAllowedIdentity, isAuthorizedGrant } from "./oauth-identity.js";

describe("OAuth allowlist", () => {
	it("requires both immutable ID and login", () => {
		expect(isAllowedIdentity({ id: 106802443, login: "KphayX" })).toBe(true);
		expect(isAllowedIdentity({ id: 1, login: "KphayX" })).toBe(false);
		expect(isAllowedIdentity({ id: 106802443, login: "other" })).toBe(false);
	});
	it("requires the verified subject and publish scope", () => {
		const props = { githubId: 106802443, githubLogin: "KphayX" };
		expect(isAuthorizedGrant({ props, auth: { userId: "github-106802443", scope: ["telegram:publish"] } })).toBe(true);
		expect(isAuthorizedGrant({ props, auth: { userId: "github-106802443", scope: [] } })).toBe(false);
		expect(isAuthorizedGrant({ props, auth: { userId: "github-1", scope: ["telegram:publish"] } })).toBe(false);
		expect(isAuthorizedGrant({ props })).toBe(false);
	});
});
