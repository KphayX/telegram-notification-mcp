/// <reference path="../worker-configuration.d.ts" />

import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";
import { sendTelegramMessage } from "./telegram";

const MCP_ENDPOINT_PATH = "/mcp";
const LEGACY_SSE_ENDPOINT_PATH = "/sse";

function createTelegramMcpServer(environment: Env): McpServer {
	const server = new McpServer({
		name: "Telegram Notification MCP",
		version: "1.1.1",
	});

	server.registerTool(
		"send_telegram_message",
		{
			description: "Send a notification to the fixed, administrator-configured Telegram recipient.",
			annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
			inputSchema: {
				text: z.string().trim().min(1).max(4096),
				parse_mode: z.enum(["Markdown", "HTML"]).optional(),
				disable_notification: z.boolean().optional(),
			},
		},
		async ({ text, parse_mode, disable_notification }) => {
			const botToken = environment.BOT_TOKEN;
			const targetChatId = environment.DEFAULT_CHAT_ID?.trim();

			if (!botToken) {
				return {
					content: [{ type: "text", text: "BOT_TOKEN is not configured" }],
					isError: true,
				};
			}

			if (!targetChatId || !/^-?[1-9]\d{0,15}$/.test(targetChatId)) {
				return {
					content: [
						{
							type: "text",
							text: "DEFAULT_CHAT_ID must contain a valid numeric Telegram chat ID",
						},
					],
					isError: true,
				};
			}

			try {
				const deliveryOutcome = await sendTelegramMessage({
					botToken,
					chatId: targetChatId,
					text,
					parseMode: parse_mode,
					disableNotification: disable_notification,
				});

				if (deliveryOutcome.status === "rejected") {
					return {
						content: [
							{
								type: "text",
								text: `Telegram API rejected the message (${deliveryOutcome.errorCode}): ${deliveryOutcome.description}`,
							},
						],
						isError: true,
					};
				}

				return {
					content: [
						{
							type: "text",
							text: `Message sent successfully to chat ${deliveryOutcome.chatId}`,
						},
					],
				};
			} catch {
				return {
					content: [
						{
							type: "text",
							text: "Telegram delivery could not be confirmed. Do not retry blindly.",
						},
					],
					isError: true,
				};
			}
		},
	);

	return server;
}

async function hashAuthenticationToken(authenticationToken: string) {
	const encodedAuthenticationToken = new TextEncoder().encode(
		authenticationToken,
	);
	return new Uint8Array(
		await crypto.subtle.digest("SHA-256", encodedAuthenticationToken),
	);
}

async function authenticationTokensMatch(
	providedAuthenticationToken: string,
	configuredAuthenticationToken: string,
): Promise<boolean> {
	const [providedTokenHash, configuredTokenHash] = await Promise.all([
		hashAuthenticationToken(providedAuthenticationToken),
		hashAuthenticationToken(configuredAuthenticationToken),
	]);

	let accumulatedDifference = 0;
	for (let byteIndex = 0; byteIndex < configuredTokenHash.length; byteIndex++) {
		accumulatedDifference |=
			providedTokenHash[byteIndex] ^ configuredTokenHash[byteIndex];
	}

	return accumulatedDifference === 0;
}

async function requestIsAuthorized(
	request: Request,
	configuredAuthenticationToken: string,
): Promise<boolean> {
	const authorizationHeader = request.headers.get("Authorization");
	if (!authorizationHeader?.startsWith("Bearer ")) {
		return false;
	}

	const providedAuthenticationToken = authorizationHeader.slice(
		"Bearer ".length,
	);
	return authenticationTokensMatch(
		providedAuthenticationToken,
		configuredAuthenticationToken,
	);
}

function unauthorizedResponse(): Response {
	return Response.json(
		{
			jsonrpc: "2.0",
			error: { code: -32001, message: "Unauthorized" },
			id: null,
		},
		{
			status: 401,
			headers: {
				"WWW-Authenticate": 'Bearer realm="telegram-notification-mcp"',
			},
		},
	);
}

export default {
	async fetch(request: Request, environment: Env, context: ExecutionContext) {
		const url = new URL(request.url);

		if (url.pathname === LEGACY_SSE_ENDPOINT_PATH) {
			return new Response(
				"The legacy SSE endpoint was retired. Use Streamable HTTP at /mcp.",
				{ status: 410 },
			);
		}

		if (url.pathname !== MCP_ENDPOINT_PATH) {
			return new Response("Not found", { status: 404 });
		}

		if (!environment.MCP_AUTH_TOKEN) {
			return new Response("MCP_AUTH_TOKEN is not configured", { status: 503 });
		}

		if (
			request.method !== "OPTIONS" &&
			!(await requestIsAuthorized(request, environment.MCP_AUTH_TOKEN))
		) {
			return unauthorizedResponse();
		}

		const mcpRequestHandler = createMcpHandler(
			() => createTelegramMcpServer(environment),
			{ route: MCP_ENDPOINT_PATH },
		);
		return mcpRequestHandler(request, environment, context);
	},
} satisfies ExportedHandler<Env>;
