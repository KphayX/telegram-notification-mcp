param(
    [string]$Endpoint = 'https://telegram-notification-mcp.dvson-dev.workers.dev/mcp'
)
$ErrorActionPreference = 'Stop'
if ($Endpoint -ne 'https://telegram-notification-mcp.dvson-dev.workers.dev/mcp') {
    throw 'Unexpected endpoint. Review the script before changing the recipient of credentials.'
}
$accept = @{ Accept = 'application/json, text/event-stream' }
function Assert-Unauthorized($headers, $label) {
    $status = 0
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $Endpoint -Headers $headers -Method Get -TimeoutSec 20
        $status = [int]$response.StatusCode
    } catch {
        if ($null -ne $_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        else { throw "$label : endpoint unreachable" }
    }
    if ($status -ne 401) { throw "$label : expected 401, got $status" }
    Write-Host "PASS: $label (401)"
}
Assert-Unauthorized $accept 'Missing token'
Assert-Unauthorized @{ Accept = $accept.Accept; Authorization = 'Bearer invalid-smoke-test-token' } 'Invalid token'
$secure = Read-Host 'MCP_AUTH_TOKEN (not BOT_TOKEN)' -AsSecureString
$token = [System.Net.NetworkCredential]::new('', $secure).Password
$headers = @{ Accept = $accept.Accept; Authorization = "Bearer $token" }
function Invoke-Mcp($method, $params, $id) {
    $body = @{ jsonrpc = '2.0'; method = $method; params = $params }
    if ($null -ne $id) { $body.id = $id }
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $Endpoint -Headers $headers -Method Post -ContentType 'application/json' -Body ($body | ConvertTo-Json -Depth 12 -Compress) -TimeoutSec 30
    } catch {
        if ($null -ne $_.Exception.Response) { throw "MCP $method failed: HTTP $([int]$_.Exception.Response.StatusCode)" }
        throw "MCP $method failed: transport error; delivery may be unknown"
    }
    if ($null -eq $id) { return }
    $raw = [string]$response.Content
    if ($raw.TrimStart().StartsWith('{')) { $reply = $raw | ConvertFrom-Json }
    else {
        $reply = $null
        foreach ($line in ($raw -split '\r?\n')) {
            if ($line.StartsWith('data:')) {
                $candidate = $line.Substring(5).Trim() | ConvertFrom-Json
                if ($candidate.id -eq $id) { $reply = $candidate; break }
            }
        }
    }
    if ($null -eq $reply -or $reply.id -ne $id -or $null -ne $reply.error) {
        throw "MCP $method failed: invalid or error JSON-RPC response"
    }
    if ($response.Headers['Mcp-Session-Id']) { $headers['Mcp-Session-Id'] = [string]$response.Headers['Mcp-Session-Id'] }
    return $reply.result
}
try {
    $init = Invoke-Mcp 'initialize' @{ protocolVersion = '2025-11-25'; capabilities = @{}; clientInfo = @{ name = 'telegram-poc-smoke-test'; version = '1.0.0' } } 1
    if (-not $init.protocolVersion) { throw 'MCP initialize returned no protocol version' }
    $headers['MCP-Protocol-Version'] = $init.protocolVersion
    Invoke-Mcp 'notifications/initialized' @{} $null
    Write-Host 'PASS: authenticated MCP initialization'
    $tools = Invoke-Mcp 'tools/list' @{} 2
    $tool = $tools.tools | Where-Object { $_.name -eq 'send_telegram_message' } | Select-Object -First 1
    if (-not $tool -or $tool.inputSchema.properties.PSObject.Properties.Name -contains 'chat_id') {
        throw 'Recipient restriction not verified; no message sent.'
    }
    Write-Host 'PASS: tool discovery, no recipient override'
    $result = Invoke-Mcp 'tools/call' @{ name = 'send_telegram_message'; arguments = @{ text = 'Telegram MCP POC: authenticated smoke test succeeded.' } } 3
    if ($result.isError -or -not ($result.content | Where-Object { $_.type -eq 'text' -and $_.text -like 'Message sent successfully*' })) {
        throw 'Telegram delivery not confirmed. Do not retry blindly.'
    }
    Write-Host 'PASS: Telegram API accepted the test message'
} finally {
    $headers.Clear()
    Remove-Variable token, secure -ErrorAction SilentlyContinue
}
