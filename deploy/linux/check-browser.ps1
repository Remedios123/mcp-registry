param([uri]$Gateway = 'http://10.100.3.74:443')
$ErrorActionPreference = 'Stop'
$origin = $Gateway.GetLeftPart([UriPartial]::Authority)
foreach ($path in @('/', '/realms/mcp-gateway/.well-known/openid-configuration')) {
    $response = Invoke-WebRequest -UseBasicParsing -Uri ($origin + $path) -TimeoutSec 15
    Write-Output "WINDOWS $path HTTP $($response.StatusCode)"
    if ($path -like '*/openid-configuration') {
        $expected = "$origin/realms/mcp-gateway"
        if (($response.Content | ConvertFrom-Json).issuer -ne $expected) {
            throw "Issuer mismatch: expected $expected"
        }
    }
}
Write-Output "Manual browser login and WorkBuddy initialize remain to be checked: $origin/airegistry-tools/mcp"
