# ==========================================
# NEUS Vaccine Test - מבחן החיסון
# ==========================================
# This script tests the full feedback loop:
# Sentinel -> NEUS -> ActiveBrain -> Patch -> Sentinel

Write-Host "🧪 NEUS VACCINE TEST - מבחן החיסון" -ForegroundColor Cyan
Write-Host "=" * 50

# Step 1: Check if Sentinel is running
Write-Host "`n📡 Step 1: Checking Sentinel status..." -ForegroundColor Yellow
try {
    $sentinelHealth = Invoke-RestMethod -Uri "http://localhost:8081/health" -Method Get -TimeoutSec 5
    Write-Host "✅ Sentinel is running: $($sentinelHealth.client_id)" -ForegroundColor Green
}
catch {
    Write-Host "❌ Sentinel is not running! Start it with: go run main.go" -ForegroundColor Red
    Write-Host "   Starting Sentinel in background..." -ForegroundColor Yellow
    Start-Process -FilePath "go" -ArgumentList "run", "main.go" -WorkingDirectory "c:\Projects\Sentinel" -WindowStyle Hidden
    Start-Sleep -Seconds 3
}

# Step 2: Check if NEUS is running
Write-Host "`n🧠 Step 2: Checking NEUS server status..." -ForegroundColor Yellow
try {
    $neusHealth = Invoke-RestMethod -Uri "http://localhost:8080/health" -Method Get -TimeoutSec 5
    Write-Host "✅ NEUS is running: $($neusHealth.service)" -ForegroundColor Green
}
catch {
    Write-Host "❌ NEUS is not running on port 8080!" -ForegroundColor Red
    Write-Host "   Start NEUS with: python neus_ui_server_clean.py" -ForegroundColor Yellow
    exit 1
}

# Step 3: Send suspicious query to trigger detection
Write-Host "`n🎯 Step 3: Sending suspicious query to NEUS..." -ForegroundColor Yellow
$threatData = @{
    type        = "sql_injection"
    description = "Suspicious query attempting to access internal secrets"
    severity    = "high"
    indicators  = @("internal_secrets", "SELECT * FROM")
    source_ip   = "192.168.1.100"
} | ConvertTo-Json

try {
    $headers = @{ "X-API-Key" = "neus-dev-key-2025"; "Content-Type" = "application/json" }
    $patchResponse = Invoke-RestMethod -Uri "http://localhost:8080/api/sentinel/deploy_patch" -Method Post -Body $threatData -Headers $headers -TimeoutSec 15

    Write-Host "✅ NEUS Response:" -ForegroundColor Green
    Write-Host "   Status: $($patchResponse.status)" -ForegroundColor White
    Write-Host "   Message: $($patchResponse.message)" -ForegroundColor White
    Write-Host "   Threat Type: $($patchResponse.patch_generated.threat_type)" -ForegroundColor White
    Write-Host "   Confidence: $($patchResponse.patch_generated.confidence)" -ForegroundColor White
    Write-Host "   Encrypted: $($patchResponse.patch_generated.encrypted)" -ForegroundColor White
    Write-Host "   Signed: $($patchResponse.patch_generated.signed)" -ForegroundColor White

    Write-Host "`n🔐 Security Protocol:" -ForegroundColor Cyan
    Write-Host "   Protocol: $($patchResponse.security.protocol)" -ForegroundColor White
    Write-Host "   Encryption: $($patchResponse.security.encryption)" -ForegroundColor White
    Write-Host "   Signature: $($patchResponse.security.signature)" -ForegroundColor White

}
catch {
    Write-Host "❌ Failed to deploy patch: $_" -ForegroundColor Red
}

# Step 4: Send fingerprint to NEUS for neural analysis
Write-Host "`n🔬 Step 4: Sending fingerprint to NEUS for neural analysis..." -ForegroundColor Yellow
$fingerprint = @{
    client_id   = "sentinel-test"
    fingerprint = @{
        query_length = 35
        token_count  = 5
        hash         = "abc123"
    }
} | ConvertTo-Json

try {
    $headers = @{ "X-API-Key" = "neus-dev-key-2025"; "Content-Type" = "application/json" }
    $analysisResponse = Invoke-RestMethod -Uri "http://localhost:8080/api/sentinel/fingerprint" -Method Post -Body $fingerprint -Headers $headers -TimeoutSec 10

    Write-Host "✅ Neural Analysis:" -ForegroundColor Green
    Write-Host "   Status: $($analysisResponse.status)" -ForegroundColor White
    Write-Host "   Verdict: $($analysisResponse.verdict)" -ForegroundColor White
    Write-Host "   Message: $($analysisResponse.message)" -ForegroundColor White

}
catch {
    Write-Host "❌ Fingerprint analysis failed: $_" -ForegroundColor Red
}

# Step 5: Check Sentinel status after patch
Write-Host "`n📊 Step 5: Checking Sentinel status after hot-patch..." -ForegroundColor Yellow
try {
    $headers = @{ "X-API-Key" = "neus-dev-key-2025" }
    $sentinelStatus = Invoke-RestMethod -Uri "http://localhost:8080/api/sentinel/status" -Method Get -Headers $headers -TimeoutSec 10

    Write-Host "✅ Sentinel Network Status:" -ForegroundColor Green
    Write-Host "   Total Sentinels: $($sentinelStatus.summary.total_sentinels)" -ForegroundColor White
    Write-Host "   Online: $($sentinelStatus.summary.online_sentinels)" -ForegroundColor White
    Write-Host "   Neural Tunnel Active: $($sentinelStatus.summary.neural_tunnel_active)" -ForegroundColor White

}
catch {
    Write-Host "⚠️ Could not get Sentinel status: $_" -ForegroundColor Yellow
}

# Step 6: Check activity log
Write-Host "`n📜 Step 6: Checking Sentinel activity log..." -ForegroundColor Yellow
try {
    $headers = @{ "X-API-Key" = "neus-dev-key-2025" }
    $activity = Invoke-RestMethod -Uri "http://localhost:8080/api/sentinel/activity" -Method Get -Headers $headers -TimeoutSec 10

    Write-Host "✅ Activity Summary:" -ForegroundColor Green
    Write-Host "   Total Entries: $($activity.total_entries)" -ForegroundColor White
    Write-Host "   Unique Sentinels: $($activity.summary.unique_sentinels)" -ForegroundColor White
    Write-Host "   Queries Analyzed: $($activity.summary.total_queries_analyzed)" -ForegroundColor White

}
catch {
    Write-Host "⚠️ Could not get activity log: $_" -ForegroundColor Yellow
}

Write-Host "`n" + "=" * 50 -ForegroundColor Cyan
Write-Host "🎉 VACCINE TEST COMPLETE!" -ForegroundColor Green
Write-Host "=" * 50
Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "1. Open NEUS Dashboard: http://localhost:8080/neural-dashboard" -ForegroundColor White
Write-Host "2. Monitor real-time activity" -ForegroundColor White
Write-Host "3. Try more attack patterns to train the system" -ForegroundColor White
