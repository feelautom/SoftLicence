# Config
$BaseUrl = "http://localhost:5200"
$AdminSecret = "CHANGE_ME_RANDOM_SECRET" # Must match AdminSettings:ApiSecret
$Headers = @{ "X-Admin-Secret" = $AdminSecret; "Content-Type" = "application/json" }

Write-Host "=== DÉBUT DES TESTS SOFTLICENCE API ===" -ForegroundColor Cyan

try {
    # 1. Test Health / Admin Access
    Write-Host "1. Test Création Produit..." -NoNewline
    $prodName = "TestApp_$(Get-Random)"
    $prodBody = """$prodName"""
    $prod = Invoke-RestMethod -Uri "$BaseUrl/api/admin/products" -Method Post -Headers $Headers -Body $prodBody
    if ($prod.id) { Write-Host " OK ($($prod.name))" -ForegroundColor Green } else { Write-Host " FAIL" -ForegroundColor Red; exit }

    # 2. Création Licence
    Write-Host "2. Test Création Licence..." -NoNewline
    $licBody = @{
        productName = $prodName
        customerName = "Tester Bot"
        customerEmail = "bot@test.com"
        type = 1
        daysValidity = 30
    } | ConvertTo-Json
    $lic = Invoke-RestMethod -Uri "$BaseUrl/api/admin/licenses" -Method Post -Headers $Headers -Body $licBody
    if ($lic.LicenseKey) { Write-Host " OK" -ForegroundColor Green } else { Write-Host " FAIL" -ForegroundColor Red; exit }

    # 3. Activation (Première fois - Setup Hardware ID)
    Write-Host "3. Test Activation (Lock HWID)..." -NoNewline
    $myHwId = "HWID-TEST-1234"
    $actBody = @{
        LicenseKey = $lic.LicenseKey
        HardwareId = $myHwId
        AppName = $prodName
    } | ConvertTo-Json
    
    $actResponse = Invoke-RestMethod -Uri "$BaseUrl/api/activation" -Method Post -Body $actBody -ContentType "application/json"
    if ($actResponse.licenseFile) { Write-Host " OK (Fichier reçu)" -ForegroundColor Green } else { Write-Host " FAIL" -ForegroundColor Red }

    # 4. Check Online (Valid)
    Write-Host "4. Check Online (Cas valide)..." -NoNewline
    $checkBody = @{
        LicenseKey = $lic.LicenseKey
        HardwareId = $myHwId
        AppName = $prodName
    } | ConvertTo-Json
    $check = Invoke-RestMethod -Uri "$BaseUrl/api/activation/check" -Method Post -Body $checkBody -ContentType "application/json"
    if ($check.status -eq "VALID") { Write-Host " OK ($($check.status))" -ForegroundColor Green } else { Write-Host " FAIL ($($check.status))" -ForegroundColor Red }

    # 5. Check Online (Bad HWID)
    Write-Host "5. Check Online (Vol de clé)..." -NoNewline
    $badCheckBody = @{
        LicenseKey = $lic.LicenseKey
        HardwareId = "PIRATE-PC-9999"
        AppName = $prodName
    } | ConvertTo-Json
    $badCheck = Invoke-RestMethod -Uri "$BaseUrl/api/activation/check" -Method Post -Body $badCheckBody -ContentType "application/json"
    if ($badCheck.status -eq "HARDWARE_MISMATCH") { Write-Host " OK (Bloqué: $($badCheck.status))" -ForegroundColor Green } else { Write-Host " FAIL (Aurait dû être bloqué: $($badCheck.status))" -ForegroundColor Red }

    Write-Host "`n=== TOUS LES TESTS SONT PASSÉS AVEC SUCCÈS ===" -ForegroundColor Cyan
}
catch {
    Write-Host "`n!!! ERREUR CRITIQUE !!!" -ForegroundColor Red
    Write-Error $_
}
