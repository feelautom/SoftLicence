# Admin-Cli.ps1 - Gestionnaire de Licences SoftLicence
# Usage: . .\Admin-Cli.ps1

$ServerUrl = "http://127.0.0.1:5200"
$AdminSecret = "CHANGE_ME_RANDOM_SECRET" # Doit correspondre à AdminSettings:ApiSecret dans appsettings.json

function New-SoftProduct {
    param([string]$Name)
    
    if ([string]::IsNullOrWhiteSpace($Name)) { Write-Error "Le nom du produit est requis."; return }

    $headers = @{ "X-Admin-Secret" = $AdminSecret; "Content-Type" = "application/json" }
    $body = """$Name""" # JSON string

    try {
        $response = Invoke-RestMethod -Uri "$ServerUrl/api/admin/products" -Method Post -Headers $headers -Body $body
        
        Write-Host "`n=== PRODUIT CRÉÉ AVEC SUCCÈS ===" -ForegroundColor Green
        Write-Host "Nom : $($response.name)"
        Write-Host "ID  : $($response.id)"
        Write-Host "`nCLÉ PUBLIQUE (À copier dans App.xaml.cs du client) :" -ForegroundColor Cyan
        Write-Host $response.publicKeyXml
        Write-Host "`n=================================="
    }
    catch {
        Write-Error $_.Exception.Message
    }
}

function Get-SoftProducts {
    $headers = @{ "X-Admin-Secret" = $AdminSecret }
    try {
        $response = Invoke-RestMethod -Uri "$ServerUrl/api/admin/products" -Method Get -Headers $headers
        $response | Format-Table Id, Name
    }
    catch { Write-Error $_.Exception.Message }
}

function New-SoftLicense {
    param(
        [string]$ProductName,
        [string]$CustomerName,
        [string]$Email = "unknown@client.com",
        [int]$Days = 365,
        [string]$Reference = ""
    )

    if ([string]::IsNullOrWhiteSpace($ProductName)) { Write-Error "Nom du produit requis."; return }

    $headers = @{ "X-Admin-Secret" = $AdminSecret; "Content-Type" = "application/json" }
    
    $bodyHash = @{
        productName = $ProductName
        customerName = $CustomerName
        customerEmail = $Email
        typeSlug = "STANDARD"
        daysValidity = $Days
    }
    if ($Reference) { $bodyHash.reference = $Reference }
    $body = $bodyHash | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Uri "$ServerUrl/api/admin/licenses" -Method Post -Headers $headers -Body $body
        
        Write-Host "`n=== LICENCE GÉNÉRÉE ===" -ForegroundColor Green
        Write-Host "Produit : $ProductName"
        Write-Host "Client  : $CustomerName"
        Write-Host "CLÉ     : $($response.LicenseKey)" -ForegroundColor Yellow
        Write-Host "======================="
    }
    catch {
        Write-Error $_.Exception.Message
    }
}

Write-Host "SoftLicence Admin Tools chargé."
Write-Host "Commandes disponibles :"
Write-Host "  New-SoftProduct 'NomApp'"
Write-Host "  Get-SoftProducts"
Write-Host "  New-SoftLicense 'NomApp' 'NomClient'"
