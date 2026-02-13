param (
    [switch]$Clean = $false,
    [switch]$Run = $false,
    [switch]$Test = $false
)

$ErrorActionPreference = "Stop"
$OriginalLocation = Get-Location
$ProjectRoot = Resolve-Path "$PSScriptRoot/.."

try {
    # 1. Déplacement à la racine du projet
    Set-Location $ProjectRoot
    Write-Host "=== SOFTLICENCE BUILD SYSTEM ===" -ForegroundColor Cyan
    Write-Host "Racine du projet : $ProjectRoot" -ForegroundColor DarkGray

    $SolutionPath = "src/SoftLicence.sln"

    # 2. Nettoyage (Optionnel)
    if ($Clean) {
        Write-Host "-> Nettoyage..." -ForegroundColor Cyan
        dotnet clean $SolutionPath
        Remove-Item -Path "src/*/bin", "src/*/obj" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "samples/*/bin", "samples/*/obj" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "tests/*/bin", "tests/*/obj" -Recurse -Force -ErrorAction SilentlyContinue
    }

    # 3. Build
    Write-Host "-> Restauration des paquets..." -ForegroundColor Cyan
    dotnet restore $SolutionPath

    Write-Host "-> Compilation de la solution..." -ForegroundColor Cyan
    dotnet build $SolutionPath --configuration Release

    if ($LASTEXITCODE -eq 0) {
        Write-Host "`n=== BUILD SUCCES ===" -ForegroundColor Green

        # 3.5 Tests Unitaires (Si demandé)
        if ($Test) {
            Write-Host "`n-> Exécution des tests unitaires..." -ForegroundColor Cyan
            dotnet test $SolutionPath --configuration Release --no-build --verbosity minimal
            if ($LASTEXITCODE -ne 0) {
                Write-Host "`n!!! TESTS ECHOUES !!!" -ForegroundColor Red
                exit 1
            }
            Write-Host "=== TESTS REUSSIS ===" -ForegroundColor Green
        }
        
        # 4. Info Serveur
        Write-Host "`n[SERVEUR PRET]" -ForegroundColor Cyan
        Write-Host "URL : http://localhost:5200"
        Write-Host "---------------------------"

        if ($Run) {
            Write-Host "-> Configuration de l'environnement..." -ForegroundColor Cyan
            $env:AdminSettings__LoginPath = "my-secret-login"
            $env:AdminSettings__Username = "admin"
            $env:AdminSettings__Password = "CHANGE_ME"
            $env:AdminSettings__ApiSecret = "CHANGE_ME_RANDOM_SECRET"

            # Configuration for local dev (Docker port 5435)
            $env:DB_TYPE = "PostgreSQL"
            $env:ConnectionStrings__DefaultConnection = "Host=localhost;Port=5435;Database=db_softlicence;Username=postgres;Password=CHANGE_ME"

            # Vérification de Docker pour PostgreSQL local
            if (Get-Command docker -ErrorAction SilentlyContinue) {
                try {
                    docker ps -q > $null
                    if ($LASTEXITCODE -ne 0) {
                        Write-Host "ATTENTION: Docker n'est pas lancé. Le serveur risque d'échouer sans base de données." -ForegroundColor Yellow
                    }
                } catch {
                    Write-Host "ATTENTION: Impossible de contacter Docker. Le serveur risque d'échouer sans base de données." -ForegroundColor Yellow
                }
            } else {
                Write-Host "ATTENTION: Docker n'est pas installé. Le serveur risque d'échouer sans base de données." -ForegroundColor Yellow
            }

            Write-Host "-> Démarrage du serveur (Ctrl+C pour arrêter)..." -ForegroundColor Cyan
            Set-Location "src/SoftLicence.Server"
            dotnet run --urls "http://0.0.0.0:5200"
        }
    } else {
        Write-Host "`n!!! BUILD ERROR !!!" -ForegroundColor Red
        exit 1
    }
}
catch {
    Write-Host "`n!!! ERREUR CRITIQUE !!!" -ForegroundColor Red
    Write-Error $_
    exit 1
}
finally {
    # 5. Retour au dossier d'origine QUOI QU'IL ARRIVE
    Set-Location $OriginalLocation
}
