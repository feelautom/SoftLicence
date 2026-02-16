FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY ["src/SoftLicence.Server/SoftLicence.Server.csproj", "SoftLicence.Server/"]
COPY ["src/SoftLicence.SDK/SoftLicence.SDK.csproj", "SoftLicence.SDK/"]
COPY ["LICENSE", "/"]
RUN dotnet restore "SoftLicence.Server/SoftLicence.Server.csproj"
COPY src/ .
WORKDIR "/src/SoftLicence.Server"
RUN dotnet build "SoftLicence.Server.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "SoftLicence.Server.csproj" -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS final
WORKDIR /app
COPY --from=publish /app/publish .

# Installation de rclone et postgresql-client-16 (doit matcher la version du serveur)
RUN apt-get update && apt-get install -y curl unzip gnupg lsb-release \
    && echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list \
    && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/postgresql.gpg \
    && apt-get update && apt-get install -y postgresql-client-16 \
    && curl https://rclone.org/install.sh | bash \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Création du dossier pour la BDD avec les droits pour l'utilisateur 'app' (uid 1654)
RUN mkdir -p /app/data && chown -R 1654:1654 /app/data
EXPOSE 8080
ENTRYPOINT ["dotnet", "SoftLicence.Server.dll"]
