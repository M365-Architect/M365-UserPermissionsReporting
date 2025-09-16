# Umfassendes M365 User Permissions Report Script
# WORK IN PROGRESS - BETA VERSION

# Autor: Andreas Hähnel
# Version: 0.1
# Datum: 16.09.2025


<#
.SYNOPSIS
M365 User Permissions Report - Gesamtheitliche Berechtigungsanalyse
.DESCRIPTION
Dieses Skript analysiert alle Berechtigungen eines M365-Benutzers übergreifend:
- Exchange Online (Postfächer, Ordner, Send-As, Full Access)
- SharePoint Online (Sites, Listen, Bibliotheken)
- OneDrive for Business
- Microsoft Teams (Mitgliedschaften, Rollen)
- Azure AD (Gruppen, Rollen, Administrative Units)
- Microsoft 365 Groups
.PARAMETER UserPrincipalName
UPN des zu analysierenden Benutzers (z.B. max.mustermann@contoso.com)
.PARAMETER OutputPath
Pfad für die CSV-Ausgabedatei (Standard: .\UserPermissionsReport_<UPN>_<Datum>.csv)
.PARAMETER IncludeInheritedPermissions
Zeigt auch vererbte Berechtigungen an (kann sehr umfangreich werden)
.EXAMPLE
.\Get-M365UserPermissionsReport.ps1 -UserPrincipalName "max.mustermann@contoso.com"
.EXAMPLE
.\Get-M365UserPermissionsReport.ps1 -UserPrincipalName "max.mustermann@contoso.com" -OutputPath "C:\Reports\MaxReport.csv" -IncludeInheritedPermissions
.NOTES
Autor: M365 Community Script
Version: 1.0
Benötigte Module: ExchangeOnlineManagement, PnP.PowerShell, Microsoft.Graph, MicrosoftTeams
Berechtigungen: Global Reader oder entsprechende Service-spezifische Rollen
#>

[CmdletBinding()]
param(
[Parameter(Mandatory = $true)]
[string]$UserPrincipalName = "spiderman@3q1cnm.onmicrosoft.com",
[Parameter(Mandatory = $false)]
[string]$OutputPath,
[Parameter(Mandatory = $false)]
[switch]$IncludeInheritedPermissions
)

# Globale Variablen
$ErrorActionPreference = "Continue"
$WarningPreference = "SilentlyContinue"
$Results = @()
$StartTime = Get-Date
#$user = Read-Host "Geben Sie den UserPrincipalName (UPN) des zu analysierenden Benutzers ein (z.B. max.mustermann@firma.de)"
#$OutputPath = Read-Host "Geben Sie den Pfad für die CSV-Ausgabedatei ein (z.B. C:\Reports\MaxReport.csv) oder drücken Sie Enter für den Standardpfad"

# Ausgabepfad definieren falls nicht angegeben
if (-not $OutputPath) {
$SafeUPN = $UserPrincipalName -replace '@', '_' -replace '\.', '_'
$DateString = Get-Date -Format "yyyyMMdd_HHmmss"
$OutputPath = ".\UserPermissionsReport_$SafeUPN`_$DateString.csv"
}

Write-Host "🔍 M365 User Permissions Report für: $UserPrincipalName" -ForegroundColor Cyan
Write-Host "📊 Ausgabe: $OutputPath" -ForegroundColor Green
Write-Host "⏰ Start: $StartTime" -ForegroundColor Yellow
Write-Host ""

# Hilfsfunktion zum Hinzufügen von Ergebnissen
function Add-PermissionResult {
param(
[string]$Service,
[string]$ResourceType,
[string]$ResourceName,
[string]$Permission,
[string]$PermissionType,
[string]$GrantedThrough,
[string]$Details
)
$script:Results += [PSCustomObject]@{
Service = $Service
ResourceType = $ResourceType
ResourceName = $ResourceName
Permission = $Permission
PermissionType = $PermissionType
GrantedThrough = $GrantedThrough
Details = $Details
Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}
}

# Modul-Prüfung und Installation
function Test-AndInstallModule {
param([string]$ModuleName)
Write-Host "🔧 Prüfe Modul: $ModuleName" -ForegroundColor Yellow
if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
Write-Host "⚠️ Modul $ModuleName nicht gefunden. Installation wird gestartet..." -ForegroundColor Red
try {
Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser
Write-Host "✅ Modul $ModuleName erfolgreich installiert" -ForegroundColor Green
}
catch {
Write-Error "❌ Fehler bei Installation von $ModuleName`: $_"
return $false
}
}
try {
Import-Module $ModuleName -Force
Write-Host "✅ Modul $ModuleName geladen" -ForegroundColor Green
return $true
}
catch {
Write-Error "❌ Fehler beim Laden von $ModuleName`: $_"
return $false
}
}

# 1. AZURE AD / ENTRA ID ANALYSE
function Get-AzureADPermissions {
Write-Host "🔍 Analysiere Azure AD / Entra ID Berechtigungen..." -ForegroundColor Cyan
try {
# Benutzer-Grundinformationen
$User = Get-MgUser -UserId $UserPrincipalName -ErrorAction Stop
Add-PermissionResult -Service "Azure AD" -ResourceType "User" -ResourceName $User.DisplayName -Permission "User Account" -PermissionType "Identity" -GrantedThrough "Direct" -Details "UPN: $($User.UserPrincipalName), ID: $($User.Id)"
# Gruppenmitgliedschaften
$GroupMemberships = Get-MgUserMemberOf -UserId $User.Id
foreach ($Group in $GroupMemberships) {
$GroupDetails = Get-MgGroup -GroupId $Group.Id -ErrorAction SilentlyContinue
if ($GroupDetails) {
$GroupType = if ($GroupDetails.GroupTypes -contains "Unified") { "M365 Group" } else { "Security Group" }
Add-PermissionResult -Service "Azure AD" -ResourceType $GroupType -ResourceName $GroupDetails.DisplayName -Permission "Member" -PermissionType "Group Membership" -GrantedThrough "Direct" -Details "Group ID: $($GroupDetails.Id)"
}
}
# Administrative Rollen
$RoleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($User.Id)'"
foreach ($Role in $RoleAssignments) {
$RoleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $Role.RoleDefinitionId -ErrorAction SilentlyContinue
if ($RoleDefinition) {
Add-PermissionResult -Service "Azure AD" -ResourceType "Directory Role" -ResourceName $RoleDefinition.DisplayName -Permission "Role Assignment" -PermissionType "Administrative" -GrantedThrough "Direct" -Details "Role ID: $($RoleDefinition.Id)"
}
}
Write-Host "✅ Azure AD Analyse abgeschlossen" -ForegroundColor Green
}
catch {
Write-Warning "⚠️ Azure AD Analyse fehlgeschlagen: $_"
}
}

# 2. EXCHANGE ONLINE ANALYSE
function Get-ExchangeOnlinePermissions {
Write-Host "🔍 Analysiere Exchange Online Berechtigungen..." -ForegroundColor Cyan
try {
# Postfach des Benutzers
$UserMailbox = Get-Mailbox -Identity $UserPrincipalName -ErrorAction SilentlyContinue
if ($UserMailbox) {
Add-PermissionResult -Service "Exchange Online" -ResourceType "Mailbox" -ResourceName $UserMailbox.DisplayName -Permission "Owner" -PermissionType "Mailbox Access" -GrantedThrough "Direct" -Details "Primary SMTP: $($UserMailbox.PrimarySmtpAddress)"
}
# Full Access Berechtigungen auf andere Postfächer
$FullAccessPerms = Get-Mailbox -ResultSize Unlimited | Get-MailboxPermission -User $UserPrincipalName -ErrorAction SilentlyContinue
foreach ($Perm in $FullAccessPerms) {
if ($Perm.AccessRights -contains "FullAccess" -and $Perm.IsInherited -eq $false) {
Add-PermissionResult -Service "Exchange Online" -ResourceType "Mailbox" -ResourceName $Perm.Identity -Permission "Full Access" -PermissionType "Mailbox Access" -GrantedThrough "Direct" -Details "Access Rights: $($Perm.AccessRights -join ', ')"
}
}
# Send As Berechtigungen
$SendAsPerms = Get-Mailbox -ResultSize Unlimited | Get-RecipientPermission -Trustee $UserPrincipalName -ErrorAction SilentlyContinue
foreach ($Perm in $SendAsPerms) {
if ($Perm.AccessRights -contains "SendAs") {
Add-PermissionResult -Service "Exchange Online" -ResourceType "Mailbox" -ResourceName $Perm.Identity -Permission "Send As" -PermissionType "Mailbox Access" -GrantedThrough "Direct" -Details "Trustee Permission"
}
}
# Send on Behalf Berechtigungen
$SendOnBehalfMailboxes = Get-Mailbox -ResultSize Unlimited | Where-Object { $_.GrantSendOnBehalfTo -contains $UserPrincipalName }
foreach ($Mailbox in $SendOnBehalfMailboxes) {
Add-PermissionResult -Service "Exchange Online" -ResourceType "Mailbox" -ResourceName $Mailbox.DisplayName -Permission "Send on Behalf" -PermissionType "Mailbox Access" -GrantedThrough "Direct" -Details "Primary SMTP: $($Mailbox.PrimarySmtpAddress)"
}
# Ordner-Berechtigungen (nur bei eigenem Postfach)
if ($UserMailbox) {
$FolderPerms = Get-MailboxFolderPermission -Identity "$($UserMailbox.PrimarySmtpAddress):\Inbox" -ErrorAction SilentlyContinue
foreach ($FolderPerm in $FolderPerms) {
if ($FolderPerm.User.DisplayName -ne "Default" -and $FolderPerm.User.DisplayName -ne "Anonymous") {
Add-PermissionResult -Service "Exchange Online" -ResourceType "Mailbox Folder" -ResourceName "Inbox" -Permission $FolderPerm.AccessRights -PermissionType "Folder Access" -GrantedThrough "Direct" -Details "User: $($FolderPerm.User.DisplayName)"
}
}
}
Write-Host "✅ Exchange Online Analyse abgeschlossen" -ForegroundColor Green
}
catch {
Write-Warning "⚠️ Exchange Online Analyse fehlgeschlagen: $_"
}
}

# 3. SHAREPOINT ONLINE ANALYSE
function Get-SharePointOnlinePermissions {
Write-Host "🔍 Analysiere SharePoint Online Berechtigungen..." -ForegroundColor Cyan
try {
# Alle Site Collections abrufen
$Sites = Get-PnPTenantSite -IncludeOneDriveSites:$false
foreach ($Site in $Sites) {
try {
Connect-PnPOnline -Url $Site.Url -Interactive -ErrorAction SilentlyContinue
# Site-Berechtigungen prüfen
$SiteUsers = Get-PnPUser | Where-Object { $_.Email -eq $UserPrincipalName -or $_.LoginName -like "*$UserPrincipalName*" }
foreach ($SiteUser in $SiteUsers) {
$UserGroups = Get-PnPGroup | Where-Object { (Get-PnPGroupMember -Identity $_.Title -ErrorAction SilentlyContinue).Email -contains $UserPrincipalName }
foreach ($Group in $UserGroups) {
Add-PermissionResult -Service "SharePoint Online" -ResourceType "Site Collection" -ResourceName $Site.Title -Permission $Group.Title -PermissionType "Site Access" -GrantedThrough "Group Membership" -Details "URL: $($Site.Url)"
}
}
# Listen und Bibliotheken (nur bei expliziten Berechtigungen)
$Lists = Get-PnPList
foreach ($List in $Lists) {
if ($List.HasUniqueRoleAssignments) {
$ListPerms = Get-PnPListItem -List $List.Title -PageSize 1 -ErrorAction SilentlyContinue
# Vereinfachte Prüfung - in Produktionsumgebung würde man hier tiefer gehen
Add-PermissionResult -Service "SharePoint Online" -ResourceType "List/Library" -ResourceName $List.Title -Permission "Custom Permissions" -PermissionType "List Access" -GrantedThrough "Direct" -Details "Site: $($Site.Title)"
}
}
}
catch {
Write-Verbose "Fehler bei Site $($Site.Url): $_"
}
}
Write-Host "✅ SharePoint Online Analyse abgeschlossen" -ForegroundColor Green
}
catch {
Write-Warning "⚠️ SharePoint Online Analyse fehlgeschlagen: $_"
}
}

# 4. ONEDRIVE FOR BUSINESS ANALYSE
function Get-OneDrivePermissions {
Write-Host "🔍 Analysiere OneDrive for Business Berechtigungen..." -ForegroundColor Cyan
try {
# OneDrive Site des Benutzers finden
$OneDriveSites = Get-PnPTenantSite -IncludeOneDriveSites:$true -Filter "Url -like '*-my.sharepoint.com/personal/*'"
$UserOneDrive = $OneDriveSites | Where-Object { $_.Owner -eq $UserPrincipalName -or $_.Url -like "*$($UserPrincipalName.Split('@')[0].Replace('.', '_'))*" }
if ($UserOneDrive) {
Add-PermissionResult -Service "OneDrive" -ResourceType "Personal Site" -ResourceName "OneDrive for Business" -Permission "Owner" -PermissionType "Site Owner" -GrantedThrough "Direct" -Details "URL: $($UserOneDrive.Url)"
# Geteilte Inhalte (vereinfacht)
try {
Connect-PnPOnline -Url $UserOneDrive.Url -Interactive -ErrorAction SilentlyContinue
$SharedItems = Get-PnPList | Where-Object { $_.Title -eq "Documents" }
if ($SharedItems) {
Add-PermissionResult -Service "OneDrive" -ResourceType "Document Library" -ResourceName "Documents" -Permission "Owner" -PermissionType "Library Access" -GrantedThrough "Direct" -Details "Personal OneDrive"
}
}
catch {
Write-Verbose "Fehler beim Zugriff auf OneDrive: $_"
}
}
Write-Host "✅ OneDrive Analyse abgeschlossen" -ForegroundColor Green
}
catch {
Write-Warning "⚠️ OneDrive Analyse fehlgeschlagen: $_"
}
}

# 5. MICROSOFT TEAMS ANALYSE
function Get-TeamsPermissions {
Write-Host "🔍 Analysiere Microsoft Teams Berechtigungen..." -ForegroundColor Cyan
try {
# Teams wo der Benutzer Mitglied ist
$UserTeams = Get-Team | Where-Object {
(Get-TeamUser -GroupId $_.GroupId -ErrorAction SilentlyContinue).User -contains $UserPrincipalName
}
foreach ($Team in $UserTeams) {
$TeamUser = Get-TeamUser -GroupId $Team.GroupId | Where-Object { $_.User -eq $UserPrincipalName }
if ($TeamUser) {
Add-PermissionResult -Service "Microsoft Teams" -ResourceType "Team" -ResourceName $Team.DisplayName -Permission $TeamUser.Role -PermissionType "Team Membership" -GrantedThrough "Direct" -Details "Team ID: $($Team.GroupId)"
# Kanäle in diesem Team
$Channels = Get-TeamChannel -GroupId $Team.GroupId -ErrorAction SilentlyContinue
foreach ($Channel in $Channels) {
if ($Channel.MembershipType -eq "Private") {
$ChannelUsers = Get-TeamChannelUser -GroupId $Team.GroupId -DisplayName $Channel.DisplayName -ErrorAction SilentlyContinue
if ($ChannelUsers.User -contains $UserPrincipalName) {
$ChannelUser = $ChannelUsers | Where-Object { $_.User -eq $UserPrincipalName }
Add-PermissionResult -Service "Microsoft Teams" -ResourceType "Private Channel" -ResourceName $Channel.DisplayName -Permission $ChannelUser.Role -PermissionType "Channel Access" -GrantedThrough "Direct" -Details "Team: $($Team.DisplayName)"
}
}
}
}
}
Write-Host "✅ Teams Analyse abgeschlossen" -ForegroundColor Green
}
catch {
Write-Warning "⚠️ Teams Analyse fehlgeschlagen: $_"
}
}

# 6. MICROSOFT 365 GROUPS ANALYSE
function Get-M365GroupsPermissions {
Write-Host "🔍 Analysiere Microsoft 365 Groups Berechtigungen..." -ForegroundColor Cyan
try {
$M365Groups = Get-UnifiedGroup
foreach ($Group in $M365Groups) {
# Mitglieder prüfen
$Members = Get-UnifiedGroupLinks -Identity $Group.Identity -LinkType Members -ErrorAction SilentlyContinue
if ($Members.PrimarySmtpAddress -contains $UserPrincipalName) {
Add-PermissionResult -Service "Microsoft 365 Groups" -ResourceType "M365 Group" -ResourceName $Group.DisplayName -Permission "Member" -PermissionType "Group Membership" -GrantedThrough "Direct" -Details "Primary SMTP: $($Group.PrimarySmtpAddress)"
}
# Besitzer prüfen
$Owners = Get-UnifiedGroupLinks -Identity $Group.Identity -LinkType Owners -ErrorAction SilentlyContinue
if ($Owners.PrimarySmtpAddress -contains $UserPrincipalName) {
Add-PermissionResult -Service "Microsoft 365 Groups" -ResourceType "M365 Group" -ResourceName $Group.DisplayName -Permission "Owner" -PermissionType "Group Ownership" -GrantedThrough "Direct" -Details "Primary SMTP: $($Group.PrimarySmtpAddress)"
}
}
Write-Host "✅ M365 Groups Analyse abgeschlossen" -ForegroundColor Green
}
catch {
Write-Warning "⚠️ M365 Groups Analyse fehlgeschlagen: $_"
}
}

# HAUPTAUSFÜHRUNG
    try {   
        # Module prüfen und laden
        $RequiredModules = @("Microsoft.Graph", "ExchangeOnlineManagement", "PnP.PowerShell", "MicrosoftTeams")
        $ModulesOK = $true
        foreach ($Module in $RequiredModules) {
        if (-not (Test-AndInstallModule -ModuleName $Module)) {
            $ModulesOK = $false
        }
    }
        if (-not $ModulesOK) {
            throw "Nicht alle erforderlichen Module konnten geladen werden."
    }

    Write-Host ""
    Write-Host "🔐 Authentifizierung wird gestartet..." -ForegroundColor Yellow
    # Authentifizierung
    try {
        Connect-MgGraph -Scopes "User.Read.All", "Group.Read.All", "RoleManagement.Read.Directory" -NoWelcome
        Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -ShowProgress $false
        Connect-PnPOnline -Interactive
        Connect-MicrosoftTeams
        Write-Host "✅ Authentifizierung erfolgreich" -ForegroundColor Green
    }
    catch {
        throw "Authentifizierung fehlgeschlagen: $_"
    }
    Write-Host ""
    Write-Host "🚀 Starte Berechtigungsanalyse..." -ForegroundColor Cyan
    Write-Host ""
    # Analysen ausführen
    Get-AzureADPermissions
    Get-ExchangeOnlinePermissions
    Get-SharePointOnlinePermissions
    Get-OneDrivePermissions
    Get-TeamsPermissions
    Get-M365GroupsPermissions
    # Ergebnisse exportieren
    Write-Host ""
    Write-Host "📊 Exportiere Ergebnisse..." -ForegroundColor Yellow
    if ($Results.Count -gt 0) {
        $Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Host "✅ Report erfolgreich erstellt: $OutputPath" -ForegroundColor Green
        Write-Host "📈 Gefundene Berechtigungen: $($Results.Count)" -ForegroundColor Cyan
        # Zusammenfassung
        Write-Host ""
        Write-Host "📋 ZUSAMMENFASSUNG:" -ForegroundColor Magenta
        $Summary = $Results | Group-Object Service | Sort-Object Count -Descending
        foreach ($Service in $Summary) {
            Write-Host " $($Service.Name): $($Service.Count) Berechtigungen" -ForegroundColor White
        }
    }
    else {
        Write-Warning "⚠️ Keine Berechtigungen gefunden für Benutzer: $UserPrincipalName"
    }
    $EndTime = Get-Date
    $Duration = $EndTime - $StartTime
    Write-Host ""
    Write-Host "⏱️ Gesamtdauer: $($Duration.ToString('hh\:mm\:ss'))" -ForegroundColor Yellow
    Write-Host "🎉 Analyse abgeschlossen!" -ForegroundColor Green
}
catch {
    Write-Error "❌ Kritischer Fehler: $_"
}
finally {
# Verbindungen trennen
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Disconnect-PnPOnline -ErrorAction SilentlyContinue
        Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue
        Write-Host "🔌 Verbindungen getrennt" -ForegroundColor Gray
    }
    catch {
        Write-Verbose "Fehler beim Trennen der Verbindungen: $_"
    }
}
