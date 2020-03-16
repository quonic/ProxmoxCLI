#!/usr/bin/powershell -Command
<#
.Description
Installs and loads all the required modules for the build.
Derived from scripts written by Warren F. (RamblingCookieMonster)
#>

[cmdletbinding()]
param (
    [ValidateSet('Default', 'Build', 'Pester', 'Clean')]
    $Task = 'Default'
)
Write-Output "Starting build"

# Cleans out old versions of modules from CurrentUser, run as admin to remove System installed Modules
if (
    $null -eq $ENV:BHBuildSystem -or
    $null -eq $ENV:BHBranchName -or
    $null -eq $ENV:BHCommitMessage
) {
    Write-Output "  Remove Duplicate and Old Dependent Modules"
    .\build.clean.modules.ps1
}

# Grab nuget bits, install modules, set build variables, start build.
Write-Output "  Install Dependent Modules"
Get-PackageProvider -Name NuGet -ForceBootstrap | Out-Null
Install-Module InvokeBuild, PSDeploy, BuildHelpers, PSScriptAnalyzer, PowerShellForGitHub -force -Scope CurrentUser
Install-Module Pester -Force -SkipPublisherCheck -Scope CurrentUser

Write-Output "  Import Dependent Modules"
Import-Module InvokeBuild, BuildHelpers, PSScriptAnalyzer, PowerShellForGitHub

Set-BuildEnvironment

Write-Output "  InvokeBuild"
Invoke-Build $Task -Result result
if ($Result.Error) {
    Get-ChildItem -Path .\ProxmoxCLI\ -Filter "*.ps1" -Recurse | Invoke-ScriptAnalyzer
    exit 1
}
else {
    exit 0
}