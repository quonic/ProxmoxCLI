Write-Host "this will report all modules with duplicate (older and newer) versions installed"
Write-Host "be sure to run this as an admin" -foregroundcolor yellow
Write-Host "(You can update all your Azure RMmodules with update-module Azurerm -force)"

$mods = Get-InstalledModule

foreach ($Mod in $mods) {
    Write-Host "Checking $($mod.name)"
    $latest = Get-InstalledModule $mod.name
    $specificmods = Get-InstalledModule $mod.name -allversions
    Write-Host "$($specificmods.count) versions of this module found [ $($mod.name) ]"

    if ($specificmods.Count -gt 1) {
        foreach ($sm in $specificmods) {
            if ($sm.version -eq $latest.version) {
                $color = "green"
                Write-Host " $($sm.name) - $($sm.version) [highest installed is $($latest.version)]" -foregroundcolor $color
            }
            else {
                $color = "magenta"
                Write-Host " $($sm.name) - $($sm.version) [highest installed is $($latest.version)] - Removing..." -foregroundcolor $color
                try {
                    Uninstall-Module -InputObject $sm -Force
                }
                catch {
                    $error[0] | Format-List
                    Write-Host " $($sm.name) - $($sm.version) [highest installed is $($latest.version)] - Skipping" -foregroundcolor $color
                }
                Write-Host " $($sm.name) - $($sm.version) [highest installed is $($latest.version)] - Removed" -foregroundcolor $color
            }
        }
        Write-Host "------------------------"
    }
}
Write-Host "done"