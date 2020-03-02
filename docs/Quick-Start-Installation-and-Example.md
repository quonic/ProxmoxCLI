# Installing ProxmoxCLI

    <!-- # Install ProxmoxCLI from the Powershell Gallery
    Find-Module ProxmoxCLI | Install-Module

    #Import Module
    Import-Module ProxmoxCLI -->

## Building

* Clone this repository.
* `.\build.ps1`
* `Import-Module .\output\ProxmoxCLI\`

## Using ProxmoxCLI

* Connect to a Proxmox sever with `Connect-PveServer -Server "Proxmox1"`, use `-BypassSSLCheck` if your computer doesn't trust the SSL cert from the Proxmox server.
* Run `Get-Node | Get-Guest` and you should see a list of your guests.
