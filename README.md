# ProxmoxCLI

A Proxmox module for accessing your Proxmox APIs similar in functionality to PowerCLI for VMWare

## Current Stage

* Developing and Testing
* NOT Production Ready, yet.
* Work on a way to dynamicly generating cmdlets from [apidata.js](https://raw.githubusercontent.com/proxmox/pve-docs/master/api-viewer/apidata.js)

[![Build status](https://ci.appveyor.com/api/projects/status/pxsta8uglrc9kql8?svg=true)](https://ci.appveyor.com/project/quonic/proxmoxcli)

## GitPitch PitchMe presentation

* [gitpitch.com/quonic/ProxmoxCLI](https://gitpitch.com/quonic/ProxmoxCLI)

## Contributing

See [CONTRIBUTING.md](/CONTRIBUTING.md).

<!-- ## Getting Started

Install from the PSGallery and Import the module

    Install-Module ProxmoxCLI
    Import-Module ProxmoxCLI -->

### Building

* Clone this repository.
* `.\build.ps1`
* `Import-Module .\output\ProxmoxCLI\`

### Using ProxmoxCLI

* Connect to a Proxmox sever with `Connect-PveServer -Server "Proxmox1"`, use `-BypassSSLCheck` if your computer doesn't trust the SSL cert from the Proxmox server.
* Run `Get-Node | Get-Guest` and you should see a list of your guests.

## More Information

For more information

<!-- * [ProxmoxCLI.readthedocs.io](http://ProxmoxCLI.readthedocs.io) -->
* [github.com/quonic/ProxmoxCLI](https://github.com/quonic/ProxmoxCLI)
<!-- * [quonic.github.io](https://quonic.github.io) -->

This project was generated using [Kevin Marquette](http://kevinmarquette.github.io)'s [Full Module Plaster Template](https://github.com/KevinMarquette/PlasterTemplates/tree/master/FullModuleTemplate).
