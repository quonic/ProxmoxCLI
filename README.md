# ProxmoxCLI

A Proxmox module for accessing your Proxmox APIs

## Current Stage

* Developing and Testing
* NOT Production Ready, yet.

[![Build status](https://ci.appveyor.com/api/projects/status/pxsta8uglrc9kql8?svg=true)](https://ci.appveyor.com/project/quonic/proxmoxcli)

## GitPitch PitchMe presentation

* [gitpitch.com/quonic/ProxmoxCLI](https://gitpitch.com/quonic/ProxmoxCLI)

## Contributing

Testing, writing code, submitting bugs, and suggesting ideas are all welcome. At the time of writing I'm primarily focused on creating cmdlets for all related API calls. See [Guests](/ProxmoxCLI/public/Guests.ps1) as an example of how I would like it to look like, but I do welcome ideas.

My only requirement for pull requests is to keep the commits related to each other in the pull request.

<!-- ## Getting Started

Install from the PSGallery and Import the module

    Install-Module ProxmoxCLI
    Import-Module ProxmoxCLI -->

### Building

* Clone this repository.
* Run `.\build\ps1`
* Run `Import-Module .\output\ProxmoxCLI\` -Verbose

### Using ProxmoxCLI

* Connect to a Proxmox sever with `Connect-PveServer -Server "Proxmox1"`, use `-BypassSSLCheck` if your computer doesn't trust the SSL cert from the Proxmox server.
* Run `Get-Node | Get-Guest` and you should see a list of your guests.


## More Information

For more information

<!-- * [ProxmoxCLI.readthedocs.io](http://ProxmoxCLI.readthedocs.io) -->
* [github.com/quonic/ProxmoxCLI](https://github.com/quonic/ProxmoxCLI)
<!-- * [quonic.github.io](https://quonic.github.io) -->


This project was generated using [Kevin Marquette](http://kevinmarquette.github.io)'s [Full Module Plaster Template](https://github.com/KevinMarquette/PlasterTemplates/tree/master/FullModuleTemplate).
