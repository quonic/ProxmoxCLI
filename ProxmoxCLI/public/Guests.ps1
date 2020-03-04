
function Start-Guest {
    <#
    .SYNOPSIS
    Starts a VM or lxc

    .DESCRIPTION
    Starts a VM or lxc

    .PARAMETER Node
    Name of the Node that the Guest resides on

    .PARAMETER Id
    ID of the guest

    .PARAMETER MachineType
    specifies the Qemu machine type

    .PARAMETER MigratedFrom
    The cluster node name to migrate from

    .PARAMETER MigrationNetwork
    CIDR of the (sum) network that is used for migration

    .PARAMETER MigrationType
    Migrate traffic is encrypted using an SSH tunnel by default. On Secure, completely private networks this can be disabled to increase performance

    .PARAMETER SkipLock
    Ignores logs - only root is allowed to use this option

    .PARAMETER StateUri
    Some command save/restore state from this location

    .PARAMETER TargetStorage
    Target storage for the migration. (Can be '1' to sue the same storage id as on the source node.)

    .PARAMETER TimeOut
    Wait maximal timeout seconds

    .EXAMPLE
    Start-VM -Node "Proxmox1" -ID 100

    .NOTES
    General notes
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage("PSUseShouldProcessForStateChangingFunctions", Scope = "function")]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Node,
        [Parameter(Mandatory = $true)]
        [int]
        $Id,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [ValidatePattern("(pc|pc(-i440fx)?-\d+(\.\d+)+(\+pve\d+)?(\.pxe)?|q35|pc-q35-\d+(\.\d+)+(\+pve\d+)?(\.pxe)?|virt(?:-\d+(\.\d+)+)?(\+pve\d+)?)")]
        [string]
        $MachineType,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [string]
        $MigratedFrom,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [string]
        $MigrationNetwork,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [MigrationType]
        $MigrationType,
        [Parameter(Mandatory = $false, ParameterSetName = "container")]
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [switch]
        $SkipLock,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [string]
        $StateUri,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [string]
        $TargetStorage,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [int]$TimeOut
    )
    $vms = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/qemu" | Where-Object { $_.vmid -eq $Id }
    $containers = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/lxc" | Where-Object { $_.vmid -eq $Id }
    $Options = @{ }
    $Options.Add("skiplock" , $SkipLock)

    if ( $vms.Count -eq 1 ) {
        Write-Verbose -Message "VM found matching $Id"
        if ($MachineType) {
            Write-Verbose -Message "Adding machine type to options"
            $Options.Add("machine" , $Machine)
        }
        if ($MigratedFrom) {
            Write-Verbose -Message "Adding migration source to options"
            $Options.Add("migratedfrom" , $MigratedFrom)
        }
        if ($MigrationNetwork) {
            Write-Verbose -Message "Adding migration network to options"
            $Options.Add("migration_network" , $MigrationNetwork)
        }
        if ($MigrationType) {
            Write-Verbose -Message "Adding migration type to options"
            $Options.Add("migration_type" , $MigrationType)
        }
        if ($StateUri) {
            Write-Verbose -Message "Adding stare uri to options"
            $Options.Add("stateuri" , $StateUri)
        }
        if ($TargetStorage) {
            Write-Verbose -Message "Adding target storage to options"
            $Options.Add("targetstorage" , $TargetStorage)
        }
        return (Invoke-ProxmoxAPI -Method Post -Resource "nodes/$($Node)/qemu/$($Id)/status/start" -Options $Options)
    }
    elseif ($containers.Count -eq 1) {
        Write-Verbose -Message "Container found matching $Id"
        return (Invoke-ProxmoxAPI -Method Post -Resource "nodes/$($Node)/lxc/$($Id)/status/start" -Options $Options)
    }
    else {
        throw "No VM or Container, or more than one guest exists with the ID of $Id"
    }
    Write-Verbose -Message "Starting guest $Id"
}


function Stop-Guest {
    <#
    .SYNOPSIS
    Stops a guest

    .DESCRIPTION
    Stops a guest. Qemu process will exit immediately. This is akin to pulling the power plug of a running computer and may damage the VM data

    .PARAMETER Node
    Name of the Node that the Guest resides on

    .PARAMETER Id
    ID of the guest

    .PARAMETER KeepActive
    Keeps the storage volumes active

    .PARAMETER SkipLock
    Ignores locks - only root is allowed to use this option

    .PARAMETER TimeOut
    Wait maximal timeout seconds

    .EXAMPLE
    Stop-Guest -Node "Proxmox1" -Id 100

    .NOTES
    General notes
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage("PSUseShouldProcessForStateChangingFunctions", Scope = "function")]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Node,
        [Parameter(Mandatory = $true)]
        [int]
        $Id,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [switch]
        $KeepActive,
        [Parameter(Mandatory = $false, ParameterSetName = "container")]
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [switch]
        $SkipLock,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [int]
        $TimeOut
    )
    $vms = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/qemu" | Where-Object { $_.vmid -eq $Id }
    $containers = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/lxc" | Where-Object { $_.vmid -eq $Id }
    $Options = @{ }
    if ($SkipLock) {
        $Options.Add("skiplock", $SkipLock)
    }
    if ($vms.Count -eq 1) {
        if ($KeepActive) {
            Write-Verbose -Message "Adding keep active to options"
            $Options.Add("keepActive", $KeepActive)
        }
        if ($TimeOut) {
            Write-Verbose -Message "Adding timeout to options"
            $Options.Add("timeout", $TimeOut)
        }
        if ($MigratedFrom) {
            Write-Verbose -Message "Adding migration source to options"
            $Options.Add("migratedfrom" , $MigratedFrom)
        }
        return (Invoke-ProxmoxAPI -Method Post -Resource "nodes/$($Node)/qemu/$($Id)/status/stop" -Options $Options)
    }
    elseif ($containers.Count -eq 1) {
        Write-Verbose -Message "Container found matching $Id"
        return (Invoke-ProxmoxAPI -Method Post -Resource "nodes/$($Node)/lxc/$($Id)/status/stop" -Options $Options)
        else {
            throw "No VM or Container, or more than one guest exists with the ID of $Id"
        }
    }
}

function Suspend-Guest {
    <#
    .SYNOPSIS
    Suspend virtual machine

    .DESCRIPTION
    Suspend virtual machine

    .PARAMETER Node
    Name of the Node that the Guest resides on

    .PARAMETER Id
    ID of the guest

    .PARAMETER StateStorage
    The storage for the VM state

    .PARAMETER ToDisk
    If set, suspends the VM to disk. Will be resumed on next VM start.

    .PARAMETER SkipLock
    Ignore locks - only root is allowed to use this option

    .EXAMPLE
    Suspend-Guest -Node "Proxmox1" -Id 100

    .NOTES
    General notes
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Node,
        [Parameter(Mandatory = $true)]
        [int]
        $Id,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [string]
        $StateStorage,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [switch]
        $ToDisk,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [switch]
        $SkipLock
    )
    $vms = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/qemu" | Where-Object { $_.vmid -eq $Id }
    $containers = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/lxc" | Where-Object { $_.vmid -eq $Id }
    $Options = @{ }
    if ($vms.Count -eq 1) {
        if ($SkipLock) {
            $Options.Add("skiplock", $SkipLock)
        }
        if ($ToDisk) {
            $Options.Add("todisk", $ToDisk)
        }
        if ($StateStorage) {
            $Options.Add("statestorage" , $StateStorage)
        }
        return (Invoke-ProxmoxAPI -Method Post -Resource "nodes/$($Node)/qemu/$($Id)/status/suspend" -Options $Options)
    }
    elseif ($containers.Count -eq 1) {
        Write-Verbose -Message "Container found matching $Id"
        return (Invoke-ProxmoxAPI -Method Post -Resource "nodes/$($Node)/lxc/$($Id)/status/suspend" -Options $Options)
    }
    else {
        throw "No VM or Container, or more than one guest exists with the ID of $Id"
    }
}

function Shutdown-Guest {
    <#
    .SYNOPSIS
    Shuts down a guest

    .DESCRIPTION
    Shutdown virtual machine. This is similar to pressing the power button on a physical machine.This will send an ACPI event for the guest OS, which should then proceed to a clean shutdown.

    .PARAMETER Node
    Name of the Node that the Guest resides on

    .PARAMETER Id
    ID of the guest

    .PARAMETER ForceStop
    Make sure the VM stops

    .PARAMETER KeepActive
    Do not deactivate storage volumes

    .PARAMETER SkipLock
    Ignores locks - only root is allowed to use this option

    .PARAMETER TimeOut
    Wait maximal timeout seconds

    .EXAMPLE
    An example

    .NOTES
    General notes
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage("PSUseApprovedVerbs", Scope = "function")]
    Param (
        [Parameter(Mandatory = $true)]
        [string]
        $Node,
        [Parameter(Mandatory = $true)]
        [int]
        $Id,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [Parameter(Mandatory = $false, ParameterSetName = "container")]
        [switch]
        $ForceStop,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [switch]
        $KeepActive,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [switch]
        $SkipLock,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [Parameter(Mandatory = $false, ParameterSetName = "container")]
        [int]
        $TimeOut
    )
    $vms = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/qemu" | Where-Object { $_.vmid -eq $Id }
    $containers = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/lxc" | Where-Object { $_.vmid -eq $Id }
    $Options = @{ }
    if ($ForceStop) {
        $Options.Add("forceStop", $ForceStop)
    }
    if ($TimeOut) {
        $Options.Add("timeout" , $TimeOut)
    }
    if ($vms.Count -eq 1) {
        if ($KeepActive) {
            $Options.Add("keepActive", $KeepActive)
        }
        if ($SkipLock) {
            $Options.Add("skipLock" , $SkipLock)
        }
        return (Invoke-ProxmoxAPI -Method Post -Resource "nodes/$($Node)/qemu/$($Id)/status/shutdown" -Options $Options)
    }
    elseif ($containers.Count -eq 1) {
        Write-Verbose -Message "Container found matching $Id"
        return (Invoke-ProxmoxAPI -Method Post -Resource "nodes/$($Node)/lxc/$($Id)/status/shutdown" -Options $Options)
    }
    else {
        throw "No VM or Container, or more than one guest exists with the ID of $Id"
    }
}

function Resume-Guest {
    <#
    .SYNOPSIS
    Resume guest

    .DESCRIPTION
    Resume guest

    .PARAMETER Node
    Name of the node that the guest resides on

    .PARAMETER Id
    Id if the guest

    .PARAMETER SkipLock
    Ignore locks - only root is allowed to use this option

    .PARAMETER NoCheck
    No description

    .EXAMPLE
    Resume-Guest -Node "Proxmox1" -Id 101

    .NOTES
    General notes
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Node,
        [Parameter(Mandatory = $true)]
        [int]
        $Id,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [switch]
        $SkipLock,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [switch]
        $NoCheck
    )
    $vms = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/qemu" | Where-Object { $_.vmid -eq $Id }
    $containers = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/lxc" | Where-Object { $_.vmid -eq $Id }
    $Options = @{ }
    if ($vms.Count -eq 1) {
        if ($NoCheck) {
            $Options.Add("nocheck", $NoCheck)
        }
        if ($SkipLock) {
            $Options.Add("skipLock" , $SkipLock)
        }
        return (Invoke-ProxmoxAPI -Method Post -Resource "nodes/$($Node)/qemu/$($Id)/status/resume" -Options $Options)
    }
    elseif ($containers.Count -eq 1) {
        Write-Verbose -Message "Container found matching $Id"
        return (Invoke-ProxmoxAPI -Method Post -Resource "nodes/$($Node)/lxc/$($Id)/status/resume" -Options $Options)
    }
    else {
        throw "No VM or Container, or more than one guest exists with the ID of $Id"
    }
}
function Reset-Guest {
    <#
    .SYNOPSIS
    Reset guest

    .DESCRIPTION
    Reset guest

    .PARAMETER Node
    Name of the node that the guest resides on

    .PARAMETER Id
    Id if the guest

    .PARAMETER SkipLock
    Ignore locks - only root is allowed to use this option

    .EXAMPLE
    Reset-Guest -Node "Proxmox1" -Id 101

    .NOTES
    General notes
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage("PSUseShouldProcessForStateChangingFunctions", Scope = "function")]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Node,
        [Parameter(Mandatory = $true)]
        [int]
        $Id,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [switch]
        $SkipLock
    )
    $vms = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/qemu" | Where-Object { $_.vmid -eq $Id }
    $containers = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/lxc" | Where-Object { $_.vmid -eq $Id }
    $Options = @{ }
    if ($vms.Count -eq 1) {
        if ($SkipLock) {
            $Options.Add("skipLock" , $SkipLock)
        }
        return (Invoke-ProxmoxAPI -Method Post -Resource "nodes/$($Node)/qemu/$($Id)/status/reset" -Options $Options)
    }
    elseif ($containers.Count -eq 1) {
        Write-Verbose -Message "Container found matching $Id"
        throw "Can't reset a container."
    }
    else {
        throw "No VM, or more than one guest exists with the ID of $Id"
    }
}

function Reboot-Guest {
    <#
    .SYNOPSIS
    Reboot guest

    .DESCRIPTION
    Reboot guest

    .PARAMETER Node
    Name of the node that the guest resides on

    .PARAMETER Id
    Id if the guest

    .PARAMETER timeOut
    Wait maximal timeout second for the shutdown

    .EXAMPLE
    Reboot-Guest -Node "Proxmox1" -Id 101

    .NOTES
    General notes
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage("PSUseApprovedVerbs", Scope = "function")]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Node,
        [Parameter(Mandatory = $true)]
        [int]
        $Id,
        [switch]
        $Timeout
    )
    $vms = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/qemu" | Where-Object { $_.vmid -eq $Id }
    $containers = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/lxc" | Where-Object { $_.vmid -eq $Id }
    $Options = @{ }
    if ($Timeout) {
        $Options.Add("timeout" , $Timeout)
    }
    if ($vms.Count -eq 1) {
        return (Invoke-ProxmoxAPI -Method Post -Resource "nodes/$($Node)/qemu/$($Id)/status/reboot" -Options $Options)
    }
    elseif ($containers.Count -eq 1) {
        Write-Verbose -Message "Container found matching $Id"
        return (Invoke-ProxmoxAPI -Method Post -Resource "nodes/$($Node)/lxc/$($Id)/status/reboot" -Options $Options)
    }
    else {
        throw "No VM or Container, or more than one guest exists with the ID of $Id"
    }
}

function Get-Guest {
    <#
    .SYNOPSIS
    Gets the status of a guest, and other stats

    .DESCRIPTION
    Gets the status of a guest, and other stats

    .PARAMETER Node
    Names of the node

    .PARAMETER Id
    Id of the guest(s)

    .EXAMPLE
    Get-Guest -Node "Promxox1"

    .EXAMPLE
    Get-Guest -Node "Promxox1" -Id 100

    .NOTES
    General notes
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Node,
        [Parameter(Mandatory = $false)]
        [int]
        $Id
    )

    begin {
        $vms = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/qemu"
        $containers = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/lxc"
        [PSCustomObject[]]$guests = [PSCustomObject]@{ }
    }

    process {
        if (($vms | Where-Object { $_.vmid -eq $Id }).Count -eq 1) {
            $guests.Add((Invoke-ProxmoxAPI -Method Post -Resource "nodes/$($Node)/qemu/$($Id)/status/current"))
        }
        elseif (($containers | Where-Object { $_.vmid -eq $Id }).Count -eq 1) {
            $guests.Add((Invoke-ProxmoxAPI -Method Post -Resource "nodes/$($Node)/lxc/$($Id)/status/current"))
        }
        else {
            Write-Error "No VM or Container exists with the ID of $Id"
        }
        Write-Output $guests
    }

    end {
        $guests = $null
    }
}

function Clone-Node {
    <#
    .SYNOPSIS
    Create a Copy of guest/template

    .DESCRIPTION
    Create a Copy of guest/template

    .PARAMETER Node
    Name of the Node that the guest resides

    .PARAMETER Id
    ID of the source guest

    .PARAMETER NewId
    ID of the new guest

    .PARAMETER BwLimit
    Override I/O bandwidth limit (in KiB/s).

    .PARAMETER Description
    Description of the new Guest

    .PARAMETER Format
    Target format for file storage. Only valid for full clone of a VM.

    .PARAMETER Full
    Create a full copy of all disks. This is always done when you clone a normal VM/containter. For VM/Container templates, we try to create a linked clone by default.

    .PARAMETER HostName
    Set a name for the new guest.

    .PARAMETER Pool
    Add the new guest to the specified pool.

    .PARAMETER SnapName
    The name of the snapshot.

    .PARAMETER Storage
    Target storage for full clone.

    .PARAMETER Target
    Target node. Only allowed if the original VM is on shared storage.

    .EXAMPLE
    Clone-Node -Node "Proxmox1" -Id 100 -NewId 101

    .NOTES
    General notes
    #>

    [Diagnostics.CodeAnalysis.SuppressMessage("PSUseApprovedVerbs", Scope = "function")]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Node,
        [Parameter(Mandatory = $true)] #ValueFromPipelineByPropertyName, ValueFromPipeline
        [int]
        $Id,
        [Parameter(Mandatory = $true)]
        [int]
        $NewId,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [Parameter(Mandatory = $false, ParameterSetName = "container")]
        [int]
        $BwLimit,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [Parameter(Mandatory = $false, ParameterSetName = "container")]
        [string]
        $Description,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [ValidateSet('raw', 'qcow2', 'vmdk')]
        [string]
        $Format,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [Parameter(Mandatory = $false, ParameterSetName = "container")]
        [switch]
        $Full,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [Parameter(Mandatory = $false, ParameterSetName = "container")]
        [string]
        $HostName,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [Parameter(Mandatory = $false, ParameterSetName = "container")]
        [string]
        $Pool,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [Parameter(Mandatory = $false, ParameterSetName = "container")]
        [string]
        $SnapName,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [Parameter(Mandatory = $false, ParameterSetName = "container")]
        [string]
        $Storage,
        [Parameter(Mandatory = $false, ParameterSetName = "vm")]
        [Parameter(Mandatory = $false, ParameterSetName = "container")]
        [string]
        $Target
    )
    begin {
        if ($Id = $NewId) {
            throw "Id and NewID can't be the same."
        }
        $vms = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/qemu"
        $containers = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/lxc"
        [PSCustomObject[]]$guests = [PSCustomObject]@{ }
        $Options = @()
    }

    process {
        $Options.Add('newid', $NewId)
        if ($BwLimit) {
            $Options.Add('bwlimit', $BwLimit)
        }
        if ($Description) {
            $Options.Add('description', $Description)
        }
        if ($Full) {
            $Options.Add('full', $Full)
        }
        if ($Name) {
            $Options.Add('name', $Name)
        }
        if ($Pool) {
            $Options.Add('pool', $Pool)
        }
        if ($SnapName) {
            $Options.Add('snapname', $SnapName)
        }
        if ($Storage) {
            $Options.Add('storage', $Storage)
        }
        if ($Target) {
            $Options.Add('target', $Target)
        }
        if (($vms | Where-Object { $_.vmid -eq $Id }).Count -eq 1) {
            if ($Format) {
                $Options.Add('format', $Format)
            }
            $guests.Add((Invoke-ProxmoxAPI -Method Post -Resource "nodes/$($Node)/qemu/$($Id)/clone" -Options $Options))
        }
        elseif (($containers | Where-Object { $_.vmid -eq $Id }).Count -eq 1) {
            $guests.Add((Invoke-ProxmoxAPI -Method Post -Resource "nodes/$($Node)/lxc/$($Id)/clone" -Options $Options))
        }
        else {
            Write-Error "No VM or Container exists with the ID of $Id"
        }
        Write-Output $guests
    }

    end {
        $guests = $null
    }
}

Export-ModuleMember -Function @('Start-Guest', 'Stop-Guest', 'Suspend-Guest', 'Shutdown-Guest', 'Resume-Guest', 'Reset-Guest', 'Reboot-Guest', 'Get-Guest', 'Clone-Node')