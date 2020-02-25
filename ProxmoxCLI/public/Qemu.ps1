
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
    $vms = callREST -Resource "nodes/$($Node)/qemu" | Where-Object { $_.vmid -eq $Id }
    $containers = callREST -Resource "nodes/$($Node)/lxc" | Where-Object { $_.vmid -eq $Id }
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
    }
    if ($containers.Count -eq 1) {
        Write-Verbose -Message "Container found matching $Id"
        # Here to check if there is a cantainer to act on
    }
    else {
        throw "No VM or Container, or more than one guest exists with the ID of $Id"
    }
    Write-Verbose -Message "Starting guest $Id"
    return (callREST -Method Post -Resource "nodes/$($Node)/qemu/$($Id)/status/start" -Options $Options)
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
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Node,
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
    $vms = callREST -Resource "nodes/$($Node)/qemu" | Where-Object { $_.vmid -eq $Id }
    $containers = callREST -Resource "nodes/$($Node)/lxc" | Where-Object { $_.vmid -eq $Id }
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
    }
    elseif ($containers.Count -eq 1) {
        Write-Verbose -Message "Container found matching $Id"
        # Here to check if there is a cantainer to act on
    }
    else {
        throw "No VM or Container, or more than one guest exists with the ID of $Id"
    }
    return (callREST -Method Post -Resource "nodes/$($Node)/qemu/$($Id)/status/stop" -Options $Options)
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
        [Parameter()]
        [string]
        $Node,
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
    $vms = callREST -Resource "nodes/$($Node)/qemu" | Where-Object { $_.vmid -eq $Id }
    $containers = callREST -Resource "nodes/$($Node)/lxc" | Where-Object { $_.vmid -eq $Id }
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
    }
    elseif ($containers.Count -eq 1) {
        Write-Verbose -Message "Container found matching $Id"
        # Here to check if there is a cantainer to act on
    }
    else {
        throw "No VM or Container, or more than one guest exists with the ID of $Id"
    }
    return (callREST -Method Post -Resource "nodes/$($Node)/qemu/$($Id)/status/suspend" -Options $Options)
}

function Shutdown-Guest {
    [Diagnostics.CodeAnalysis.SuppressMessage("PSUseApprovedVerbs", Scope = "function")]
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
    
    Param (
        [Parameter()]
        [string]
        $Node,
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
    $vms = callREST -Resource "nodes/$($Node)/qemu" | Where-Object { $_.vmid -eq $Id }
    $containers = callREST -Resource "nodes/$($Node)/lxc" | Where-Object { $_.vmid -eq $Id }
    $Options = @{ }
    if ($vms.Count -eq 1) {
        if ($KeepActive) {
            $Options.Add("keepActive", $KeepActive)
        }
        if ($SkipLock) {
            $Options.Add("skipLock" , $SkipLock)
        }
    }
    elseif ($containers.Count -eq 1) {
        Write-Verbose -Message "Container found matching $Id"

        # Here to check if there is a cantainer to act on
    }
    else {
        throw "No VM or Container, or more than one guest exists with the ID of $Id"
    }
    if ($ForceStop) {
        $Options.Add("forceStop", $ForceStop)
    }
    if ($TimeOut) {
        $Options.Add("timeout" , $TimeOut)
    }
    return (callREST -Method Post -Resource "nodes/$($Node)/qemu/$($Id)/status/shutdown" -Options $Options)

}


Export-ModuleMember -Function @('Start-Guest', 'Stop-Guest', 'Suspend-Guest', 'Shutdown-Guest')