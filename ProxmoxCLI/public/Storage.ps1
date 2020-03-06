function Get-Storage {
    <#
    .SYNOPSIS
    Returns the storage configuration

    .DESCRIPTION
    Returns the storage configuration

    .PARAMETER Storage
    Storage ID

    .PARAMETER Type
    Type of storage

    .EXAMPLE
    Get-Storage

    .EXAMPLE
    Get-Storage -Type zfs

    .EXAMPLE
    Get-Storage -Storage "local-zfs"

    .NOTES
    General notes
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = "storage")]
        $Storage,
        [Parameter(Mandatory = $false, ParameterSetName = "storages")]
        [ValidateSet("cephfs", "cifs", "dir", "drbd", "glusterfs", "iscsi", "iscsidirect", "lvm", "lvmthin", "nfs", "rbd", "zfs", "zfspool")]
        $Type
    )
    $Options = @{ }
    if ($Storage) {
        $Storage | ForEach-Object {
            return (Invoke-ProxmoxAPI -Method Post -Resource "storage/$_")
        }
    }
    else {
        if ($Type) {
            $Options.Add("type" , $Type)
        }
        return (Invoke-ProxmoxAPI -Method Post -Resource "storage" -Options $Options)
    }
}


Export-ModuleMember -Function @(
    'Get-Storage'
)