enum NodeStatus {
    unknown
    online
    offline
}

function Get-Node {
    <#
    .SYNOPSIS
    Retruns Nodes from currently connected Proxmox host

    .DESCRIPTION
    Retruns Nodes from currently connected Proxmox host or can return a specific Node.

    .PARAMETER node
    Node name

    .EXAMPLE
    Get-Node

    .EXAMPLE
    Get-Node -Node "pvehost1"

    .EXAMPLE
    $pvehost1 = Get-Node -Node "pvehost1"

    .NOTES
    The object(s) returned can be used to manipulate node(s)
    #>
    [CmdletBinding()]
    [OutputType("System.Object[]")]
    Param(
        [Parameter(Mandatory = $true)]
        [Parameter(ValueFromPipelineByPropertyName)]
        [String]
        $Node
    )
    [PSCustomObject[]] $Nodes = @()
    if ($Node) {
        $Node | ForEach-Object {
            try {
                $NodeReturn = Invoke-ProxmoxAPI -Resource "/nodes/$_"
            }
            catch {
                throw "$Node doesn't exist."
            }
            $return = [PSCustomObject]@{
                Node           = $NodeReturn.node
                Status         = $(
                    switch ($NodeReturn.status) {
                        ([NodeStatus]::online).ToString() { [NodeStatus]::online }
                        ([NodeStatus]::offline).ToString() { [NodeStatus]::offline }
                        Default { [NodeStatus]::unknown }
                    }
                )
                Cpu            = $NodeReturn.cpu
                MaxCpu         = $NodeReturn.maxcpu
                Level          = $NodeReturn.level
                Memory         = $NodeReturn.mem
                SslFingerprint = $NodeReturn.ssl_fingerprint
                UpTime         = $NodeReturn.uptime
            }
            $Nodes.Add($return)
        }
    }
    else {
        Invoke-ProxmoxAPI -Resource "/nodes" | ForEach-Object {
            $return = [PSCustomObject]@{
                Node           = $_.node
                Status         = $(
                    switch ($_.status) {
                        ([NodeStatus]::online).ToString() { [NodeStatus]::online }
                        ([NodeStatus]::offline).ToString() { [NodeStatus]::offline }
                        Default { [NodeStatus]::unknown }
                    }
                )
                Cpu            = $_.cpu
                MaxCpu         = $_.maxcpu
                Level          = $_.level
                Memory         = $_.mem
                SslFingerprint = $_.ssl_fingerprint
                UpTime         = $_.uptime
            }
            $Nodes.Add($return)
        }
    }
    $Nodes | ForEach-Object {
        Add-Member -InputObject $_ -MemberType ScriptMethod -Name "getGuests" -Force -Value {
            Get-Guest -Node $_.Node
        }
        Add-Member -InputObject $_ -MemberType ScriptMethod -Name "subscription" -Force -Value {
            Invoke-ProxmoxAPI -Resource "nodes/$($_.Node)/subscription"
        }
        Add-Member -InputObject $_ -MemberType ScriptMethod -Name "startall" -Force -Value {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $false)]
                [string[]]
                $Vms,
                [Parameter(Mandatory = $false)]
                [switch]
                $force = $false
            )
            Invoke-ProxmoxAPI -Resource "nodes/$($_.Node)/startall" -Options @{force = $force; vms = $Vms }
        }
    }
    return $Nodes
}

function Get-Syslog {
    <#
    .SYNOPSIS
    Reads the system log

    .DESCRIPTION
    Reads the system log

    .PARAMETER Node
    Node to get the logs from

    .PARAMETER Limit
    Number of lines to show

    .PARAMETER Service
    Service ID

    .PARAMETER Since
    Start date-time to start from

    .PARAMETER Start
    Line number to start at

    .PARAMETER Until
    Ends date-time to end at

    .EXAMPLE
    Get-Node | Get-Syslog

    .NOTES
    General notes
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Parameter(ValueFromPipelineByPropertyName)]
        [String]
        $Node,
        [int]
        $Limit,
        # Service ID
        [string]
        $Service,
        # Display all log since this date-time string
        [ValidatePattern("^\d{4}-\d{2}-\d{2}( \d{2}:\d{2}(:\d{2})?)?$")]
        [string]
        $Since,
        [int]
        $Start,
        # Display all log until this date-time string
        [ValidatePattern("^\d{4}-\d{2}-\d{2}( \d{2}:\d{2}(:\d{2})?)?$")]
        [string]
        $Until
    )
    $Options = @()
    if ($Limit) {
        $Options.Add("limit" , $Limit)
    }
    if ($Service) {
        $Options.Add("service" , $Service)
    }
    if ($Since) {
        $Options.Add("since" , $Since)
    }
    if ($Start) {
        $Options.Add("start" , $Start)
    }
    if ($Until) {
        $Options.Add("until" , $Until)
    }
    # TODO parse the lines?
    return (Invoke-ProxmoxAPI -Method Get -Resource "nodes/$($Node)/syslog" -Options $Options)
}

function Invoke-ScanNode {
    <#
    .SYNOPSIS
    Index of available scan methods or scan the different storage methods.

    .DESCRIPTION
    Index of available scan methods or scan the different storage methods.

    .PARAMETER Node
    Name of the Node to scan

    .PARAMETER Type
    Type of storage to scan

    .PARAMETER Domain
    CIFS domain name

    .PARAMETER Password
    CIFS password

    .PARAMETER Username
    CIFS username

    .PARAMETER Server
    Server IP or DNS name for CIFS, GlusterFS, iSCSI, or NFS Server/Portal

    .PARAMETER Vg
    The LVM logical volume group name

    .EXAMPLE
    Invoke-ScanNode -Node "Proxmox1"

    .EXAMPLE
    Invoke-ScanNode -Node "Proxmox1" -Type zfs

    .NOTES
    General notes
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Parameter(ValueFromPipelineByPropertyName)]
        [String[]]
        $Node,
        [ValidateSet('cifs', 'glusterfs', 'iscsi', 'lvm', 'lvmthin', 'nfs', 'usb', 'zfs')]
        [Parameter(Mandatory = $false, ParameterSetName = "none")]
        [Parameter(Mandatory = $true, ParameterSetName = "cifs")]
        [Parameter(Mandatory = $true, ParameterSetName = "glusterfs")]
        [Parameter(Mandatory = $true, ParameterSetName = "iscsi")]
        [Parameter(Mandatory = $true, ParameterSetName = "lvm")]
        [Parameter(Mandatory = $true, ParameterSetName = "lvmthin")]
        [Parameter(Mandatory = $true, ParameterSetName = "nfs")]
        [Parameter(Mandatory = $true, ParameterSetName = "usb")]
        [String]
        $Type,
        [Parameter(Mandatory = $false, ParameterSetName = "cifs")]
        [string]
        $Domain,
        [Parameter(Mandatory = $false, ParameterSetName = "cifs")]
        [securestring]
        $Password,
        [Parameter(Mandatory = $false, ParameterSetName = "cifs")]
        [string]
        $Username,
        [Parameter(Mandatory = $true, ParameterSetName = "glusterfs")]
        [Parameter(Mandatory = $true, ParameterSetName = "iscsi")]
        [Parameter(Mandatory = $true, ParameterSetName = "nfs")]
        [Alias('Portal')]
        [string]
        $Server,
        [Parameter(Mandatory = $true, ParameterSetName = "lvmthin")]
        [ValidatePattern("[a-zA-Z0-9\.\+\_][a-zA-Z0-9\.\+\_\-]+")]
        [string]
        $Vg
    )
    $Options = @()
    switch ($Type) {
        cifs {
            if ($Domain) {
                $Options.Add("domain", $Domain)
            }
            if ($Username) {
                $Options.Add("username", $Username)
            }
            if ($Password) {
                $Options.Add("password", (ConvertFrom-SecureString $Password))
            }
            return (Invoke-ProxmoxAPI -Method Get -Resource "nodes/$($Node)/scan/cifs" -Options $Options)
        }
        glusterfs {
            $Options.Add("server", $Server)
            return (Invoke-ProxmoxAPI -Method Get -Resource "nodes/$($Node)/scan/glusterfs" -Options $Options)
        }
        iscsi {
            $Options.Add("portal", $Server)
            return (Invoke-ProxmoxAPI -Method Get -Resource "nodes/$($Node)/scan/iscsi" -Options $Options)
        }
        lvm {
            return (Invoke-ProxmoxAPI -Method Get -Resource "nodes/$($Node)/scan/lvm")
        }
        lvmthin {
            $Options.Add("vg", $Vg)
            return (Invoke-ProxmoxAPI -Method Get -Resource "nodes/$($Node)/scan/lvmthin" -Options $Options)
        }
        nfs {
            $Options.Add("server", $Server)
            return (Invoke-ProxmoxAPI -Method Get -Resource "nodes/$($Node)/scan/nfs" -Options $Options)
        }
        usb {
            return (Invoke-ProxmoxAPI -Method Get -Resource "nodes/$($Node)/scan/usb")
        }
        zfs {
            return (Invoke-ProxmoxAPI -Method Get -Resource "nodes/$($Node)/scan/zfs")
        }
        Default {
            return (Invoke-ProxmoxAPI -Method Get -Resource "nodes/$($Node)/scan")
        }
    }
}

Export-ModuleMember -Function @(
    'Get-Node',
    'Get-Syslog',
    'Invoke-ScanNode'
)