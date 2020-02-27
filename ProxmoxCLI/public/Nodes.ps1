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
    return (Invoke-ProxmoxAPI -Method Post -Resource "nodes/$($Node)/qemu/$($Id)/status/reboot" -Options $Options)
}


Export-ModuleMember -Function @('Get-Node', 'Get-Syslog')