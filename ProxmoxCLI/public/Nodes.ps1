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
    Param(
        [Parameter(ValueFromPipelineByPropertyName)]
        [String]
        $Node
    )
    $Nodes = @()
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

Export-ModuleMember -Function @('Get-Node')