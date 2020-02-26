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

    if ($Node) {
        $Node | ForEach-Object {
            try {
                $NodeReturn = Invoke-ProxmoxAPI -Resource "/nodes/$_"
            }
            catch {
                throw "$Node doesn't exist."
            }
            $Name = $NodeReturn.node
            $return = [PSCustomObject]@{
                Name           = $NodeReturn.node
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
            Add-Member -InputObject $return -MemberType ScriptMethod -Name "getGuests" -Force -Value {
                Get-Guest -Node $Name
            }
        }
    }
    else {
        return Invoke-ProxmoxAPI -Resource "/nodes" | ForEach-Object {
            $Name = $_.node
            $return = [PSCustomObject]@{
                Name           = $_.node
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
            Add-Member -InputObject $return -MemberType ScriptMethod -Name "getGuests" -Force -Value {
                Get-Guest -Node $Name
            }
        }
    }
}

Export-ModuleMember -Function @('Get-Node')