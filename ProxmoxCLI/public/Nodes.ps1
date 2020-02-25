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

    # TODO - Expand this to return more information, probably in Node class.
    if ($Node) {
        return $Node | ForEach-Object {
            #[Node]::new($_)
            New-Object -TypeName "Node" -ArgumentList $_
        }
    }
    else {
        return Invoke-ProxmoxAPI -Resource "/nodes" | ForEach-Object {
            #[Node]::new($_.node)
            New-Object -TypeName "Node" -ArgumentList $_.node
        }
    }
}

function Get-Guest {
    <#
    .SYNOPSIS
    Retruns a Guest from the specified Node

    .DESCRIPTION
    Retruns a Guest from the specified Node

    .PARAMETER vmid
    The Guest property called vmid

    .PARAMETER Node
    Name of node that the Guest is running under

    .EXAMPLE
    Get-Guest -vmid "101" -Node "pvehost1"

    .EXAMPLE
    $vm101 = Get-Guest -vmid "101" -Node "pvehost1"

    .NOTES
    The object(s) returned can be used to manipulate Guest(s)
    #>
    [CmdletBinding()]
    Param(
        [Parameter(mandatory = $false, ValueFromPipelineByPropertyName)]
        [String]
        $Id,
        [Parameter(mandatory = $true)]
        [String]
        $Node,
        [Parameter(Mandatory = $false, ParameterSetName = "OnlySpecificType")]
        [Parameter(mandatory = $false)]
        [switch]
        $ContainerOnly,
        [Parameter(Mandatory = $false, ParameterSetName = "OnlySpecificType")]
        [Parameter(mandatory = $false)]
        [switch]
        $VmOnly
    )
    $vms = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/qemu"
    $containers = Invoke-ProxmoxAPI -Resource "nodes/$($Node)/lxc"
    if ($Id) {
        if (($vms | Where-Object { $_.vmid -eq $Id }).Count -eq 1) {
            return [PSCustomObject]@{
                id   = $vms.vmid
                node = $Node
            }
        }
        elseif (($containers | Where-Object { $_.vmid -eq $Id }).Count -eq 1) {
            return [PSCustomObject]@{
                id   = $containers.vmid
                node = $Node
            }
        }
        else {
            throw "No VM or Container, or more than one guest exists with the ID of $Id"
        }
    }
    else {
        if ($ContainerOnly) {
            return $containers | ForEach-Object {
                [PSCustomObject]@{
                    id   = $_.vmid
                    node = $Node
                }
            }
        }
        elseif ($VmOnly) {
            $vms | ForEach-Object {
                [PSCustomObject]@{
                    id   = $_.vmid
                    node = $Node
                }
            }
        }
        else {
            return $vms + $containers | ForEach-Object {
                [PSCustomObject]@{
                    id   = $_.vmid
                    node = $Node
                }
            }
        }
    }
}

Export-ModuleMember -Function @('Get-Node', 'Get-Guest')