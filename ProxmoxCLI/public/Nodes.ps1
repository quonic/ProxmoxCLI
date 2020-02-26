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

Export-ModuleMember -Function @('Get-Node')