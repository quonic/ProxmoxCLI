function Get-Node {
    [CmdletBinding()]
    Param(
        # Parameter help description
        [Parameter(ValueFromPipelineByPropertyName)]
        [String]
        $node
    )

    # TODO - Expand this to return more information, probably in Node class.
    if ($node) {
        return $node | ForEach-Object {
            New-Object -TypeName "Node" -ArgumentList $_
        }
    }
    else {
        return callREST -Resource "/nodes" | ForEach-Object {
            New-Object -TypeName "Node" -ArgumentList $_.node
        }
    }
}

function Get-Qemu {
    [CmdletBinding()]
    Param(
        # The Qemu property called vmid
        [Parameter(mandatory = $true, ValueFromPipelineByPropertyName)]
        [String]
        $vmid,
        # Name of node that the Qemu is running under
        [Parameter(mandatory = $true)]
        [String]
        $Node
    )
    return [Qemu]::new($Node, $vmid)
}

Export-ModuleMember -Function @('Get-Node', 'Get-Qemu')