function Get-Container {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    [OutputType([PSObject[]])]
    param(
        # Id of the LXC guest
        [Parameter(Mandatory = $false, ParameterSetName = "Id", ValueFromPipelineByPropertyName)]
        [string[]]
        $Id,
        # Node(s) that the LXC guest(s) are running under
        [Parameter(Mandatory = $false, ParameterSetName = "Id", ValueFromPipelineByPropertyName)]
        [int[]]
        $Node
    )
    
    begin {
    }
    
    process {
        if ($Node) {
            $Node | ForEach-Object {
                if ($Id) {
                    $N = $_
                    $Id | ForEach-Object {
                        Get-NodeLxcVmid -node $N -vmid $_
                    }
                    
                }
                else {
                    Get-NodeLxc -node $_
                }
            }
        }
        else {
            Get-Node | ForEach-Object {
                Get-NodeLxc -node $_.node        
            }
        }
    }
    
    end {
    }
}