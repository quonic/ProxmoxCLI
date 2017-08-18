class Qemu {
    
    [string] $vmid
    [PSCustomObject] $AvailableResources
    [PSCustomObject] $Status
    [Node] $Node
        
        
    Qemu ([Node] $Node, [string] $vmid) {
        $this.vmid = $vmid
        $this.Node = $Node
        $this.AvailableResources = (callREST -Resource "nodes/$($this.Node.Name)/qemu/$($this.vmid)")
        $this.Status = $this.getStatus()
    }
        
    [PSCustomObject] getStatus() {
        return (callREST -Resource "nodes/$($this.Node.Name)/qemu/$($this.vmid)/status/current")
        
    }

}