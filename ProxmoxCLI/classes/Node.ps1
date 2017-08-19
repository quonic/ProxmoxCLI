class Node {

    [string] $Name
    [PSCustomObject] $AvailableResources
    [PSCustomObject] $Subscription
    [DateTime] $Time
    [PSCustomObject] $Version
    [PSCustomObject] $Status
    [PSCustomObject] $Dns
    
    
    Node ([string] $Name) {
        $this.Name = [string]$Name
        $this.AvailableResources = (callREST -Resource "nodes/$Name")
        $this.Subscription = $this.getSubscription()
        # Convert UNIX time to Windows time
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
        $this.Time = $origin.AddSeconds(($this.getTime()).localtime)
        $this.Version = $this.getVersion()
        $this.Status = $this.getStatus()
        $this.Dns = $this.getDns()
    }
    
    [PSCustomObject] getSubscription() {
        return (callREST -Resource "nodes/$($this.Name)/subscription")
    }
    [PSCustomObject] getSyslog() {
        return (callREST -Resource "nodes/$($this.Name)/syslog")
    }
    [PSCustomObject] getTime() {
        return (callREST -Resource "nodes/$($this.Name)/time")
    }
    [PSCustomObject] getVersion() {
        return (callREST -Resource "nodes/$($this.Name)/version")
    }
    [PSCustomObject] getStatus() {
        return (callREST -Resource "nodes/$($this.Name)/status")
    }
    [PSCustomObject] getAplinfo() {
        return (callREST -Resource "nodes/$($this.Name)/aplinfo")
    }
    [PSCustomObject] getDns() {
        return (callREST -Resource "nodes/$($this.Name)/dns")
    }
    [PSCustomObject] getNetstat() {
        return (callREST -Resource "nodes/$($this.Name)/netstat")
    }
    [PSCustomObject] getReport() {
        return (callREST -Resource "nodes/$($this.Name)/report")
    }


    
    # /apt/*
    [PSCustomObject] getAptChangeLog ([String]$package) {
        return (callREST -Resource "nodes/$($this.Name)/apt/changelog" -Options @{name = $package})
    }
    [PSCustomObject] getAptUpdate () {
        return (callREST -Resource "nodes/$($this.Name)/apt/update")
    }
    [PSCustomObject] runAptUpdate ([switch]$notify) {
        $query = "?quiet=true"
        if ($notify) {$query = "$($query)&notify=true"}
        return (callREST -Resource "nodes/$($this.Name)/apt/update$query")
    }
    [PSCustomObject] getAptVersion () {
        return (callREST -Resource "nodes/$($this.Name)/apt/versions")
    }

    # /ceph/*
    # I don't have a ceph setup at the moment to properly write and test this
    [PSCustomObject] getCephFlags () {
        return (callREST -Resource "nodes/$($this.Name)/ceph/flags")
    }
    [PSCustomObject] getCeph () {
        return (callREST -Resource "nodes/$($this.Name)/ceph")
    }

    # /disks/*
    [PSCustomObject] getDisks () {
        return (callREST -Resource "nodes/$($this.Name)/disks/list")
    }
    [PSCustomObject] getDisksHealth () {
        return $this.getDisks() | ForEach-Object {
            @{
                'devpath'    = $_.devpath;
                'attributes' = (callREST -Resource "nodes/$($this.Name)/disks/smart" -Options @{disk = $_.devpath}) | Select-Object health
            }
        }
    }
    # /firewall/*
    # I haven't used this yet, but plan on doing so to get this implimented
    [PSCustomObject] getFirewall () {
        return (callREST -Resource "nodes/$($this.Name)/firewall")
    }
    # /lxc/*
    [PSCustomObject] getLxc () {
        return (callREST -Resource "nodes/$($this.Name)/lxc")
    }
    # /network/*
    [PSCustomObject] getNetwork () {
        return (callREST -Resource "nodes/$($this.Name)/network")
    }
    # /qemu/*
    [PSCustomObject] getQemu () {
        $vms = (callREST -Resource "nodes/$($this.Name)/qemu")
        return $vms | ForEach-Object { [Qemu]::new($this.Name, $_.vmid) }
    }
    # /replication/*
    [PSCustomObject] getReplication () {
        return (callREST -Resource "nodes/$($this.Name)/replicate")
    }
    # /scan/*
    [PSCustomObject] getScan () {
        return (callREST -Resource "nodes/$($this.Name)/scan")
    }
    # /services/*
    [PSCustomObject] getServices () {
        return (callREST -Resource "nodes/$($this.Name)/services")
    }
    # /storage/*
    [PSCustomObject] getStorage () {
        return (callREST -Resource "nodes/$($this.Name)/storage")
    }
    # /tasks/*
    [PSCustomObject] getTasks () {
        return (callREST -Resource "nodes/$($this.Name)/tasks")
    }
    # /vzdump/*
    # [PSCustomObject] getVzdump () {
    #     $this.vzdump = (callREST -Resource "nodes/$($this.Name)/vzdump")
    # }

    # /rrd
    #$this.rrd = (callREST -Resource "nodes/$($this.Name)/rrd")
    # /rrddata
    #$this.rrddata = (callREST -Resource "nodes/$($this.Name)/rrddata")
    # /spiceshell
    # $this.spiceshell = (callPost -Resource "nodes/$($this.Name)/spiceshell")
    # /startall
    #$this.startall = (callPost -Resource "nodes/$($this.Name)/startall")
    
    # /stopall
    #$this.stopall = (callPost -Resource "nodes/$($this.Name)/stopall")
    
    # /vncshell
    #$this.vncshell = (callPost -Resource "nodes/$($this.Name)/vncshell")
    # /vncwebsocket
    #$this.vncwebsocket = (callREST -Resource "nodes/$($this.Name)/vncwebsocket")

    # /execute
    [PSCustomObject] execute ($command, $node) {
        #return (callREST -Resource "nodes/$($this.Name)/execute")
        return $false
    }
    # /migrateall
    [PSCustomObject] MigrateAll () {
        #return (callREST -Resource "nodes/$($this.Name)/migrateall")
        return $false
    }
}

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