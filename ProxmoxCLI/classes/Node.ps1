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
        $this.AvailableResources = (callGet -Resource "nodes/$Name")
        $this.Subscription = $this.getSubscription()
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
        $this.Time = $origin.AddSeconds(($this.getTime()).localtime)
        $this.Version = $this.getVersion()
        $this.Status = $this.getStatus()
        $this.Dns = $this.getDns()
    }
    
    [PSCustomObject] getSubscription() {
        return (callGet -Resource "nodes/$($this.Name)/subscription")
    }
    [PSCustomObject] getSyslog() {
        return (callGet -Resource "nodes/$($this.Name)/syslog")
    }
    [PSCustomObject] getTime() {
        return (callGet -Resource "nodes/$($this.Name)/time")
    }
    [PSCustomObject] getVersion() {
        return (callGet -Resource "nodes/$($this.Name)/version")
    }
    [PSCustomObject] getStatus() {
        return (callGet -Resource "nodes/$($this.Name)/status")
    }
    [PSCustomObject] getAplinfo() {
        return (callGet -Resource "nodes/$($this.Name)/aplinfo")
    }
    [PSCustomObject] getDns() {
        return (callGet -Resource "nodes/$($this.Name)/dns")
    }
    [PSCustomObject] getNetstat() {
        return (callGet -Resource "nodes/$($this.Name)/netstat")
    }
    [PSCustomObject] getReport() {
        return (callGet -Resource "nodes/$($this.Name)/report")
    }


    
    # /apt/*
    [PSCustomObject] getAptChangeLog ([String]$package) {
        return (callGet -Resource "nodes/$($this.Name)/apt/changelog" -Options @{name=$package})
    }
    [PSCustomObject] getAptUpdate () {
        return (callGet -Resource "nodes/$($this.Name)/apt/update")
    }
    [PSCustomObject] getAptVersion () {
        return (callGet -Resource "nodes/$($this.Name)/apt/versions")
    }

    # /ceph/*
    [PSCustomObject] getCephFlags () {
        return (callGet -Resource "nodes/$($this.Name)/ceph/flags")
    }
    [PSCustomObject] getCeph () {
        return (callGet -Resource "nodes/$($this.Name)/ceph")
    }

    # /disks/*
    [PSCustomObject] getDisks () {
        return (callGet -Resource "nodes/$($this.Name)/disks")
    }
    # /firewall/*
    [PSCustomObject] getFirewall () {
        return (callGet -Resource "nodes/$($this.Name)/firewall")
    }
    # /lxc/*
    [PSCustomObject] getLxc () {
        return (callGet -Resource "nodes/$($this.Name)/lxc")
    }
    # /network/*
    [PSCustomObject] getNetwork () {
        return (callGet -Resource "nodes/$($this.Name)/Network")
    }
    # /qemu/*
    [PSCustomObject] getQemu () {
        return (callGet -Resource "nodes/$($this.Name)/qemu")
    }
    # /replication/*
    [PSCustomObject] getReplication () {
        return (callGet -Resource "nodes/$($this.Name)/replicate")
    }
    # /scan/*
    [PSCustomObject] getScan () {
        return (callGet -Resource "nodes/$($this.Name)/Scan")
    }
    # /services/*
    [PSCustomObject] getServices () {
        return (callGet -Resource "nodes/$($this.Name)/services")
    }
    # /storage/*
    [PSCustomObject] getStorage () {
        return (callGet -Resource "nodes/$($this.Name)/storage")
    }
    # /tasks/*
    [PSCustomObject] getTasks () {
        return (callGet -Resource "nodes/$($this.Name)/tasks")
    }
    # /vzdump/*
    # [PSCustomObject] getVzdump () {
    #     $this.vzdump = (callGet -Resource "nodes/$($this.Name)/vzdump")
    # }

    # /rrd
    #$this.rrd = (callGet -Resource "nodes/$($this.Name)/rrd")
    # /rrddata
    #$this.rrddata = (callGet -Resource "nodes/$($this.Name)/rrddata")
    # /spiceshell
    # $this.spiceshell = (callPost -Resource "nodes/$($this.Name)/spiceshell")
    # /startall
    #$this.startall = (callPost -Resource "nodes/$($this.Name)/startall")
    
    # /stopall
    #$this.stopall = (callPost -Resource "nodes/$($this.Name)/stopall")
    
    # /vncshell
    #$this.vncshell = (callPost -Resource "nodes/$($this.Name)/vncshell")
    # /vncwebsocket
    #$this.vncwebsocket = (callGet -Resource "nodes/$($this.Name)/vncwebsocket")

    # /execute
    [PSCustomObject] execute ($command, $node) {
        #return (callGet -Resource "nodes/$($this.Name)/execute")
        return $false
    }
    # /migrateall
    [PSCustomObject] MigrateAll () {
        #return (callGet -Resource "nodes/$($this.Name)/migrateall")
        return $false
    }
}