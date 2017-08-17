class Node {

    [string] $Name
    [PSCustomObject] $AvailableResources
    
    Node ([string] $Name) {
        $this.Name = [string]$Name
        $this.AvailableResources = (callGet -Resource "nodes/$Name")
    }
    
    [PSCustomObject] Subscription() {
        return (callGet -Resource "nodes/$($this.Name)/subscription")
    }
    [PSCustomObject] Syslog() {
        return (callGet -Resource "nodes/$($this.Name)/syslog")
    }
    [PSCustomObject] Time() {
        return (callGet -Resource "nodes/$($this.Name)/time")
    }
    [PSCustomObject] Version() {
        return (callGet -Resource "nodes/$($this.Name)/version")
    }
    [PSCustomObject] Status() {
        return (callGet -Resource "nodes/$($this.Name)/status")
    }
    [PSCustomObject] Aplinfo() {
        return (callGet -Resource "nodes/$($this.Name)/aplinfo")
    }
    [PSCustomObject] Dns() {
        return (callGet -Resource "nodes/$($this.Name)/dns")
    }
    [PSCustomObject] Netstat() {
        return (callGet -Resource "nodes/$($this.Name)/netstat")
    }
    [PSCustomObject] Report() {
        return (callGet -Resource "nodes/$($this.Name)/report")
    }


    
    # /apt/*
    [PSCustomObject] getAptChangeLog () {
        return (callGet -Resource "nodes/$($this.Name)/apt/changlog")
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