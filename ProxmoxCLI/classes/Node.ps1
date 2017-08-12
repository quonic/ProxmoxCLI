class Node {

    [string] $Name
    [PSCustomObject] $AvailableResources
    
    Node ([string] $Name) {
        $this.Name = [string]$Name
        $this.AvailableResources = (callGet -Resource "node/$Name")
    }
    
    [PSCustomObject] Subscription() {
        return (callGet -Resource "node/$($this.Name)/subscription")
    }
    [PSCustomObject] Syslog() {
        return (callGet -Resource "node/$($this.Name)/syslog")
    }
    [PSCustomObject] Time() {
        return (callGet -Resource "node/$($this.Name)/time")
    }
    [PSCustomObject] Version() {
        return (callGet -Resource "node/$($this.Name)/version")
    }
    [PSCustomObject] Status() {
        return (callGet -Resource "node/$($this.Name)/status")
    }
    [PSCustomObject] Aplinfo() {
        return (callGet -Resource "node/$($this.Name)/aplinfo")
    }
    [PSCustomObject] Dns() {
        return (callGet -Resource "node/$($this.Name)/dns")
    }
    [PSCustomObject] Netstat() {
        return (callGet -Resource "node/$($this.Name)/netstat")
    }
    [PSCustomObject] Report() {
        return (callGet -Resource "node/$($this.Name)/report")
    }


    
    # /apt/*
    [PSCustomObject] getAptChangeLog () {
        return (callGet -Resource "node/$($this.Name)/apt/changlog")
    }
    [PSCustomObject] getAptUpdate () {
        return (callGet -Resource "node/$($this.Name)/apt/update")
    }
    [PSCustomObject] getAptVersion () {
        return (callGet -Resource "node/$($this.Name)/apt/versions")
    }

    # /ceph/*
    [PSCustomObject] getCephFlags () {
        return (callGet -Resource "node/$($this.Name)/ceph/flags")
    }
    [PSCustomObject] getCeph () {
        return (callGet -Resource "node/$($this.Name)/ceph")
    }

    # /disks/*
    [PSCustomObject] getDisks () {
        return (callGet -Resource "node/$($this.Name)/disks")
    }
    # /firewall/*
    [PSCustomObject] getFirewall () {
        return (callGet -Resource "node/$($this.Name)/firewall")
    }
    # /lxc/*
    [PSCustomObject] getLxc () {
        return (callGet -Resource "node/$($this.Name)/lxc")
    }
    # /network/*
    [PSCustomObject] getNetwork () {
        return (callGet -Resource "node/$($this.Name)/Network")
    }
    # /qemu/*
    [PSCustomObject] getQemu () {
        return (callGet -Resource "node/$($this.Name)/qemu")
    }
    # /replication/*
    [PSCustomObject] getReplication () {
        return (callGet -Resource "node/$($this.Name)/replicate")
    }
    # /scan/*
    [PSCustomObject] getScan () {
        return (callGet -Resource "node/$($this.Name)/Scan")
    }
    # /services/*
    [PSCustomObject] getServices () {
        return (callGet -Resource "node/$($this.Name)/services")
    }
    # /storage/*
    [PSCustomObject] getStorage () {
        return (callGet -Resource "node/$($this.Name)/storage")
    }
    # /tasks/*
    [PSCustomObject] getTasks () {
        return (callGet -Resource "node/$($this.Name)/tasks")
    }
    # /vzdump/*
    # [PSCustomObject] getVzdump () {
    #     $this.vzdump = (callGet -Resource "node/$($this.Name)/vzdump")
    # }

    # /rrd
    #$this.rrd = (callGet -Resource "node/$($this.Name)/rrd")
    # /rrddata
    #$this.rrddata = (callGet -Resource "node/$($this.Name)/rrddata")
    # /spiceshell
    # $this.spiceshell = (callPost -Resource "node/$($this.Name)/spiceshell")
    # /startall
    #$this.startall = (callPost -Resource "node/$($this.Name)/startall")
    
    # /stopall
    #$this.stopall = (callPost -Resource "node/$($this.Name)/stopall")
    
    # /vncshell
    #$this.vncshell = (callPost -Resource "node/$($this.Name)/vncshell")
    # /vncwebsocket
    #$this.vncwebsocket = (callGet -Resource "node/$($this.Name)/vncwebsocket")

    # /execute
    [PSCustomObject] execute ($command, $node) {
        #return (callGet -Resource "node/$($this.Name)/execute")
        return $false
    }
    # /migrateall
    [PSCustomObject] MigrateAll () {
        #return (callGet -Resource "node/$($this.Name)/migrateall")
        return $false
    }
}
$pvehost01 = New-Object -TypeName "Node" -ArgumentList "pvehost01"