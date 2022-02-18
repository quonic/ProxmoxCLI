function Get-Cluster {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster"
}
function Get-ClusterReplication {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/replication"
}
function New-ClusterReplication {
	[CmdletBinding()]
	param(
		# Description.
		[string]
		$comment,
		# Flag to disable/deactivate the entry.
		[switch]
		$disable,
		[Parameter(Mandatory)]
		# Replication Job ID. The ID is composed of a Guest ID and a job number, separated by a hyphen, i.e. '<GUEST>-<JOBNUM>'.
		[string]
		$id,
		# Rate limit in mbps (megabytes per second) as floating point number.
		[number]
		$rate,
		# Mark the replication job for removal. The job will remove all local replication snapshots. When set to 'full', it also tries to remove replicated volumes on the target. The job then removes itself from the configuration file.
		[string]
		$remove_job,
		# Storage replication schedule. The format is a subset of `systemd` calendar events.
		[string]
		$schedule,
		# For internal use, to detect if the guest was stolen.
		[string]
		$source,
		[Parameter(Mandatory)]
		# Target node.
		[string]
		$target,
		[Parameter(Mandatory)]
		# Section type.
		[string]
		$type
	)
	$Options = @()
	$Options.Add('id', $id)
	$Options.Add('target', $target)
	$Options.Add('type', $type)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($disable) { $Options.Add('disable', $disable) }
	if ($rate -and -not [String]::IsNullOrEmpty($rate) -and -not [String]::IsNullOrWhiteSpace($rate)) { $Options.Add('rate', $rate) }
	if ($remove_job -and -not [String]::IsNullOrEmpty($remove_job) -and -not [String]::IsNullOrWhiteSpace($remove_job)) { $Options.Add('remove_job', $remove_job) }
	if ($schedule -and -not [String]::IsNullOrEmpty($schedule) -and -not [String]::IsNullOrWhiteSpace($schedule)) { $Options.Add('schedule', $schedule) }
	if ($source -and -not [String]::IsNullOrEmpty($source) -and -not [String]::IsNullOrWhiteSpace($source)) { $Options.Add('source', $source) }
	Invoke-ProxmoxAPI -Method POST -Resource "/cluster/replication" -Options $Options
}
function Get-ClusterReplicationId {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# Replication Job ID. The ID is composed of a Guest ID and a job number, separated by a hyphen, i.e. '<GUEST>-<JOBNUM>'.
		[string]
		$id
	)
	$Options = @()
	$Options.Add('id', $id)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/replication/{id}" -Options $Options
}
function Set-ClusterReplicationId {
	[CmdletBinding()]
	param(
		# Description.
		[string]
		$comment,
		# A list of settings you want to delete.
		[string]
		$delete,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# Flag to disable/deactivate the entry.
		[switch]
		$disable,
		[Parameter(Mandatory)]
		# Replication Job ID. The ID is composed of a Guest ID and a job number, separated by a hyphen, i.e. '<GUEST>-<JOBNUM>'.
		[string]
		$id,
		# Rate limit in mbps (megabytes per second) as floating point number.
		[number]
		$rate,
		# Mark the replication job for removal. The job will remove all local replication snapshots. When set to 'full', it also tries to remove replicated volumes on the target. The job then removes itself from the configuration file.
		[string]
		$remove_job,
		# Storage replication schedule. The format is a subset of `systemd` calendar events.
		[string]
		$schedule,
		# For internal use, to detect if the guest was stolen.
		[string]
		$source
	)
	$Options = @()
	$Options.Add('id', $id)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($delete -and -not [String]::IsNullOrEmpty($delete) -and -not [String]::IsNullOrWhiteSpace($delete)) { $Options.Add('delete', $delete) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($disable) { $Options.Add('disable', $disable) }
	if ($rate -and -not [String]::IsNullOrEmpty($rate) -and -not [String]::IsNullOrWhiteSpace($rate)) { $Options.Add('rate', $rate) }
	if ($remove_job -and -not [String]::IsNullOrEmpty($remove_job) -and -not [String]::IsNullOrWhiteSpace($remove_job)) { $Options.Add('remove_job', $remove_job) }
	if ($schedule -and -not [String]::IsNullOrEmpty($schedule) -and -not [String]::IsNullOrWhiteSpace($schedule)) { $Options.Add('schedule', $schedule) }
	if ($source -and -not [String]::IsNullOrEmpty($source) -and -not [String]::IsNullOrWhiteSpace($source)) { $Options.Add('source', $source) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/cluster/replication/{id}" -Options $Options
}
function Remove-ClusterReplicationId {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Replication Job ID. The ID is composed of a Guest ID and a job number, separated by a hyphen, i.e. '<GUEST>-<JOBNUM>'.
		[string]
		$id,
		# Keep replicated data at target (do not remove).
		[switch]
		$keep
	)
	$Options = @()
	$Options.Add('id', $id)
	if ($force) { $Options.Add('force', $force) }
	if ($keep) { $Options.Add('keep', $keep) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/cluster/replication/{id}" -Options $Options
}
function Get-ClusterMetrics {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/metrics"
}
function Get-ClusterMetricsServer {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/metrics/server"
}
function Get-ClusterMetricsServerId {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# 
		[string]
		$id
	)
	$Options = @()
	$Options.Add('id', $id)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/metrics/server/{id}" -Options $Options
}
function New-ClusterMetricsServerId {
	[CmdletBinding()]
	param(
		# An API path prefix inserted between '<host>:<port>/' and '/api2/'. Can be useful if the InfluxDB service runs behind a reverse proxy.
		[string]
		$apipathprefix,
		# The InfluxDB bucket/db. Only necessary when using the http v2 api.
		[string]
		$bucket,
		# Flag to disable the plugin.
		[switch]
		$disable,
		[Parameter(Mandatory)]
		# The ID of the entry.
		[string]
		$id,
		# 
		[string]
		$influxdbproto,
		# InfluxDB max-body-size in bytes. Requests are batched up to this size.
		[integer]
		$maxbodysize,
		# MTU for metrics transmission over UDP
		[integer]
		$mtu,
		# The InfluxDB organization. Only necessary when using the http v2 api. Has no meaning when using v2 compatibility api.
		[string]
		$organization,
		# root graphite path (ex: proxmox.mycluster.mykey)
		[string]
		$path,
		[Parameter(Mandatory)]
		# server network port
		[integer]
		$port,
		# Protocol to send graphite data. TCP or UDP (default)
		[string]
		$proto,
		[Parameter(Mandatory)]
		# server dns name or IP address
		[string]
		$server,
		# graphite TCP socket timeout (default=1)
		[integer]
		$timeout,
		# The InfluxDB access token. Only necessary when using the http v2 api. If the v2 compatibility api is used, use 'user:password' instead.
		[string]
		$token,
		[Parameter(Mandatory)]
		# Plugin type.
		[string]
		$type,
		# Set to 0 to disable certificate verification for https endpoints.
		[switch]
		$verifycertificate
	)
	$Options = @()
	$Options.Add('id', $id)
	$Options.Add('port', $port)
	$Options.Add('server', $server)
	$Options.Add('type', $type)
	if ($apipathprefix -and -not [String]::IsNullOrEmpty($apipathprefix) -and -not [String]::IsNullOrWhiteSpace($apipathprefix)) { $Options.Add('api-path-prefix', $apipathprefix) }
	if ($bucket -and -not [String]::IsNullOrEmpty($bucket) -and -not [String]::IsNullOrWhiteSpace($bucket)) { $Options.Add('bucket', $bucket) }
	if ($disable) { $Options.Add('disable', $disable) }
	if ($influxdbproto -and -not [String]::IsNullOrEmpty($influxdbproto) -and -not [String]::IsNullOrWhiteSpace($influxdbproto)) { $Options.Add('influxdbproto', $influxdbproto) }
	if ($maxbodysize -and -not [String]::IsNullOrEmpty($maxbodysize) -and -not [String]::IsNullOrWhiteSpace($maxbodysize)) { $Options.Add('max-body-size', $maxbodysize) }
	if ($mtu -and -not [String]::IsNullOrEmpty($mtu) -and -not [String]::IsNullOrWhiteSpace($mtu)) { $Options.Add('mtu', $mtu) }
	if ($organization -and -not [String]::IsNullOrEmpty($organization) -and -not [String]::IsNullOrWhiteSpace($organization)) { $Options.Add('organization', $organization) }
	if ($path -and -not [String]::IsNullOrEmpty($path) -and -not [String]::IsNullOrWhiteSpace($path)) { $Options.Add('path', $path) }
	if ($proto -and -not [String]::IsNullOrEmpty($proto) -and -not [String]::IsNullOrWhiteSpace($proto)) { $Options.Add('proto', $proto) }
	if ($timeout -and -not [String]::IsNullOrEmpty($timeout) -and -not [String]::IsNullOrWhiteSpace($timeout)) { $Options.Add('timeout', $timeout) }
	if ($token -and -not [String]::IsNullOrEmpty($token) -and -not [String]::IsNullOrWhiteSpace($token)) { $Options.Add('token', $token) }
	if ($verifycertificate) { $Options.Add('verify-certificate', $verifycertificate) }
	Invoke-ProxmoxAPI -Method POST -Resource "/cluster/metrics/server/{id}" -Options $Options
}
function Set-ClusterMetricsServerId {
	[CmdletBinding()]
	param(
		# An API path prefix inserted between '<host>:<port>/' and '/api2/'. Can be useful if the InfluxDB service runs behind a reverse proxy.
		[string]
		$apipathprefix,
		# The InfluxDB bucket/db. Only necessary when using the http v2 api.
		[string]
		$bucket,
		# A list of settings you want to delete.
		[string]
		$delete,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# Flag to disable the plugin.
		[switch]
		$disable,
		[Parameter(Mandatory)]
		# The ID of the entry.
		[string]
		$id,
		# 
		[string]
		$influxdbproto,
		# InfluxDB max-body-size in bytes. Requests are batched up to this size.
		[integer]
		$maxbodysize,
		# MTU for metrics transmission over UDP
		[integer]
		$mtu,
		# The InfluxDB organization. Only necessary when using the http v2 api. Has no meaning when using v2 compatibility api.
		[string]
		$organization,
		# root graphite path (ex: proxmox.mycluster.mykey)
		[string]
		$path,
		[Parameter(Mandatory)]
		# server network port
		[integer]
		$port,
		# Protocol to send graphite data. TCP or UDP (default)
		[string]
		$proto,
		[Parameter(Mandatory)]
		# server dns name or IP address
		[string]
		$server,
		# graphite TCP socket timeout (default=1)
		[integer]
		$timeout,
		# The InfluxDB access token. Only necessary when using the http v2 api. If the v2 compatibility api is used, use 'user:password' instead.
		[string]
		$token,
		# Set to 0 to disable certificate verification for https endpoints.
		[switch]
		$verifycertificate
	)
	$Options = @()
	$Options.Add('id', $id)
	$Options.Add('port', $port)
	$Options.Add('server', $server)
	if ($apipathprefix -and -not [String]::IsNullOrEmpty($apipathprefix) -and -not [String]::IsNullOrWhiteSpace($apipathprefix)) { $Options.Add('api-path-prefix', $apipathprefix) }
	if ($bucket -and -not [String]::IsNullOrEmpty($bucket) -and -not [String]::IsNullOrWhiteSpace($bucket)) { $Options.Add('bucket', $bucket) }
	if ($delete -and -not [String]::IsNullOrEmpty($delete) -and -not [String]::IsNullOrWhiteSpace($delete)) { $Options.Add('delete', $delete) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($disable) { $Options.Add('disable', $disable) }
	if ($influxdbproto -and -not [String]::IsNullOrEmpty($influxdbproto) -and -not [String]::IsNullOrWhiteSpace($influxdbproto)) { $Options.Add('influxdbproto', $influxdbproto) }
	if ($maxbodysize -and -not [String]::IsNullOrEmpty($maxbodysize) -and -not [String]::IsNullOrWhiteSpace($maxbodysize)) { $Options.Add('max-body-size', $maxbodysize) }
	if ($mtu -and -not [String]::IsNullOrEmpty($mtu) -and -not [String]::IsNullOrWhiteSpace($mtu)) { $Options.Add('mtu', $mtu) }
	if ($organization -and -not [String]::IsNullOrEmpty($organization) -and -not [String]::IsNullOrWhiteSpace($organization)) { $Options.Add('organization', $organization) }
	if ($path -and -not [String]::IsNullOrEmpty($path) -and -not [String]::IsNullOrWhiteSpace($path)) { $Options.Add('path', $path) }
	if ($proto -and -not [String]::IsNullOrEmpty($proto) -and -not [String]::IsNullOrWhiteSpace($proto)) { $Options.Add('proto', $proto) }
	if ($timeout -and -not [String]::IsNullOrEmpty($timeout) -and -not [String]::IsNullOrWhiteSpace($timeout)) { $Options.Add('timeout', $timeout) }
	if ($token -and -not [String]::IsNullOrEmpty($token) -and -not [String]::IsNullOrWhiteSpace($token)) { $Options.Add('token', $token) }
	if ($verifycertificate) { $Options.Add('verify-certificate', $verifycertificate) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/cluster/metrics/server/{id}" -Options $Options
}
function Remove-ClusterMetricsServerId {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# 
		[string]
		$id
	)
	$Options = @()
	$Options.Add('id', $id)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/cluster/metrics/server/{id}" -Options $Options
}
function Get-ClusterConfig {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/config"
}
function New-ClusterConfig {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The name of the cluster.
		[string]
		$clustername,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link0,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link1,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link2,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link3,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link4,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link5,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link6,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link7,
		# Node id for this node.
		[integer]
		$nodeid,
		# Number of votes for this node.
		[integer]
		$votes
	)
	$Options = @()
	$Options.Add('clustername', $clustername)
	if ($link0 -and -not [String]::IsNullOrEmpty($link0) -and -not [String]::IsNullOrWhiteSpace($link0)) { $Options.Add('link0', $link0) }
	if ($link1 -and -not [String]::IsNullOrEmpty($link1) -and -not [String]::IsNullOrWhiteSpace($link1)) { $Options.Add('link1', $link1) }
	if ($link2 -and -not [String]::IsNullOrEmpty($link2) -and -not [String]::IsNullOrWhiteSpace($link2)) { $Options.Add('link2', $link2) }
	if ($link3 -and -not [String]::IsNullOrEmpty($link3) -and -not [String]::IsNullOrWhiteSpace($link3)) { $Options.Add('link3', $link3) }
	if ($link4 -and -not [String]::IsNullOrEmpty($link4) -and -not [String]::IsNullOrWhiteSpace($link4)) { $Options.Add('link4', $link4) }
	if ($link5 -and -not [String]::IsNullOrEmpty($link5) -and -not [String]::IsNullOrWhiteSpace($link5)) { $Options.Add('link5', $link5) }
	if ($link6 -and -not [String]::IsNullOrEmpty($link6) -and -not [String]::IsNullOrWhiteSpace($link6)) { $Options.Add('link6', $link6) }
	if ($link7 -and -not [String]::IsNullOrEmpty($link7) -and -not [String]::IsNullOrWhiteSpace($link7)) { $Options.Add('link7', $link7) }
	if ($nodeid -and -not [String]::IsNullOrEmpty($nodeid) -and -not [String]::IsNullOrWhiteSpace($nodeid)) { $Options.Add('nodeid', $nodeid) }
	if ($votes -and -not [String]::IsNullOrEmpty($votes) -and -not [String]::IsNullOrWhiteSpace($votes)) { $Options.Add('votes', $votes) }
	Invoke-ProxmoxAPI -Method POST -Resource "/cluster/config" -Options $Options
}
function Get-ClusterConfigApiversion {
	[CmdletBinding()]
	[OutputType([Int32])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/config/apiversion"
}
function Get-ClusterFirewall {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/firewall"
}
function Get-ClusterConfigNodes {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/config/nodes"
}
function New-ClusterConfigNodesNode {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		# The JOIN_API_VERSION of the new node.
		[integer]
		$apiversion,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link0,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link1,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link2,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link3,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link4,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link5,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link6,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link7,
		# IP Address of node to add. Used as fallback if no links are given.
		[string]
		$new_node_ip,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Node id for this node.
		[integer]
		$nodeid,
		# Number of votes for this node
		[integer]
		$votes
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($apiversion -and -not [String]::IsNullOrEmpty($apiversion) -and -not [String]::IsNullOrWhiteSpace($apiversion)) { $Options.Add('apiversion', $apiversion) }
	if ($force) { $Options.Add('force', $force) }
	if ($link0 -and -not [String]::IsNullOrEmpty($link0) -and -not [String]::IsNullOrWhiteSpace($link0)) { $Options.Add('link0', $link0) }
	if ($link1 -and -not [String]::IsNullOrEmpty($link1) -and -not [String]::IsNullOrWhiteSpace($link1)) { $Options.Add('link1', $link1) }
	if ($link2 -and -not [String]::IsNullOrEmpty($link2) -and -not [String]::IsNullOrWhiteSpace($link2)) { $Options.Add('link2', $link2) }
	if ($link3 -and -not [String]::IsNullOrEmpty($link3) -and -not [String]::IsNullOrWhiteSpace($link3)) { $Options.Add('link3', $link3) }
	if ($link4 -and -not [String]::IsNullOrEmpty($link4) -and -not [String]::IsNullOrWhiteSpace($link4)) { $Options.Add('link4', $link4) }
	if ($link5 -and -not [String]::IsNullOrEmpty($link5) -and -not [String]::IsNullOrWhiteSpace($link5)) { $Options.Add('link5', $link5) }
	if ($link6 -and -not [String]::IsNullOrEmpty($link6) -and -not [String]::IsNullOrWhiteSpace($link6)) { $Options.Add('link6', $link6) }
	if ($link7 -and -not [String]::IsNullOrEmpty($link7) -and -not [String]::IsNullOrWhiteSpace($link7)) { $Options.Add('link7', $link7) }
	if ($new_node_ip -and -not [String]::IsNullOrEmpty($new_node_ip) -and -not [String]::IsNullOrWhiteSpace($new_node_ip)) { $Options.Add('new_node_ip', $new_node_ip) }
	if ($nodeid -and -not [String]::IsNullOrEmpty($nodeid) -and -not [String]::IsNullOrWhiteSpace($nodeid)) { $Options.Add('nodeid', $nodeid) }
	if ($votes -and -not [String]::IsNullOrEmpty($votes) -and -not [String]::IsNullOrWhiteSpace($votes)) { $Options.Add('votes', $votes) }
	Invoke-ProxmoxAPI -Method POST -Resource "/cluster/config/nodes/{node}" -Options $Options
}
function Remove-ClusterConfigNodesNode {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/cluster/config/nodes/{node}" -Options $Options
}
function Get-ClusterBackup {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/backup"
}
function New-ClusterBackup {
	[CmdletBinding()]
	param(
		# Backup all known guest systems on this host.
		[switch]
		$all,
		# Limit I/O bandwidth (KBytes per second).
		[integer]
		$bwlimit,
		# Description for the Job.
		[string]
		$comment,
		# Compress dump file.
		[string]
		$compress,
		# Day of week selection.
		[string]
		$dow,
		# Store resulting files to specified directory.
		[string]
		$dumpdir,
		# Enable or disable the job.
		[switch]
		$enabled,
		# Exclude specified guest systems (assumes --all)
		[string]
		$exclude,
		# Exclude certain files/directories (shell globs). Paths starting with '/' are anchored to the container's root,  other paths match relative to each subdirectory.
		[string]
		$excludepath,
		# Job ID (will be autogenerated).
		[string]
		$id,
		# Set CFQ ionice priority.
		[integer]
		$ionice,
		# Maximal time to wait for the global lock (minutes).
		[integer]
		$lockwait,
		# Specify when to send an email
		[string]
		$mailnotification,
		# Comma-separated list of email addresses or users that should receive email notifications.
		[string]
		$mailto,
		# Deprecated: use 'prune-backups' instead. Maximal number of backup files per guest system.
		[integer]
		$maxfiles,
		# Backup mode.
		[string]
		$mode,
		# Only run if executed on this node.
		[string]
		$node,
		# Use pigz instead of gzip when N>0. N=1 uses half of cores, N>1 uses N as thread count.
		[integer]
		$pigz,
		# Backup all known guest systems included in the specified pool.
		[string]
		$pool,
		# Use these retention options instead of those from the storage configuration.
		[string]
		$prunebackups,
		# Be quiet.
		[switch]
		$quiet,
		# Prune older backups according to 'prune-backups'.
		[switch]
		$remove,
		# Backup schedule. The format is a subset of `systemd` calendar events.
		[string]
		$schedule,
		# Use specified hook script.
		[string]
		$script,
		# Job Start time.
		[string]
		$starttime,
		# Exclude temporary files and logs.
		[switch]
		$stdexcludes,
		# Stop running backup jobs on this host.
		[switch]
		$stop,
		# Maximal time to wait until a guest system is stopped (minutes).
		[integer]
		$stopwait,
		# Store resulting file to this storage.
		[string]
		$storage,
		# Store temporary files to specified directory.
		[string]
		$tmpdir,
		# The ID of the guest system you want to backup.
		[string]
		$vmid,
		# Zstd threads. N=0 uses half of the available cores, N>0 uses N as thread count.
		[integer]
		$zstd
	)
	$Options = @()
	if ($all) { $Options.Add('all', $all) }
	if ($bwlimit -and -not [String]::IsNullOrEmpty($bwlimit) -and -not [String]::IsNullOrWhiteSpace($bwlimit)) { $Options.Add('bwlimit', $bwlimit) }
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($compress -and -not [String]::IsNullOrEmpty($compress) -and -not [String]::IsNullOrWhiteSpace($compress)) { $Options.Add('compress', $compress) }
	if ($dow -and -not [String]::IsNullOrEmpty($dow) -and -not [String]::IsNullOrWhiteSpace($dow)) { $Options.Add('dow', $dow) }
	if ($dumpdir -and -not [String]::IsNullOrEmpty($dumpdir) -and -not [String]::IsNullOrWhiteSpace($dumpdir)) { $Options.Add('dumpdir', $dumpdir) }
	if ($enabled) { $Options.Add('enabled', $enabled) }
	if ($exclude -and -not [String]::IsNullOrEmpty($exclude) -and -not [String]::IsNullOrWhiteSpace($exclude)) { $Options.Add('exclude', $exclude) }
	if ($excludepath -and -not [String]::IsNullOrEmpty($excludepath) -and -not [String]::IsNullOrWhiteSpace($excludepath)) { $Options.Add('exclude-path', $excludepath) }
	if ($id -and -not [String]::IsNullOrEmpty($id) -and -not [String]::IsNullOrWhiteSpace($id)) { $Options.Add('id', $id) }
	if ($ionice -and -not [String]::IsNullOrEmpty($ionice) -and -not [String]::IsNullOrWhiteSpace($ionice)) { $Options.Add('ionice', $ionice) }
	if ($lockwait -and -not [String]::IsNullOrEmpty($lockwait) -and -not [String]::IsNullOrWhiteSpace($lockwait)) { $Options.Add('lockwait', $lockwait) }
	if ($mailnotification -and -not [String]::IsNullOrEmpty($mailnotification) -and -not [String]::IsNullOrWhiteSpace($mailnotification)) { $Options.Add('mailnotification', $mailnotification) }
	if ($mailto -and -not [String]::IsNullOrEmpty($mailto) -and -not [String]::IsNullOrWhiteSpace($mailto)) { $Options.Add('mailto', $mailto) }
	if ($maxfiles -and -not [String]::IsNullOrEmpty($maxfiles) -and -not [String]::IsNullOrWhiteSpace($maxfiles)) { $Options.Add('maxfiles', $maxfiles) }
	if ($mode -and -not [String]::IsNullOrEmpty($mode) -and -not [String]::IsNullOrWhiteSpace($mode)) { $Options.Add('mode', $mode) }
	if ($node -and -not [String]::IsNullOrEmpty($node) -and -not [String]::IsNullOrWhiteSpace($node)) { $Options.Add('node', $node) }
	if ($pigz -and -not [String]::IsNullOrEmpty($pigz) -and -not [String]::IsNullOrWhiteSpace($pigz)) { $Options.Add('pigz', $pigz) }
	if ($pool -and -not [String]::IsNullOrEmpty($pool) -and -not [String]::IsNullOrWhiteSpace($pool)) { $Options.Add('pool', $pool) }
	if ($prunebackups -and -not [String]::IsNullOrEmpty($prunebackups) -and -not [String]::IsNullOrWhiteSpace($prunebackups)) { $Options.Add('prune-backups', $prunebackups) }
	if ($quiet) { $Options.Add('quiet', $quiet) }
	if ($remove) { $Options.Add('remove', $remove) }
	if ($schedule -and -not [String]::IsNullOrEmpty($schedule) -and -not [String]::IsNullOrWhiteSpace($schedule)) { $Options.Add('schedule', $schedule) }
	if ($script -and -not [String]::IsNullOrEmpty($script) -and -not [String]::IsNullOrWhiteSpace($script)) { $Options.Add('script', $script) }
	if ($starttime -and -not [String]::IsNullOrEmpty($starttime) -and -not [String]::IsNullOrWhiteSpace($starttime)) { $Options.Add('starttime', $starttime) }
	if ($stdexcludes) { $Options.Add('stdexcludes', $stdexcludes) }
	if ($stop) { $Options.Add('stop', $stop) }
	if ($stopwait -and -not [String]::IsNullOrEmpty($stopwait) -and -not [String]::IsNullOrWhiteSpace($stopwait)) { $Options.Add('stopwait', $stopwait) }
	if ($storage -and -not [String]::IsNullOrEmpty($storage) -and -not [String]::IsNullOrWhiteSpace($storage)) { $Options.Add('storage', $storage) }
	if ($tmpdir -and -not [String]::IsNullOrEmpty($tmpdir) -and -not [String]::IsNullOrWhiteSpace($tmpdir)) { $Options.Add('tmpdir', $tmpdir) }
	if ($vmid -and -not [String]::IsNullOrEmpty($vmid) -and -not [String]::IsNullOrWhiteSpace($vmid)) { $Options.Add('vmid', $vmid) }
	if ($zstd -and -not [String]::IsNullOrEmpty($zstd) -and -not [String]::IsNullOrWhiteSpace($zstd)) { $Options.Add('zstd', $zstd) }
	Invoke-ProxmoxAPI -Method POST -Resource "/cluster/backup" -Options $Options
}
function Get-ClusterConfigJoin {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		# The node for which the joinee gets the nodeinfo. 
		[string]
		$node
	)
	$Options = @()
	if ($node -and -not [String]::IsNullOrEmpty($node) -and -not [String]::IsNullOrWhiteSpace($node)) { $Options.Add('node', $node) }
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/config/join" -Options $Options
}
function New-ClusterConfigJoin {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# Certificate SHA 256 fingerprint.
		[string]
		$fingerprint,
		[Parameter(Mandatory)]
		# Hostname (or IP) of an existing cluster member.
		[string]
		$hostname,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link0,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link1,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link2,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link3,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link4,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link5,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link6,
		# Address and priority information of a single corosync link. (up to 8 links supported; link0..link7)
		[string]
		$link7,
		# Node id for this node.
		[integer]
		$nodeid,
		[Parameter(Mandatory)]
		# Superuser (root) password of peer node.
		[securestring]
		$password,
		# Number of votes for this node
		[integer]
		$votes
	)
	$Options = @()
	$Options.Add('fingerprint', $fingerprint)
	$Options.Add('hostname', $hostname)
	$Options.Add('password', $password)
	if ($force) { $Options.Add('force', $force) }
	if ($link0 -and -not [String]::IsNullOrEmpty($link0) -and -not [String]::IsNullOrWhiteSpace($link0)) { $Options.Add('link0', $link0) }
	if ($link1 -and -not [String]::IsNullOrEmpty($link1) -and -not [String]::IsNullOrWhiteSpace($link1)) { $Options.Add('link1', $link1) }
	if ($link2 -and -not [String]::IsNullOrEmpty($link2) -and -not [String]::IsNullOrWhiteSpace($link2)) { $Options.Add('link2', $link2) }
	if ($link3 -and -not [String]::IsNullOrEmpty($link3) -and -not [String]::IsNullOrWhiteSpace($link3)) { $Options.Add('link3', $link3) }
	if ($link4 -and -not [String]::IsNullOrEmpty($link4) -and -not [String]::IsNullOrWhiteSpace($link4)) { $Options.Add('link4', $link4) }
	if ($link5 -and -not [String]::IsNullOrEmpty($link5) -and -not [String]::IsNullOrWhiteSpace($link5)) { $Options.Add('link5', $link5) }
	if ($link6 -and -not [String]::IsNullOrEmpty($link6) -and -not [String]::IsNullOrWhiteSpace($link6)) { $Options.Add('link6', $link6) }
	if ($link7 -and -not [String]::IsNullOrEmpty($link7) -and -not [String]::IsNullOrWhiteSpace($link7)) { $Options.Add('link7', $link7) }
	if ($nodeid -and -not [String]::IsNullOrEmpty($nodeid) -and -not [String]::IsNullOrWhiteSpace($nodeid)) { $Options.Add('nodeid', $nodeid) }
	if ($votes -and -not [String]::IsNullOrEmpty($votes) -and -not [String]::IsNullOrWhiteSpace($votes)) { $Options.Add('votes', $votes) }
	Invoke-ProxmoxAPI -Method POST -Resource "/cluster/config/join" -Options $Options
}
function Get-ClusterBackupInfo {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/backup-info"
}
function Get-ClusterConfigTotem {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/config/totem"
}
function Get-ClusterHa {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/ha"
}
function Get-ClusterConfigQdevice {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/config/qdevice"
}
function Get-ClusterAcme {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/acme"
}
function Get-ClusterFirewallGroups {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/firewall/groups"
}
function New-ClusterFirewallGroups {
	[CmdletBinding()]
	param(
		# 
		[string]
		$comment,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# Security Group name.
		[string]
		$group,
		# Rename/update an existing security group. You can set 'rename' to the same value as 'name' to update the 'comment' of an existing group.
		[string]
		$rename
	)
	$Options = @()
	$Options.Add('group', $group)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($rename -and -not [String]::IsNullOrEmpty($rename) -and -not [String]::IsNullOrWhiteSpace($rename)) { $Options.Add('rename', $rename) }
	Invoke-ProxmoxAPI -Method POST -Resource "/cluster/firewall/groups" -Options $Options
}
function Get-ClusterFirewallGroupsGroup {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# Security Group name.
		[string]
		$group
	)
	$Options = @()
	$Options.Add('group', $group)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/firewall/groups/{group}" -Options $Options
}
function New-ClusterFirewallGroupsGroup {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.
		[string]
		$action,
		# Descriptive comment.
		[string]
		$comment,
		# Restrict packet destination address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
		[string]
		$dest,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# Restrict TCP/UDP destination port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
		[string]
		$dport,
		# Flag to enable/disable a rule.
		[integer]
		$enable,
		[Parameter(Mandatory)]
		# Security Group name.
		[string]
		$group,
		# Specify icmp-type. Only valid if proto equals 'icmp'.
		[string]
		$icmptype,
		# Network interface name. You have to use network configuration key names for VMs and containers ('net\d+'). Host related rules can use arbitrary strings.
		[string]
		$iface,
		# Log level for firewall rule.
		[string]
		$log,
		# Use predefined standard macro.
		[string]
		$macro,
		# Update rule at position <pos>.
		[integer]
		$pos,
		# IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.
		[string]
		$proto,
		# Restrict packet source address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
		[string]
		$source,
		# Restrict TCP/UDP source port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
		[string]
		$sport,
		[Parameter(Mandatory)]
		# Rule type.
		[string]
		$type
	)
	$Options = @()
	$Options.Add('action', $action)
	$Options.Add('group', $group)
	$Options.Add('type', $type)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($dest -and -not [String]::IsNullOrEmpty($dest) -and -not [String]::IsNullOrWhiteSpace($dest)) { $Options.Add('dest', $dest) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($dport -and -not [String]::IsNullOrEmpty($dport) -and -not [String]::IsNullOrWhiteSpace($dport)) { $Options.Add('dport', $dport) }
	if ($enable -and -not [String]::IsNullOrEmpty($enable) -and -not [String]::IsNullOrWhiteSpace($enable)) { $Options.Add('enable', $enable) }
	if ($icmptype -and -not [String]::IsNullOrEmpty($icmptype) -and -not [String]::IsNullOrWhiteSpace($icmptype)) { $Options.Add('icmp-type', $icmptype) }
	if ($iface -and -not [String]::IsNullOrEmpty($iface) -and -not [String]::IsNullOrWhiteSpace($iface)) { $Options.Add('iface', $iface) }
	if ($log -and -not [String]::IsNullOrEmpty($log) -and -not [String]::IsNullOrWhiteSpace($log)) { $Options.Add('log', $log) }
	if ($macro -and -not [String]::IsNullOrEmpty($macro) -and -not [String]::IsNullOrWhiteSpace($macro)) { $Options.Add('macro', $macro) }
	if ($pos -and -not [String]::IsNullOrEmpty($pos) -and -not [String]::IsNullOrWhiteSpace($pos)) { $Options.Add('pos', $pos) }
	if ($proto -and -not [String]::IsNullOrEmpty($proto) -and -not [String]::IsNullOrWhiteSpace($proto)) { $Options.Add('proto', $proto) }
	if ($source -and -not [String]::IsNullOrEmpty($source) -and -not [String]::IsNullOrWhiteSpace($source)) { $Options.Add('source', $source) }
	if ($sport -and -not [String]::IsNullOrEmpty($sport) -and -not [String]::IsNullOrWhiteSpace($sport)) { $Options.Add('sport', $sport) }
	Invoke-ProxmoxAPI -Method POST -Resource "/cluster/firewall/groups/{group}" -Options $Options
}
function Remove-ClusterFirewallGroupsGroup {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Security Group name.
		[string]
		$group
	)
	$Options = @()
	$Options.Add('group', $group)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/cluster/firewall/groups/{group}" -Options $Options
}
function Get-ClusterFirewallGroupsGroupPos {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# Security Group name.
		[string]
		$group,
		# Update rule at position <pos>.
		[integer]
		$pos
	)
	$Options = @()
	$Options.Add('group', $group)
	if ($pos -and -not [String]::IsNullOrEmpty($pos) -and -not [String]::IsNullOrWhiteSpace($pos)) { $Options.Add('pos', $pos) }
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/firewall/groups/{group}/{pos}" -Options $Options
}
function Set-ClusterFirewallGroupsGroupPos {
	[CmdletBinding()]
	param(
		# Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.
		[string]
		$action,
		# Descriptive comment.
		[string]
		$comment,
		# A list of settings you want to delete.
		[string]
		$delete,
		# Restrict packet destination address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
		[string]
		$dest,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# Restrict TCP/UDP destination port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
		[string]
		$dport,
		# Flag to enable/disable a rule.
		[integer]
		$enable,
		[Parameter(Mandatory)]
		# Security Group name.
		[string]
		$group,
		# Specify icmp-type. Only valid if proto equals 'icmp'.
		[string]
		$icmptype,
		# Network interface name. You have to use network configuration key names for VMs and containers ('net\d+'). Host related rules can use arbitrary strings.
		[string]
		$iface,
		# Log level for firewall rule.
		[string]
		$log,
		# Use predefined standard macro.
		[string]
		$macro,
		# Move rule to new position <moveto>. Other arguments are ignored.
		[integer]
		$moveto,
		# Update rule at position <pos>.
		[integer]
		$pos,
		# IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.
		[string]
		$proto,
		# Restrict packet source address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
		[string]
		$source,
		# Restrict TCP/UDP source port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
		[string]
		$sport,
		# Rule type.
		[string]
		$type
	)
	$Options = @()
	$Options.Add('group', $group)
	if ($action -and -not [String]::IsNullOrEmpty($action) -and -not [String]::IsNullOrWhiteSpace($action)) { $Options.Add('action', $action) }
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($delete -and -not [String]::IsNullOrEmpty($delete) -and -not [String]::IsNullOrWhiteSpace($delete)) { $Options.Add('delete', $delete) }
	if ($dest -and -not [String]::IsNullOrEmpty($dest) -and -not [String]::IsNullOrWhiteSpace($dest)) { $Options.Add('dest', $dest) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($dport -and -not [String]::IsNullOrEmpty($dport) -and -not [String]::IsNullOrWhiteSpace($dport)) { $Options.Add('dport', $dport) }
	if ($enable -and -not [String]::IsNullOrEmpty($enable) -and -not [String]::IsNullOrWhiteSpace($enable)) { $Options.Add('enable', $enable) }
	if ($icmptype -and -not [String]::IsNullOrEmpty($icmptype) -and -not [String]::IsNullOrWhiteSpace($icmptype)) { $Options.Add('icmp-type', $icmptype) }
	if ($iface -and -not [String]::IsNullOrEmpty($iface) -and -not [String]::IsNullOrWhiteSpace($iface)) { $Options.Add('iface', $iface) }
	if ($log -and -not [String]::IsNullOrEmpty($log) -and -not [String]::IsNullOrWhiteSpace($log)) { $Options.Add('log', $log) }
	if ($macro -and -not [String]::IsNullOrEmpty($macro) -and -not [String]::IsNullOrWhiteSpace($macro)) { $Options.Add('macro', $macro) }
	if ($moveto -and -not [String]::IsNullOrEmpty($moveto) -and -not [String]::IsNullOrWhiteSpace($moveto)) { $Options.Add('moveto', $moveto) }
	if ($pos -and -not [String]::IsNullOrEmpty($pos) -and -not [String]::IsNullOrWhiteSpace($pos)) { $Options.Add('pos', $pos) }
	if ($proto -and -not [String]::IsNullOrEmpty($proto) -and -not [String]::IsNullOrWhiteSpace($proto)) { $Options.Add('proto', $proto) }
	if ($source -and -not [String]::IsNullOrEmpty($source) -and -not [String]::IsNullOrWhiteSpace($source)) { $Options.Add('source', $source) }
	if ($sport -and -not [String]::IsNullOrEmpty($sport) -and -not [String]::IsNullOrWhiteSpace($sport)) { $Options.Add('sport', $sport) }
	if ($type -and -not [String]::IsNullOrEmpty($type) -and -not [String]::IsNullOrWhiteSpace($type)) { $Options.Add('type', $type) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/cluster/firewall/groups/{group}/{pos}" -Options $Options
}
function Remove-ClusterFirewallGroupsGroupPos {
	[CmdletBinding()]
	param(
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# Security Group name.
		[string]
		$group,
		# Update rule at position <pos>.
		[integer]
		$pos
	)
	$Options = @()
	$Options.Add('group', $group)
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($pos -and -not [String]::IsNullOrEmpty($pos) -and -not [String]::IsNullOrWhiteSpace($pos)) { $Options.Add('pos', $pos) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/cluster/firewall/groups/{group}/{pos}" -Options $Options
}
function Get-ClusterCeph {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/ceph"
}
function Get-ClusterFirewallRules {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/firewall/rules"
}
function New-ClusterFirewallRules {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.
		[string]
		$action,
		# Descriptive comment.
		[string]
		$comment,
		# Restrict packet destination address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
		[string]
		$dest,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# Restrict TCP/UDP destination port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
		[string]
		$dport,
		# Flag to enable/disable a rule.
		[integer]
		$enable,
		# Specify icmp-type. Only valid if proto equals 'icmp'.
		[string]
		$icmptype,
		# Network interface name. You have to use network configuration key names for VMs and containers ('net\d+'). Host related rules can use arbitrary strings.
		[string]
		$iface,
		# Log level for firewall rule.
		[string]
		$log,
		# Use predefined standard macro.
		[string]
		$macro,
		# Update rule at position <pos>.
		[integer]
		$pos,
		# IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.
		[string]
		$proto,
		# Restrict packet source address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
		[string]
		$source,
		# Restrict TCP/UDP source port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
		[string]
		$sport,
		[Parameter(Mandatory)]
		# Rule type.
		[string]
		$type
	)
	$Options = @()
	$Options.Add('action', $action)
	$Options.Add('type', $type)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($dest -and -not [String]::IsNullOrEmpty($dest) -and -not [String]::IsNullOrWhiteSpace($dest)) { $Options.Add('dest', $dest) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($dport -and -not [String]::IsNullOrEmpty($dport) -and -not [String]::IsNullOrWhiteSpace($dport)) { $Options.Add('dport', $dport) }
	if ($enable -and -not [String]::IsNullOrEmpty($enable) -and -not [String]::IsNullOrWhiteSpace($enable)) { $Options.Add('enable', $enable) }
	if ($icmptype -and -not [String]::IsNullOrEmpty($icmptype) -and -not [String]::IsNullOrWhiteSpace($icmptype)) { $Options.Add('icmp-type', $icmptype) }
	if ($iface -and -not [String]::IsNullOrEmpty($iface) -and -not [String]::IsNullOrWhiteSpace($iface)) { $Options.Add('iface', $iface) }
	if ($log -and -not [String]::IsNullOrEmpty($log) -and -not [String]::IsNullOrWhiteSpace($log)) { $Options.Add('log', $log) }
	if ($macro -and -not [String]::IsNullOrEmpty($macro) -and -not [String]::IsNullOrWhiteSpace($macro)) { $Options.Add('macro', $macro) }
	if ($pos -and -not [String]::IsNullOrEmpty($pos) -and -not [String]::IsNullOrWhiteSpace($pos)) { $Options.Add('pos', $pos) }
	if ($proto -and -not [String]::IsNullOrEmpty($proto) -and -not [String]::IsNullOrWhiteSpace($proto)) { $Options.Add('proto', $proto) }
	if ($source -and -not [String]::IsNullOrEmpty($source) -and -not [String]::IsNullOrWhiteSpace($source)) { $Options.Add('source', $source) }
	if ($sport -and -not [String]::IsNullOrEmpty($sport) -and -not [String]::IsNullOrWhiteSpace($sport)) { $Options.Add('sport', $sport) }
	Invoke-ProxmoxAPI -Method POST -Resource "/cluster/firewall/rules" -Options $Options
}
function Get-ClusterFirewallRulesPos {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		# Update rule at position <pos>.
		[integer]
		$pos
	)
	$Options = @()
	if ($pos -and -not [String]::IsNullOrEmpty($pos) -and -not [String]::IsNullOrWhiteSpace($pos)) { $Options.Add('pos', $pos) }
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/firewall/rules/{pos}" -Options $Options
}
function Set-ClusterFirewallRulesPos {
	[CmdletBinding()]
	param(
		# Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.
		[string]
		$action,
		# Descriptive comment.
		[string]
		$comment,
		# A list of settings you want to delete.
		[string]
		$delete,
		# Restrict packet destination address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
		[string]
		$dest,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# Restrict TCP/UDP destination port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
		[string]
		$dport,
		# Flag to enable/disable a rule.
		[integer]
		$enable,
		# Specify icmp-type. Only valid if proto equals 'icmp'.
		[string]
		$icmptype,
		# Network interface name. You have to use network configuration key names for VMs and containers ('net\d+'). Host related rules can use arbitrary strings.
		[string]
		$iface,
		# Log level for firewall rule.
		[string]
		$log,
		# Use predefined standard macro.
		[string]
		$macro,
		# Move rule to new position <moveto>. Other arguments are ignored.
		[integer]
		$moveto,
		# Update rule at position <pos>.
		[integer]
		$pos,
		# IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.
		[string]
		$proto,
		# Restrict packet source address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
		[string]
		$source,
		# Restrict TCP/UDP source port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
		[string]
		$sport,
		# Rule type.
		[string]
		$type
	)
	$Options = @()
	if ($action -and -not [String]::IsNullOrEmpty($action) -and -not [String]::IsNullOrWhiteSpace($action)) { $Options.Add('action', $action) }
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($delete -and -not [String]::IsNullOrEmpty($delete) -and -not [String]::IsNullOrWhiteSpace($delete)) { $Options.Add('delete', $delete) }
	if ($dest -and -not [String]::IsNullOrEmpty($dest) -and -not [String]::IsNullOrWhiteSpace($dest)) { $Options.Add('dest', $dest) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($dport -and -not [String]::IsNullOrEmpty($dport) -and -not [String]::IsNullOrWhiteSpace($dport)) { $Options.Add('dport', $dport) }
	if ($enable -and -not [String]::IsNullOrEmpty($enable) -and -not [String]::IsNullOrWhiteSpace($enable)) { $Options.Add('enable', $enable) }
	if ($icmptype -and -not [String]::IsNullOrEmpty($icmptype) -and -not [String]::IsNullOrWhiteSpace($icmptype)) { $Options.Add('icmp-type', $icmptype) }
	if ($iface -and -not [String]::IsNullOrEmpty($iface) -and -not [String]::IsNullOrWhiteSpace($iface)) { $Options.Add('iface', $iface) }
	if ($log -and -not [String]::IsNullOrEmpty($log) -and -not [String]::IsNullOrWhiteSpace($log)) { $Options.Add('log', $log) }
	if ($macro -and -not [String]::IsNullOrEmpty($macro) -and -not [String]::IsNullOrWhiteSpace($macro)) { $Options.Add('macro', $macro) }
	if ($moveto -and -not [String]::IsNullOrEmpty($moveto) -and -not [String]::IsNullOrWhiteSpace($moveto)) { $Options.Add('moveto', $moveto) }
	if ($pos -and -not [String]::IsNullOrEmpty($pos) -and -not [String]::IsNullOrWhiteSpace($pos)) { $Options.Add('pos', $pos) }
	if ($proto -and -not [String]::IsNullOrEmpty($proto) -and -not [String]::IsNullOrWhiteSpace($proto)) { $Options.Add('proto', $proto) }
	if ($source -and -not [String]::IsNullOrEmpty($source) -and -not [String]::IsNullOrWhiteSpace($source)) { $Options.Add('source', $source) }
	if ($sport -and -not [String]::IsNullOrEmpty($sport) -and -not [String]::IsNullOrWhiteSpace($sport)) { $Options.Add('sport', $sport) }
	if ($type -and -not [String]::IsNullOrEmpty($type) -and -not [String]::IsNullOrWhiteSpace($type)) { $Options.Add('type', $type) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/cluster/firewall/rules/{pos}" -Options $Options
}
function Remove-ClusterFirewallRulesPos {
	[CmdletBinding()]
	param(
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# Update rule at position <pos>.
		[integer]
		$pos
	)
	$Options = @()
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($pos -and -not [String]::IsNullOrEmpty($pos) -and -not [String]::IsNullOrWhiteSpace($pos)) { $Options.Add('pos', $pos) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/cluster/firewall/rules/{pos}" -Options $Options
}
function Get-ClusterJobs {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/jobs"
}
function Get-ClusterFirewallIpset {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/firewall/ipset"
}
function New-ClusterFirewallIpset {
	[CmdletBinding()]
	param(
		# 
		[string]
		$comment,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name,
		# Rename an existing IPSet. You can set 'rename' to the same value as 'name' to update the 'comment' of an existing IPSet.
		[string]
		$rename
	)
	$Options = @()
	$Options.Add('name', $name)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($rename -and -not [String]::IsNullOrEmpty($rename) -and -not [String]::IsNullOrWhiteSpace($rename)) { $Options.Add('rename', $rename) }
	Invoke-ProxmoxAPI -Method POST -Resource "/cluster/firewall/ipset" -Options $Options
}
function Get-ClusterFirewallIpsetName {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name
	)
	$Options = @()
	$Options.Add('name', $name)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/firewall/ipset/{name}" -Options $Options
}
function New-ClusterFirewallIpsetName {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Network/IP specification in CIDR format.
		[string]
		$cidr,
		# 
		[string]
		$comment,
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name,
		# 
		[switch]
		$nomatch
	)
	$Options = @()
	$Options.Add('cidr', $cidr)
	$Options.Add('name', $name)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($nomatch) { $Options.Add('nomatch', $nomatch) }
	Invoke-ProxmoxAPI -Method POST -Resource "/cluster/firewall/ipset/{name}" -Options $Options
}
function Remove-ClusterFirewallIpsetName {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name
	)
	$Options = @()
	$Options.Add('name', $name)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/cluster/firewall/ipset/{name}" -Options $Options
}
function Get-ClusterFirewallIpsetNameCidr {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# Network/IP specification in CIDR format.
		[string]
		$cidr,
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name
	)
	$Options = @()
	$Options.Add('cidr', $cidr)
	$Options.Add('name', $name)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/firewall/ipset/{name}/{cidr}" -Options $Options
}
function Set-ClusterFirewallIpsetNameCidr {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Network/IP specification in CIDR format.
		[string]
		$cidr,
		# 
		[string]
		$comment,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name,
		# 
		[switch]
		$nomatch
	)
	$Options = @()
	$Options.Add('cidr', $cidr)
	$Options.Add('name', $name)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($nomatch) { $Options.Add('nomatch', $nomatch) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/cluster/firewall/ipset/{name}/{cidr}" -Options $Options
}
function Remove-ClusterFirewallIpsetNameCidr {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Network/IP specification in CIDR format.
		[string]
		$cidr,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name
	)
	$Options = @()
	$Options.Add('cidr', $cidr)
	$Options.Add('name', $name)
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/cluster/firewall/ipset/{name}/{cidr}" -Options $Options
}
function Get-ClusterSdn {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/sdn"
}
function Set-ClusterSdn {
	[CmdletBinding()]
	[OutputType([string])]
	param(
	)
	Invoke-ProxmoxAPI -Method PUT -Resource "/cluster/sdn"
}
function Get-ClusterFirewallAliases {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/firewall/aliases"
}
function New-ClusterFirewallAliases {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Network/IP specification in CIDR format.
		[string]
		$cidr,
		# 
		[string]
		$comment,
		[Parameter(Mandatory)]
		# Alias name.
		[string]
		$name
	)
	$Options = @()
	$Options.Add('cidr', $cidr)
	$Options.Add('name', $name)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	Invoke-ProxmoxAPI -Method POST -Resource "/cluster/firewall/aliases" -Options $Options
}
function Get-ClusterFirewallAliasesName {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# Alias name.
		[string]
		$name
	)
	$Options = @()
	$Options.Add('name', $name)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/firewall/aliases/{name}" -Options $Options
}
function Set-ClusterFirewallAliasesName {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Network/IP specification in CIDR format.
		[string]
		$cidr,
		# 
		[string]
		$comment,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# Alias name.
		[string]
		$name,
		# Rename an existing alias.
		[string]
		$rename
	)
	$Options = @()
	$Options.Add('cidr', $cidr)
	$Options.Add('name', $name)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($rename -and -not [String]::IsNullOrEmpty($rename) -and -not [String]::IsNullOrWhiteSpace($rename)) { $Options.Add('rename', $rename) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/cluster/firewall/aliases/{name}" -Options $Options
}
function Remove-ClusterFirewallAliasesName {
	[CmdletBinding()]
	param(
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# Alias name.
		[string]
		$name
	)
	$Options = @()
	$Options.Add('name', $name)
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/cluster/firewall/aliases/{name}" -Options $Options
}
function Get-ClusterLog {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# Maximum number of entries.
		[integer]
		$max
	)
	$Options = @()
	if ($max -and -not [String]::IsNullOrEmpty($max) -and -not [String]::IsNullOrWhiteSpace($max)) { $Options.Add('max', $max) }
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/log" -Options $Options
}
function Get-ClusterFirewallOptions {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/firewall/options"
}
function Set-ClusterFirewallOptions {
	[CmdletBinding()]
	param(
		# A list of settings you want to delete.
		[string]
		$delete,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# Enable ebtables rules cluster wide.
		[switch]
		$ebtables,
		# Enable or disable the firewall cluster wide.
		[integer]
		$enable,
		# Log ratelimiting settings
		[string]
		$log_ratelimit,
		# Input policy.
		[string]
		$policy_in,
		# Output policy.
		[string]
		$policy_out
	)
	$Options = @()
	if ($delete -and -not [String]::IsNullOrEmpty($delete) -and -not [String]::IsNullOrWhiteSpace($delete)) { $Options.Add('delete', $delete) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($ebtables) { $Options.Add('ebtables', $ebtables) }
	if ($enable -and -not [String]::IsNullOrEmpty($enable) -and -not [String]::IsNullOrWhiteSpace($enable)) { $Options.Add('enable', $enable) }
	if ($log_ratelimit -and -not [String]::IsNullOrEmpty($log_ratelimit) -and -not [String]::IsNullOrWhiteSpace($log_ratelimit)) { $Options.Add('log_ratelimit', $log_ratelimit) }
	if ($policy_in -and -not [String]::IsNullOrEmpty($policy_in) -and -not [String]::IsNullOrWhiteSpace($policy_in)) { $Options.Add('policy_in', $policy_in) }
	if ($policy_out -and -not [String]::IsNullOrEmpty($policy_out) -and -not [String]::IsNullOrWhiteSpace($policy_out)) { $Options.Add('policy_out', $policy_out) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/cluster/firewall/options" -Options $Options
}
function Get-ClusterResources {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# 
		[string]
		$type
	)
	$Options = @()
	if ($type -and -not [String]::IsNullOrEmpty($type) -and -not [String]::IsNullOrWhiteSpace($type)) { $Options.Add('type', $type) }
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/resources" -Options $Options
}
function Get-ClusterFirewallMacros {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/firewall/macros"
}
function Get-ClusterTasks {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/tasks"
}
function Get-ClusterFirewallRefs {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# Only list references of specified type.
		[string]
		$type
	)
	$Options = @()
	if ($type -and -not [String]::IsNullOrEmpty($type) -and -not [String]::IsNullOrWhiteSpace($type)) { $Options.Add('type', $type) }
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/firewall/refs" -Options $Options
}
function Get-ClusterOptions {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/options"
}
function Set-ClusterOptions {
	[CmdletBinding()]
	param(
		# Set bandwidth/io limits various operations.
		[string]
		$bwlimit,
		# Select the default Console viewer. You can either use the builtin java applet (VNC; deprecated and maps to html5), an external virt-viewer comtatible application (SPICE), an HTML5 based vnc viewer (noVNC), or an HTML5 based console client (xtermjs). If the selected viewer is not available (e.g. SPICE not activated for the VM), the fallback is noVNC.
		[string]
		$console,
		# A list of settings you want to delete.
		[string]
		$delete,
		# Datacenter description. Shown in the web-interface datacenter notes panel. This is saved as comment inside the configuration file.
		[string]
		$description,
		# Specify email address to send notification from (default is root@$hostname)
		[string]
		$email_from,
		# Set the fencing mode of the HA cluster. Hardware mode needs a valid configuration of fence devices in /etc/pve/ha/fence.cfg. With both all two modes are used.
		[string]
		$fencing,
		# Cluster wide HA settings.
		[string]
		$ha,
		# Specify external http proxy which is used for downloads (example: 'http://username:password@host:port/')
		[string]
		$http_proxy,
		# Default keybord layout for vnc server.
		[string]
		$keyboard,
		# Default GUI language.
		[string]
		$language,
		# Prefix for autogenerated MAC addresses.
		[string]
		$mac_prefix,
		# Defines how many workers (per node) are maximal started  on actions like 'stopall VMs' or task from the ha-manager.
		[integer]
		$max_workers,
		# For cluster wide migration settings.
		[string]
		$migration,
		# Migration is secure using SSH tunnel by default. For secure private networks you can disable it to speed up migration. Deprecated, use the 'migration' property instead!
		[switch]
		$migration_unsecure,
		# u2f
		[string]
		$u2f,
		# webauthn configuration
		[string]
		$webauthn
	)
	$Options = @()
	if ($bwlimit -and -not [String]::IsNullOrEmpty($bwlimit) -and -not [String]::IsNullOrWhiteSpace($bwlimit)) { $Options.Add('bwlimit', $bwlimit) }
	if ($console -and -not [String]::IsNullOrEmpty($console) -and -not [String]::IsNullOrWhiteSpace($console)) { $Options.Add('console', $console) }
	if ($delete -and -not [String]::IsNullOrEmpty($delete) -and -not [String]::IsNullOrWhiteSpace($delete)) { $Options.Add('delete', $delete) }
	if ($description -and -not [String]::IsNullOrEmpty($description) -and -not [String]::IsNullOrWhiteSpace($description)) { $Options.Add('description', $description) }
	if ($email_from -and -not [String]::IsNullOrEmpty($email_from) -and -not [String]::IsNullOrWhiteSpace($email_from)) { $Options.Add('email_from', $email_from) }
	if ($fencing -and -not [String]::IsNullOrEmpty($fencing) -and -not [String]::IsNullOrWhiteSpace($fencing)) { $Options.Add('fencing', $fencing) }
	if ($ha -and -not [String]::IsNullOrEmpty($ha) -and -not [String]::IsNullOrWhiteSpace($ha)) { $Options.Add('ha', $ha) }
	if ($http_proxy -and -not [String]::IsNullOrEmpty($http_proxy) -and -not [String]::IsNullOrWhiteSpace($http_proxy)) { $Options.Add('http_proxy', $http_proxy) }
	if ($keyboard -and -not [String]::IsNullOrEmpty($keyboard) -and -not [String]::IsNullOrWhiteSpace($keyboard)) { $Options.Add('keyboard', $keyboard) }
	if ($language -and -not [String]::IsNullOrEmpty($language) -and -not [String]::IsNullOrWhiteSpace($language)) { $Options.Add('language', $language) }
	if ($mac_prefix -and -not [String]::IsNullOrEmpty($mac_prefix) -and -not [String]::IsNullOrWhiteSpace($mac_prefix)) { $Options.Add('mac_prefix', $mac_prefix) }
	if ($max_workers -and -not [String]::IsNullOrEmpty($max_workers) -and -not [String]::IsNullOrWhiteSpace($max_workers)) { $Options.Add('max_workers', $max_workers) }
	if ($migration -and -not [String]::IsNullOrEmpty($migration) -and -not [String]::IsNullOrWhiteSpace($migration)) { $Options.Add('migration', $migration) }
	if ($migration_unsecure) { $Options.Add('migration_unsecure', $migration_unsecure) }
	if ($u2f -and -not [String]::IsNullOrEmpty($u2f) -and -not [String]::IsNullOrWhiteSpace($u2f)) { $Options.Add('u2f', $u2f) }
	if ($webauthn -and -not [String]::IsNullOrEmpty($webauthn) -and -not [String]::IsNullOrWhiteSpace($webauthn)) { $Options.Add('webauthn', $webauthn) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/cluster/options" -Options $Options
}
function Get-ClusterBackupId {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The job ID.
		[string]
		$id
	)
	$Options = @()
	$Options.Add('id', $id)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/backup/{id}" -Options $Options
}
function Set-ClusterBackupId {
	[CmdletBinding()]
	param(
		# Backup all known guest systems on this host.
		[switch]
		$all,
		# Limit I/O bandwidth (KBytes per second).
		[integer]
		$bwlimit,
		# Description for the Job.
		[string]
		$comment,
		# Compress dump file.
		[string]
		$compress,
		# A list of settings you want to delete.
		[string]
		$delete,
		# Day of week selection.
		[string]
		$dow,
		# Store resulting files to specified directory.
		[string]
		$dumpdir,
		# Enable or disable the job.
		[switch]
		$enabled,
		# Exclude specified guest systems (assumes --all)
		[string]
		$exclude,
		# Exclude certain files/directories (shell globs). Paths starting with '/' are anchored to the container's root,  other paths match relative to each subdirectory.
		[string]
		$excludepath,
		[Parameter(Mandatory)]
		# The job ID.
		[string]
		$id,
		# Set CFQ ionice priority.
		[integer]
		$ionice,
		# Maximal time to wait for the global lock (minutes).
		[integer]
		$lockwait,
		# Specify when to send an email
		[string]
		$mailnotification,
		# Comma-separated list of email addresses or users that should receive email notifications.
		[string]
		$mailto,
		# Deprecated: use 'prune-backups' instead. Maximal number of backup files per guest system.
		[integer]
		$maxfiles,
		# Backup mode.
		[string]
		$mode,
		# Only run if executed on this node.
		[string]
		$node,
		# Use pigz instead of gzip when N>0. N=1 uses half of cores, N>1 uses N as thread count.
		[integer]
		$pigz,
		# Backup all known guest systems included in the specified pool.
		[string]
		$pool,
		# Use these retention options instead of those from the storage configuration.
		[string]
		$prunebackups,
		# Be quiet.
		[switch]
		$quiet,
		# Prune older backups according to 'prune-backups'.
		[switch]
		$remove,
		# Backup schedule. The format is a subset of `systemd` calendar events.
		[string]
		$schedule,
		# Use specified hook script.
		[string]
		$script,
		# Job Start time.
		[string]
		$starttime,
		# Exclude temporary files and logs.
		[switch]
		$stdexcludes,
		# Stop running backup jobs on this host.
		[switch]
		$stop,
		# Maximal time to wait until a guest system is stopped (minutes).
		[integer]
		$stopwait,
		# Store resulting file to this storage.
		[string]
		$storage,
		# Store temporary files to specified directory.
		[string]
		$tmpdir,
		# The ID of the guest system you want to backup.
		[string]
		$vmid,
		# Zstd threads. N=0 uses half of the available cores, N>0 uses N as thread count.
		[integer]
		$zstd
	)
	$Options = @()
	$Options.Add('id', $id)
	if ($all) { $Options.Add('all', $all) }
	if ($bwlimit -and -not [String]::IsNullOrEmpty($bwlimit) -and -not [String]::IsNullOrWhiteSpace($bwlimit)) { $Options.Add('bwlimit', $bwlimit) }
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($compress -and -not [String]::IsNullOrEmpty($compress) -and -not [String]::IsNullOrWhiteSpace($compress)) { $Options.Add('compress', $compress) }
	if ($delete -and -not [String]::IsNullOrEmpty($delete) -and -not [String]::IsNullOrWhiteSpace($delete)) { $Options.Add('delete', $delete) }
	if ($dow -and -not [String]::IsNullOrEmpty($dow) -and -not [String]::IsNullOrWhiteSpace($dow)) { $Options.Add('dow', $dow) }
	if ($dumpdir -and -not [String]::IsNullOrEmpty($dumpdir) -and -not [String]::IsNullOrWhiteSpace($dumpdir)) { $Options.Add('dumpdir', $dumpdir) }
	if ($enabled) { $Options.Add('enabled', $enabled) }
	if ($exclude -and -not [String]::IsNullOrEmpty($exclude) -and -not [String]::IsNullOrWhiteSpace($exclude)) { $Options.Add('exclude', $exclude) }
	if ($excludepath -and -not [String]::IsNullOrEmpty($excludepath) -and -not [String]::IsNullOrWhiteSpace($excludepath)) { $Options.Add('exclude-path', $excludepath) }
	if ($ionice -and -not [String]::IsNullOrEmpty($ionice) -and -not [String]::IsNullOrWhiteSpace($ionice)) { $Options.Add('ionice', $ionice) }
	if ($lockwait -and -not [String]::IsNullOrEmpty($lockwait) -and -not [String]::IsNullOrWhiteSpace($lockwait)) { $Options.Add('lockwait', $lockwait) }
	if ($mailnotification -and -not [String]::IsNullOrEmpty($mailnotification) -and -not [String]::IsNullOrWhiteSpace($mailnotification)) { $Options.Add('mailnotification', $mailnotification) }
	if ($mailto -and -not [String]::IsNullOrEmpty($mailto) -and -not [String]::IsNullOrWhiteSpace($mailto)) { $Options.Add('mailto', $mailto) }
	if ($maxfiles -and -not [String]::IsNullOrEmpty($maxfiles) -and -not [String]::IsNullOrWhiteSpace($maxfiles)) { $Options.Add('maxfiles', $maxfiles) }
	if ($mode -and -not [String]::IsNullOrEmpty($mode) -and -not [String]::IsNullOrWhiteSpace($mode)) { $Options.Add('mode', $mode) }
	if ($node -and -not [String]::IsNullOrEmpty($node) -and -not [String]::IsNullOrWhiteSpace($node)) { $Options.Add('node', $node) }
	if ($pigz -and -not [String]::IsNullOrEmpty($pigz) -and -not [String]::IsNullOrWhiteSpace($pigz)) { $Options.Add('pigz', $pigz) }
	if ($pool -and -not [String]::IsNullOrEmpty($pool) -and -not [String]::IsNullOrWhiteSpace($pool)) { $Options.Add('pool', $pool) }
	if ($prunebackups -and -not [String]::IsNullOrEmpty($prunebackups) -and -not [String]::IsNullOrWhiteSpace($prunebackups)) { $Options.Add('prune-backups', $prunebackups) }
	if ($quiet) { $Options.Add('quiet', $quiet) }
	if ($remove) { $Options.Add('remove', $remove) }
	if ($schedule -and -not [String]::IsNullOrEmpty($schedule) -and -not [String]::IsNullOrWhiteSpace($schedule)) { $Options.Add('schedule', $schedule) }
	if ($script -and -not [String]::IsNullOrEmpty($script) -and -not [String]::IsNullOrWhiteSpace($script)) { $Options.Add('script', $script) }
	if ($starttime -and -not [String]::IsNullOrEmpty($starttime) -and -not [String]::IsNullOrWhiteSpace($starttime)) { $Options.Add('starttime', $starttime) }
	if ($stdexcludes) { $Options.Add('stdexcludes', $stdexcludes) }
	if ($stop) { $Options.Add('stop', $stop) }
	if ($stopwait -and -not [String]::IsNullOrEmpty($stopwait) -and -not [String]::IsNullOrWhiteSpace($stopwait)) { $Options.Add('stopwait', $stopwait) }
	if ($storage -and -not [String]::IsNullOrEmpty($storage) -and -not [String]::IsNullOrWhiteSpace($storage)) { $Options.Add('storage', $storage) }
	if ($tmpdir -and -not [String]::IsNullOrEmpty($tmpdir) -and -not [String]::IsNullOrWhiteSpace($tmpdir)) { $Options.Add('tmpdir', $tmpdir) }
	if ($vmid -and -not [String]::IsNullOrEmpty($vmid) -and -not [String]::IsNullOrWhiteSpace($vmid)) { $Options.Add('vmid', $vmid) }
	if ($zstd -and -not [String]::IsNullOrEmpty($zstd) -and -not [String]::IsNullOrWhiteSpace($zstd)) { $Options.Add('zstd', $zstd) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/cluster/backup/{id}" -Options $Options
}
function Remove-ClusterBackupId {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# The job ID.
		[string]
		$id
	)
	$Options = @()
	$Options.Add('id', $id)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/cluster/backup/{id}" -Options $Options
}
function Get-ClusterBackupIncludedVolumes {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The job ID.
		[string]
		$id
	)
	$Options = @()
	$Options.Add('id', $id)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/backup/{id}/included_volumes" -Options $Options
}
function Get-ClusterStatus {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/status"
}
function Get-ClusterBackupInfoNotBackedUp {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/backup-info/not-backed-up"
}
function Get-ClusterNextid {
	[CmdletBinding()]
	[OutputType([Int32])]
	param(
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	if ($vmid -and -not [String]::IsNullOrEmpty($vmid) -and -not [String]::IsNullOrWhiteSpace($vmid)) { $Options.Add('vmid', $vmid) }
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/nextid" -Options $Options
}
function Get-ClusterHaResources {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# Only list resources of specific type
		[string]
		$type
	)
	$Options = @()
	if ($type -and -not [String]::IsNullOrEmpty($type) -and -not [String]::IsNullOrWhiteSpace($type)) { $Options.Add('type', $type) }
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/ha/resources" -Options $Options
}
function New-ClusterHaResources {
	[CmdletBinding()]
	param(
		# Description.
		[string]
		$comment,
		# The HA group identifier.
		[string]
		$group,
		# Maximal number of service relocate tries when a service failes to start.
		[integer]
		$max_relocate,
		# Maximal number of tries to restart the service on a node after its start failed.
		[integer]
		$max_restart,
		[Parameter(Mandatory)]
		# HA resource ID. This consists of a resource type followed by a resource specific name, separated with colon (example: vm:100 / ct:100). For virtual machines and containers, you can simply use the VM or CT id as a shortcut (example: 100).
		[string]
		$sid,
		# Requested resource state.
		[string]
		$state,
		# Resource type.
		[string]
		$type
	)
	$Options = @()
	$Options.Add('sid', $sid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($group -and -not [String]::IsNullOrEmpty($group) -and -not [String]::IsNullOrWhiteSpace($group)) { $Options.Add('group', $group) }
	if ($max_relocate -and -not [String]::IsNullOrEmpty($max_relocate) -and -not [String]::IsNullOrWhiteSpace($max_relocate)) { $Options.Add('max_relocate', $max_relocate) }
	if ($max_restart -and -not [String]::IsNullOrEmpty($max_restart) -and -not [String]::IsNullOrWhiteSpace($max_restart)) { $Options.Add('max_restart', $max_restart) }
	if ($state -and -not [String]::IsNullOrEmpty($state) -and -not [String]::IsNullOrWhiteSpace($state)) { $Options.Add('state', $state) }
	if ($type -and -not [String]::IsNullOrEmpty($type) -and -not [String]::IsNullOrWhiteSpace($type)) { $Options.Add('type', $type) }
	Invoke-ProxmoxAPI -Method POST -Resource "/cluster/ha/resources" -Options $Options
}
function Get-ClusterHaResourcesSid {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# HA resource ID. This consists of a resource type followed by a resource specific name, separated with colon (example: vm:100 / ct:100). For virtual machines and containers, you can simply use the VM or CT id as a shortcut (example: 100).
		[string]
		$sid
	)
	$Options = @()
	$Options.Add('sid', $sid)
	Invoke-ProxmoxAPI -Method GET -Resource "/cluster/ha/resources/{sid}" -Options $Options
}
function Set-ClusterHaResourcesSid {
	[CmdletBinding()]
	param(
		# Description.
		[string]
		$comment,
		# A list of settings you want to delete.
		[string]
		$delete,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# The HA group identifier.
		[string]
		$group,
		# Maximal number of service relocate tries when a service failes to start.
		[integer]
		$max_relocate,
		# Maximal number of tries to restart the service on a node after its start failed.
		[integer]
		$max_restart,
		[Parameter(Mandatory)]
		# HA resource ID. This consists of a resource type followed by a resource specific name, separated with colon (example: vm:100 / ct:100). For virtual machines and containers, you can simply use the VM or CT id as a shortcut (example: 100).
		[string]
		$sid,
		# Requested resource state.
		[string]
		$state
	)
	$Options = @()
	$Options.Add('sid', $sid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($delete -and -not [String]::IsNullOrEmpty($delete) -and -not [String]::IsNullOrWhiteSpace($delete)) { $Options.Add('delete', $delete) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($group -and -not [String]::IsNullOrEmpty($group) -and -not [String]::IsNullOrWhiteSpace($group)) { $Options.Add('group', $group) }
	if ($max_relocate -and -not [String]::IsNullOrEmpty($max_relocate) -and -not [String]::IsNullOrWhiteSpace($max_relocate)) { $Options.Add('max_relocate', $max_relocate) }
	if ($max_restart -and -not [String]::IsNullOrEmpty($max_restart) -and -not [String]::IsNullOrWhiteSpace($max_restart)) { $Options.Add('max_restart', $max_restart) }
	if ($state -and -not [String]::IsNullOrEmpty($state) -and -not [String]::IsNullOrWhiteSpace($state)) { $Options.Add('state', $state) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/cluster/ha/resources/{sid}" -Options $Options
}
function Remove-ClusterHaResourcesSid {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# HA resource ID. This consists of a resource type followed by a resource specific name, separated with colon (example: vm:100 / ct:100). For virtual machines and containers, you can simply use the VM or CT id as a shortcut (example: 100).
		[string]
		$sid
	)
	$Options = @()
	$Options.Add('sid', $sid)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/cluster/ha/resources/{sid}" -Options $Options
}
function New-ClusterHaResourcesMigrate {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Target node.
		[string]
		$node,
		[Parameter(Mandatory)]
		# HA resource ID. This consists of a resource type followed by a resource specific name, separated with colon (example: vm:100 / ct:100). For virtual machines and containers, you can simply use the VM or CT id as a shortcut (example: 100).
		[string]
		$sid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('sid', $sid)
	Invoke-ProxmoxAPI -Method POST -Resource "/cluster/ha/resources/{sid}/migrate" -Options $Options
}
function New-ClusterHaResourcesRelocate {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Target node.
		[string]
		$node,
		[Parameter(Mandatory)]
		# HA resource ID. This consists of a resource type followed by a resource specific name, separated with colon (example: vm:100 / ct:100). For virtual machines and containers, you can simply use the VM or CT id as a shortcut (example: 100).
		[string]
		$sid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('sid', $sid)
	Invoke-ProxmoxAPI -Method POST -Resource "/cluster/ha/resources/{sid}/relocate" -Options $Options
}
function Get-Nodes {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes"
}
function Get-Node {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}" -Options $Options
}
function Get-NodeQemu {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# Determine the full status of active VMs.
		[switch]
		$full,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($full) { $Options.Add('full', $full) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu" -Options $Options
}
function New-NodeQemu {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Enable/disable ACPI.
		[switch]
		$acpi,
		# Enable/disable communication with the Qemu Guest Agent and its properties.
		[string]
		$agent,
		# Virtual processor architecture. Defaults to the host.
		[string]
		$arch,
		# The backup archive. Either the file system path to a .tar or .vma file (use '-' to pipe data from stdin) or a proxmox storage backup volume identifier.
		[string]
		$archive,
		# Arbitrary arguments passed to kvm.
		[string]
		$AudioArgs,
		# Configure a audio device, useful in combination with QXL/Spice.
		[string]
		$audio0,
		# Automatic restart after crash (currently ignored).
		[switch]
		$autostart,
		# Amount of target RAM for the VM in MB. Using zero disables the ballon driver.
		[integer]
		$balloon,
		# Select BIOS implementation.
		[string]
		$bios,
		# Specify guest boot order. Use the 'order=' sub-property as usage with no key or 'legacy=' is deprecated.
		[string]
		$boot,
		# Enable booting from specified disk. Deprecated: Use 'boot: order=foo;bar' instead.
		[string]
		$bootdisk,
		# Override I/O bandwidth limit (in KiB/s).
		[integer]
		$bwlimit,
		# This is an alias for option -ide2
		[string]
		$cdrom,
		# cloud-init: Specify custom files to replace the automatically generated ones at start.
		[string]
		$cicustom,
		# cloud-init: Password to assign the user. Using this is generally not recommended. Use ssh keys instead. Also note that older cloud-init versions do not support hashed passwords.
		[securestring]
		$cipassword,
		# Specifies the cloud-init configuration format. The default depends on the configured operating system type (`ostype`. We use the `nocloud` format for Linux, and `configdrive2` for windows.
		[string]
		$citype,
		# cloud-init: User name to change ssh keys and password for instead of the image's configured default user.
		[string]
		$ciuser,
		# The number of cores per socket.
		[integer]
		$cores,
		# Emulated CPU type.
		[string]
		$cpu,
		# Limit of CPU usage.
		[number]
		$cpulimit,
		# CPU weight for a VM, will be clamped to [1, 10000] in cgroup v2.
		[integer]
		$cpuunits,
		# Description for the VM. Shown in the web-interface VM's summary. This is saved as comment inside the configuration file.
		[string]
		$description,
		# Configure a Disk for storing EFI vars. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume. Note that SIZE_IN_GiB is ignored here and that the default EFI vars are copied to the volume instead.
		[string]
		$efidisk0,
		# Freeze CPU at startup (use 'c' monitor command to start execution).
		[switch]
		$freeze,
		# Script that will be executed during various steps in the vms lifetime.
		[string]
		$hookscript,
		# Map host PCI devices into guest.
		[string]
		$hostpci0,
		# Map host PCI devices into guest.
		[string]
		$hostpci1,
		# Map host PCI devices into guest.
		[string]
		$hostpci2,
		# Map host PCI devices into guest.
		[string]
		$hostpci3,
		# Map host PCI devices into guest.
		[string]
		$hostpci4,
		# Map host PCI devices into guest.
		[string]
		$hostpci5,
		# Map host PCI devices into guest.
		[string]
		$hostpci6,
		# Map host PCI devices into guest.
		[string]
		$hostpci7,
		# Map host PCI devices into guest.
		[string]
		$hostpci8,
		# Map host PCI devices into guest.
		[string]
		$hostpci9,
		# Map host PCI devices into guest.
		[string]
		$hostpci10,
		# Selectively enable hotplug features. This is a comma separated list of hotplug features: 'network', 'disk', 'cpu', 'memory' and 'usb'. Use '0' to disable hotplug completely. Using '1' as value is an alias for the default `network,disk,usb`.
		[string]
		$hotplug,
		# Enable/disable hugepages memory.
		[string]
		$hugepages,
		# Use volume as IDE hard disk or CD-ROM (n is 0 to 3). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$ide0,
		# Use volume as IDE hard disk or CD-ROM (n is 0 to 3). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$ide1,
		# Use volume as IDE hard disk or CD-ROM (n is 0 to 3). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$ide2,
		# Use volume as IDE hard disk or CD-ROM (n is 0 to 3). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$ide3,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig0,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig1,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig2,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig3,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig4,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig5,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig6,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig7,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig8,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig9,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig10,
		# Inter-VM shared memory. Useful for direct communication between VMs, or to the host.
		[string]
		$ivshmem,
		# Use together with hugepages. If enabled, hugepages will not not be deleted after VM shutdown and can be used for subsequent starts.
		[switch]
		$keephugepages,
		# Keyboard layout for VNC server. The default is read from the'/etc/pve/datacenter.cfg' configuration file. It should not be necessary to set it.
		[string]
		$keyboard,
		# Enable/disable KVM hardware virtualization.
		[switch]
		$kvm,
		# Start the VM immediately from the backup and restore in background. PBS only.
		[switch]
		$liverestore,
		# Set the real time clock (RTC) to local time. This is enabled by default if the `ostype` indicates a Microsoft Windows OS.
		[switch]
		$localtime,
		# Lock/unlock the VM.
		[string]
		$lock,
		# Specifies the Qemu machine type.
		[string]
		$machine,
		# Amount of RAM for the VM in MB. This is the maximum available memory when you use the balloon device.
		[integer]
		$memory,
		# Set maximum tolerated downtime (in seconds) for migrations.
		[number]
		$migrate_downtime,
		# Set maximum speed (in MB/s) for migrations. Value 0 is no limit.
		[integer]
		$migrate_speed,
		# Set a name for the VM. Only used on the configuration web interface.
		[string]
		$name,
		# cloud-init: Sets DNS server IP address for a container. Create will'
		[string]
		$nameserver,
		# Specify network devices.
		[string]
		$net0,
		# Specify network devices.
		[string]
		$net1,
		# Specify network devices.
		[string]
		$net2,
		# Specify network devices.
		[string]
		$net3,
		# Specify network devices.
		[string]
		$net4,
		# Specify network devices.
		[string]
		$net5,
		# Specify network devices.
		[string]
		$net6,
		# Specify network devices.
		[string]
		$net7,
		# Specify network devices.
		[string]
		$net8,
		# Specify network devices.
		[string]
		$net9,
		# Specify network devices.
		[string]
		$net10,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Enable/disable NUMA.
		[switch]
		$numa,
		# NUMA topology.
		[string]
		$numa0,
		# NUMA topology.
		[string]
		$numa1,
		# NUMA topology.
		[string]
		$numa2,
		# NUMA topology.
		[string]
		$numa3,
		# NUMA topology.
		[string]
		$numa4,
		# NUMA topology.
		[string]
		$numa5,
		# NUMA topology.
		[string]
		$numa6,
		# NUMA topology.
		[string]
		$numa7,
		# NUMA topology.
		[string]
		$numa8,
		# NUMA topology.
		[string]
		$numa9,
		# NUMA topology.
		[string]
		$numa10,
		# Specifies whether a VM will be started during system bootup.
		[switch]
		$onboot,
		# Specify guest operating system.
		[string]
		$ostype,
		# Map host parallel devices (n is 0 to 2).
		[string]
		$parallel0,
		# Map host parallel devices (n is 0 to 2).
		[string]
		$parallel1,
		# Map host parallel devices (n is 0 to 2).
		[string]
		$parallel2,
		# Add the VM to the specified pool.
		[string]
		$pool,
		# Sets the protection flag of the VM. This will disable the remove VM and remove disk operations.
		[switch]
		$protection,
		# Allow reboot. If set to '0' the VM exit on reboot.
		[switch]
		$reboot,
		# Configure a VirtIO-based Random Number Generator.
		[string]
		$rng0,
		# Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$sata0,
		# Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$sata1,
		# Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$sata2,
		# Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$sata3,
		# Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$sata4,
		# Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$sata5,
		# SCSI controller model
		[string]
		$scsihw,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi0,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi1,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi2,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi3,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi4,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi5,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi6,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi7,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi8,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi9,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi10,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi11,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi12,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi13,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi14,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi15,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi16,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi17,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi18,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi19,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi20,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi21,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi22,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi23,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi24,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi25,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi26,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi27,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi28,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi29,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi30,
		# cloud-init: Sets DNS search domains for a container. Create will'
		[string]
		$searchdomain,
		# Create a serial device inside the VM (n is 0 to 3)
		[string]
		$serial0,
		# Create a serial device inside the VM (n is 0 to 3)
		[string]
		$serial1,
		# Create a serial device inside the VM (n is 0 to 3)
		[string]
		$serial2,
		# Create a serial device inside the VM (n is 0 to 3)
		[string]
		$serial3,
		# Amount of memory shares for auto-ballooning. The larger the number is, the more memory this VM gets. Number is relative to weights of all other running VMs. Using zero disables auto-ballooning. Auto-ballooning is done by pvestatd.
		[integer]
		$shares,
		# Specify SMBIOS type 1 fields.
		[string]
		$smbios1,
		# The number of CPUs. Please use option -sockets instead.
		[integer]
		$smp,
		# The number of CPU sockets.
		[integer]
		$sockets,
		# Configure additional enhancements for SPICE.
		[string]
		$spice_enhancements,
		# cloud-init: Setup public SSH keys (one key per line, OpenSSH format).
		[string]
		$sshkeys,
		# Start VM after it was created successfully.
		[switch]
		$start,
		# Set the initial date of the real time clock. Valid format for date are:'now' or '2006-06-17T16:01:21' or '2006-06-17'.
		[string]
		$startdate,
		# Startup and shutdown behavior. Order is a non-negative number defining the general startup order. Shutdown in done with reverse ordering. Additionally you can set the 'up' or 'down' delay in seconds, which specifies a delay to wait before the next VM is started or stopped.
		[string]
		$startup,
		# Default storage.
		[string]
		$storage,
		# Enable/disable the USB tablet device.
		[switch]
		$tablet,
		# Tags of the VM. This is only meta information.
		[string]
		$tags,
		# Enable/disable time drift fix.
		[switch]
		$tdf,
		# Enable/disable Template.
		[switch]
		$template,
		# Configure a Disk for storing TPM state. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume. Note that SIZE_IN_GiB is ignored here and that the default size of 4 MiB will always be used instead. The format is also fixed to 'raw'.
		[string]
		$tpmstate0,
		# Assign a unique random ethernet address.
		[switch]
		$unique,
		# Configure an USB device (n is 0 to 4).
		[string]
		$usb0,
		# Configure an USB device (n is 0 to 4).
		[string]
		$usb1,
		# Configure an USB device (n is 0 to 4).
		[string]
		$usb2,
		# Configure an USB device (n is 0 to 4).
		[string]
		$usb3,
		# Configure an USB device (n is 0 to 4).
		[string]
		$usb4,
		# Number of hotplugged vcpus.
		[integer]
		$vcpus,
		# Configure the VGA hardware.
		[string]
		$vga,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio0,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio1,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio2,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio3,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio4,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio5,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio6,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio7,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio8,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio9,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio10,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio11,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio12,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio13,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio14,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio15,
		# Set VM Generation ID. Use '1' to autogenerate on create or update, pass '0' to disable explicitly.
		[string]
		$vmgenid,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid,
		# Default storage for VM state volumes/files.
		[string]
		$vmstatestorage,
		# Create a virtual hardware watchdog device.
		[string]
		$watchdog
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($acpi) { $Options.Add('acpi', $acpi) }
	if ($agent -and -not [String]::IsNullOrEmpty($agent) -and -not [String]::IsNullOrWhiteSpace($agent)) { $Options.Add('agent', $agent) }
	if ($arch -and -not [String]::IsNullOrEmpty($arch) -and -not [String]::IsNullOrWhiteSpace($arch)) { $Options.Add('arch', $arch) }
	if ($archive -and -not [String]::IsNullOrEmpty($archive) -and -not [String]::IsNullOrWhiteSpace($archive)) { $Options.Add('archive', $archive) }
	if ($AudioArgs -and -not [String]::IsNullOrEmpty($AudioArgs) -and -not [String]::IsNullOrWhiteSpace($AudioArgs)) { $Options.Add('args', $AudioArgs) }
	if ($audio0 -and -not [String]::IsNullOrEmpty($audio0) -and -not [String]::IsNullOrWhiteSpace($audio0)) { $Options.Add('audio0', $audio0) }
	if ($autostart) { $Options.Add('autostart', $autostart) }
	if ($balloon -and -not [String]::IsNullOrEmpty($balloon) -and -not [String]::IsNullOrWhiteSpace($balloon)) { $Options.Add('balloon', $balloon) }
	if ($bios -and -not [String]::IsNullOrEmpty($bios) -and -not [String]::IsNullOrWhiteSpace($bios)) { $Options.Add('bios', $bios) }
	if ($boot -and -not [String]::IsNullOrEmpty($boot) -and -not [String]::IsNullOrWhiteSpace($boot)) { $Options.Add('boot', $boot) }
	if ($bootdisk -and -not [String]::IsNullOrEmpty($bootdisk) -and -not [String]::IsNullOrWhiteSpace($bootdisk)) { $Options.Add('bootdisk', $bootdisk) }
	if ($bwlimit -and -not [String]::IsNullOrEmpty($bwlimit) -and -not [String]::IsNullOrWhiteSpace($bwlimit)) { $Options.Add('bwlimit', $bwlimit) }
	if ($cdrom -and -not [String]::IsNullOrEmpty($cdrom) -and -not [String]::IsNullOrWhiteSpace($cdrom)) { $Options.Add('cdrom', $cdrom) }
	if ($cicustom -and -not [String]::IsNullOrEmpty($cicustom) -and -not [String]::IsNullOrWhiteSpace($cicustom)) { $Options.Add('cicustom', $cicustom) }
	if ($cipassword) { $Options.Add('cipassword', $($cipassword | ConvertFrom-SecureString -AsPlainText)) }
	if ($citype -and -not [String]::IsNullOrEmpty($citype) -and -not [String]::IsNullOrWhiteSpace($citype)) { $Options.Add('citype', $citype) }
	if ($ciuser -and -not [String]::IsNullOrEmpty($ciuser) -and -not [String]::IsNullOrWhiteSpace($ciuser)) { $Options.Add('ciuser', $ciuser) }
	if ($cores -and -not [String]::IsNullOrEmpty($cores) -and -not [String]::IsNullOrWhiteSpace($cores)) { $Options.Add('cores', $cores) }
	if ($cpu -and -not [String]::IsNullOrEmpty($cpu) -and -not [String]::IsNullOrWhiteSpace($cpu)) { $Options.Add('cpu', $cpu) }
	if ($cpulimit -and -not [String]::IsNullOrEmpty($cpulimit) -and -not [String]::IsNullOrWhiteSpace($cpulimit)) { $Options.Add('cpulimit', $cpulimit) }
	if ($cpuunits -and -not [String]::IsNullOrEmpty($cpuunits) -and -not [String]::IsNullOrWhiteSpace($cpuunits)) { $Options.Add('cpuunits', $cpuunits) }
	if ($description -and -not [String]::IsNullOrEmpty($description) -and -not [String]::IsNullOrWhiteSpace($description)) { $Options.Add('description', $description) }
	if ($efidisk0 -and -not [String]::IsNullOrEmpty($efidisk0) -and -not [String]::IsNullOrWhiteSpace($efidisk0)) { $Options.Add('efidisk0', $efidisk0) }
	if ($force) { $Options.Add('force', $force) }
	if ($freeze) { $Options.Add('freeze', $freeze) }
	if ($hookscript -and -not [String]::IsNullOrEmpty($hookscript) -and -not [String]::IsNullOrWhiteSpace($hookscript)) { $Options.Add('hookscript', $hookscript) }
	if ($hostpci0 -and -not [String]::IsNullOrEmpty($hostpci0) -and -not [String]::IsNullOrWhiteSpace($hostpci0)) { $Options.Add('hostpci0', $hostpci0) }
	if ($hostpci1 -and -not [String]::IsNullOrEmpty($hostpci1) -and -not [String]::IsNullOrWhiteSpace($hostpci1)) { $Options.Add('hostpci1', $hostpci1) }
	if ($hostpci2 -and -not [String]::IsNullOrEmpty($hostpci2) -and -not [String]::IsNullOrWhiteSpace($hostpci2)) { $Options.Add('hostpci2', $hostpci2) }
	if ($hostpci3 -and -not [String]::IsNullOrEmpty($hostpci3) -and -not [String]::IsNullOrWhiteSpace($hostpci3)) { $Options.Add('hostpci3', $hostpci3) }
	if ($hostpci4 -and -not [String]::IsNullOrEmpty($hostpci4) -and -not [String]::IsNullOrWhiteSpace($hostpci4)) { $Options.Add('hostpci4', $hostpci4) }
	if ($hostpci5 -and -not [String]::IsNullOrEmpty($hostpci5) -and -not [String]::IsNullOrWhiteSpace($hostpci5)) { $Options.Add('hostpci5', $hostpci5) }
	if ($hostpci6 -and -not [String]::IsNullOrEmpty($hostpci6) -and -not [String]::IsNullOrWhiteSpace($hostpci6)) { $Options.Add('hostpci6', $hostpci6) }
	if ($hostpci7 -and -not [String]::IsNullOrEmpty($hostpci7) -and -not [String]::IsNullOrWhiteSpace($hostpci7)) { $Options.Add('hostpci7', $hostpci7) }
	if ($hostpci8 -and -not [String]::IsNullOrEmpty($hostpci8) -and -not [String]::IsNullOrWhiteSpace($hostpci8)) { $Options.Add('hostpci8', $hostpci8) }
	if ($hostpci9 -and -not [String]::IsNullOrEmpty($hostpci9) -and -not [String]::IsNullOrWhiteSpace($hostpci9)) { $Options.Add('hostpci9', $hostpci9) }
	if ($hostpci10 -and -not [String]::IsNullOrEmpty($hostpci10) -and -not [String]::IsNullOrWhiteSpace($hostpci10)) { $Options.Add('hostpci10', $hostpci10) }
	if ($hotplug -and -not [String]::IsNullOrEmpty($hotplug) -and -not [String]::IsNullOrWhiteSpace($hotplug)) { $Options.Add('hotplug', $hotplug) }
	if ($hugepages -and -not [String]::IsNullOrEmpty($hugepages) -and -not [String]::IsNullOrWhiteSpace($hugepages)) { $Options.Add('hugepages', $hugepages) }
	if ($ide0 -and -not [String]::IsNullOrEmpty($ide0) -and -not [String]::IsNullOrWhiteSpace($ide0)) { $Options.Add('ide0', $ide0) }
	if ($ide1 -and -not [String]::IsNullOrEmpty($ide1) -and -not [String]::IsNullOrWhiteSpace($ide1)) { $Options.Add('ide1', $ide1) }
	if ($ide2 -and -not [String]::IsNullOrEmpty($ide2) -and -not [String]::IsNullOrWhiteSpace($ide2)) { $Options.Add('ide2', $ide2) }
	if ($ide3 -and -not [String]::IsNullOrEmpty($ide3) -and -not [String]::IsNullOrWhiteSpace($ide3)) { $Options.Add('ide3', $ide3) }
	if ($ipconfig0 -and -not [String]::IsNullOrEmpty($ipconfig0) -and -not [String]::IsNullOrWhiteSpace($ipconfig0)) { $Options.Add('ipconfig0', $ipconfig0) }
	if ($ipconfig1 -and -not [String]::IsNullOrEmpty($ipconfig1) -and -not [String]::IsNullOrWhiteSpace($ipconfig1)) { $Options.Add('ipconfig1', $ipconfig1) }
	if ($ipconfig2 -and -not [String]::IsNullOrEmpty($ipconfig2) -and -not [String]::IsNullOrWhiteSpace($ipconfig2)) { $Options.Add('ipconfig2', $ipconfig2) }
	if ($ipconfig3 -and -not [String]::IsNullOrEmpty($ipconfig3) -and -not [String]::IsNullOrWhiteSpace($ipconfig3)) { $Options.Add('ipconfig3', $ipconfig3) }
	if ($ipconfig4 -and -not [String]::IsNullOrEmpty($ipconfig4) -and -not [String]::IsNullOrWhiteSpace($ipconfig4)) { $Options.Add('ipconfig4', $ipconfig4) }
	if ($ipconfig5 -and -not [String]::IsNullOrEmpty($ipconfig5) -and -not [String]::IsNullOrWhiteSpace($ipconfig5)) { $Options.Add('ipconfig5', $ipconfig5) }
	if ($ipconfig6 -and -not [String]::IsNullOrEmpty($ipconfig6) -and -not [String]::IsNullOrWhiteSpace($ipconfig6)) { $Options.Add('ipconfig6', $ipconfig6) }
	if ($ipconfig7 -and -not [String]::IsNullOrEmpty($ipconfig7) -and -not [String]::IsNullOrWhiteSpace($ipconfig7)) { $Options.Add('ipconfig7', $ipconfig7) }
	if ($ipconfig8 -and -not [String]::IsNullOrEmpty($ipconfig8) -and -not [String]::IsNullOrWhiteSpace($ipconfig8)) { $Options.Add('ipconfig8', $ipconfig8) }
	if ($ipconfig9 -and -not [String]::IsNullOrEmpty($ipconfig9) -and -not [String]::IsNullOrWhiteSpace($ipconfig9)) { $Options.Add('ipconfig9', $ipconfig9) }
	if ($ipconfig10 -and -not [String]::IsNullOrEmpty($ipconfig10) -and -not [String]::IsNullOrWhiteSpace($ipconfig10)) { $Options.Add('ipconfig10', $ipconfig10) }
	if ($ivshmem -and -not [String]::IsNullOrEmpty($ivshmem) -and -not [String]::IsNullOrWhiteSpace($ivshmem)) { $Options.Add('ivshmem', $ivshmem) }
	if ($keephugepages) { $Options.Add('keephugepages', $keephugepages) }
	if ($keyboard -and -not [String]::IsNullOrEmpty($keyboard) -and -not [String]::IsNullOrWhiteSpace($keyboard)) { $Options.Add('keyboard', $keyboard) }
	if ($kvm) { $Options.Add('kvm', $kvm) }
	if ($liverestore) { $Options.Add('live-restore', $liverestore) }
	if ($localtime) { $Options.Add('localtime', $localtime) }
	if ($lock -and -not [String]::IsNullOrEmpty($lock) -and -not [String]::IsNullOrWhiteSpace($lock)) { $Options.Add('lock', $lock) }
	if ($machine -and -not [String]::IsNullOrEmpty($machine) -and -not [String]::IsNullOrWhiteSpace($machine)) { $Options.Add('machine', $machine) }
	if ($memory -and -not [String]::IsNullOrEmpty($memory) -and -not [String]::IsNullOrWhiteSpace($memory)) { $Options.Add('memory', $memory) }
	if ($migrate_downtime -and -not [String]::IsNullOrEmpty($migrate_downtime) -and -not [String]::IsNullOrWhiteSpace($migrate_downtime)) { $Options.Add('migrate_downtime', $migrate_downtime) }
	if ($migrate_speed -and -not [String]::IsNullOrEmpty($migrate_speed) -and -not [String]::IsNullOrWhiteSpace($migrate_speed)) { $Options.Add('migrate_speed', $migrate_speed) }
	if ($name -and -not [String]::IsNullOrEmpty($name) -and -not [String]::IsNullOrWhiteSpace($name)) { $Options.Add('name', $name) }
	if ($nameserver -and -not [String]::IsNullOrEmpty($nameserver) -and -not [String]::IsNullOrWhiteSpace($nameserver)) { $Options.Add('nameserver', $nameserver) }
	if ($net0 -and -not [String]::IsNullOrEmpty($net0) -and -not [String]::IsNullOrWhiteSpace($net0)) { $Options.Add('net0', $net0) }
	if ($net1 -and -not [String]::IsNullOrEmpty($net1) -and -not [String]::IsNullOrWhiteSpace($net1)) { $Options.Add('net1', $net1) }
	if ($net2 -and -not [String]::IsNullOrEmpty($net2) -and -not [String]::IsNullOrWhiteSpace($net2)) { $Options.Add('net2', $net2) }
	if ($net3 -and -not [String]::IsNullOrEmpty($net3) -and -not [String]::IsNullOrWhiteSpace($net3)) { $Options.Add('net3', $net3) }
	if ($net4 -and -not [String]::IsNullOrEmpty($net4) -and -not [String]::IsNullOrWhiteSpace($net4)) { $Options.Add('net4', $net4) }
	if ($net5 -and -not [String]::IsNullOrEmpty($net5) -and -not [String]::IsNullOrWhiteSpace($net5)) { $Options.Add('net5', $net5) }
	if ($net6 -and -not [String]::IsNullOrEmpty($net6) -and -not [String]::IsNullOrWhiteSpace($net6)) { $Options.Add('net6', $net6) }
	if ($net7 -and -not [String]::IsNullOrEmpty($net7) -and -not [String]::IsNullOrWhiteSpace($net7)) { $Options.Add('net7', $net7) }
	if ($net8 -and -not [String]::IsNullOrEmpty($net8) -and -not [String]::IsNullOrWhiteSpace($net8)) { $Options.Add('net8', $net8) }
	if ($net9 -and -not [String]::IsNullOrEmpty($net9) -and -not [String]::IsNullOrWhiteSpace($net9)) { $Options.Add('net9', $net9) }
	if ($net10 -and -not [String]::IsNullOrEmpty($net10) -and -not [String]::IsNullOrWhiteSpace($net10)) { $Options.Add('net10', $net10) }
	if ($numa) { $Options.Add('numa', $numa) }
	if ($numa0 -and -not [String]::IsNullOrEmpty($numa0) -and -not [String]::IsNullOrWhiteSpace($numa0)) { $Options.Add('numa0', $numa0) }
	if ($numa1 -and -not [String]::IsNullOrEmpty($numa1) -and -not [String]::IsNullOrWhiteSpace($numa1)) { $Options.Add('numa1', $numa1) }
	if ($numa2 -and -not [String]::IsNullOrEmpty($numa2) -and -not [String]::IsNullOrWhiteSpace($numa2)) { $Options.Add('numa2', $numa2) }
	if ($numa3 -and -not [String]::IsNullOrEmpty($numa3) -and -not [String]::IsNullOrWhiteSpace($numa3)) { $Options.Add('numa3', $numa3) }
	if ($numa4 -and -not [String]::IsNullOrEmpty($numa4) -and -not [String]::IsNullOrWhiteSpace($numa4)) { $Options.Add('numa4', $numa4) }
	if ($numa5 -and -not [String]::IsNullOrEmpty($numa5) -and -not [String]::IsNullOrWhiteSpace($numa5)) { $Options.Add('numa5', $numa5) }
	if ($numa6 -and -not [String]::IsNullOrEmpty($numa6) -and -not [String]::IsNullOrWhiteSpace($numa6)) { $Options.Add('numa6', $numa6) }
	if ($numa7 -and -not [String]::IsNullOrEmpty($numa7) -and -not [String]::IsNullOrWhiteSpace($numa7)) { $Options.Add('numa7', $numa7) }
	if ($numa8 -and -not [String]::IsNullOrEmpty($numa8) -and -not [String]::IsNullOrWhiteSpace($numa8)) { $Options.Add('numa8', $numa8) }
	if ($numa9 -and -not [String]::IsNullOrEmpty($numa9) -and -not [String]::IsNullOrWhiteSpace($numa9)) { $Options.Add('numa9', $numa9) }
	if ($numa10 -and -not [String]::IsNullOrEmpty($numa10) -and -not [String]::IsNullOrWhiteSpace($numa10)) { $Options.Add('numa10', $numa10) }
	if ($onboot) { $Options.Add('onboot', $onboot) }
	if ($ostype -and -not [String]::IsNullOrEmpty($ostype) -and -not [String]::IsNullOrWhiteSpace($ostype)) { $Options.Add('ostype', $ostype) }
	if ($parallel0 -and -not [String]::IsNullOrEmpty($parallel0) -and -not [String]::IsNullOrWhiteSpace($parallel0)) { $Options.Add('parallel0', $parallel0) }
	if ($parallel1 -and -not [String]::IsNullOrEmpty($parallel1) -and -not [String]::IsNullOrWhiteSpace($parallel1)) { $Options.Add('parallel1', $parallel1) }
	if ($parallel2 -and -not [String]::IsNullOrEmpty($parallel2) -and -not [String]::IsNullOrWhiteSpace($parallel2)) { $Options.Add('parallel2', $parallel2) }
	if ($pool -and -not [String]::IsNullOrEmpty($pool) -and -not [String]::IsNullOrWhiteSpace($pool)) { $Options.Add('pool', $pool) }
	if ($protection) { $Options.Add('protection', $protection) }
	if ($reboot) { $Options.Add('reboot', $reboot) }
	if ($rng0 -and -not [String]::IsNullOrEmpty($rng0) -and -not [String]::IsNullOrWhiteSpace($rng0)) { $Options.Add('rng0', $rng0) }
	if ($sata0 -and -not [String]::IsNullOrEmpty($sata0) -and -not [String]::IsNullOrWhiteSpace($sata0)) { $Options.Add('sata0', $sata0) }
	if ($sata1 -and -not [String]::IsNullOrEmpty($sata1) -and -not [String]::IsNullOrWhiteSpace($sata1)) { $Options.Add('sata1', $sata1) }
	if ($sata2 -and -not [String]::IsNullOrEmpty($sata2) -and -not [String]::IsNullOrWhiteSpace($sata2)) { $Options.Add('sata2', $sata2) }
	if ($sata3 -and -not [String]::IsNullOrEmpty($sata3) -and -not [String]::IsNullOrWhiteSpace($sata3)) { $Options.Add('sata3', $sata3) }
	if ($sata4 -and -not [String]::IsNullOrEmpty($sata4) -and -not [String]::IsNullOrWhiteSpace($sata4)) { $Options.Add('sata4', $sata4) }
	if ($sata5 -and -not [String]::IsNullOrEmpty($sata5) -and -not [String]::IsNullOrWhiteSpace($sata5)) { $Options.Add('sata5', $sata5) }
	if ($scsihw -and -not [String]::IsNullOrEmpty($scsihw) -and -not [String]::IsNullOrWhiteSpace($scsihw)) { $Options.Add('scsihw', $scsihw) }
	if ($scsi0 -and -not [String]::IsNullOrEmpty($scsi0) -and -not [String]::IsNullOrWhiteSpace($scsi0)) { $Options.Add('scsi0', $scsi0) }
	if ($scsi1 -and -not [String]::IsNullOrEmpty($scsi1) -and -not [String]::IsNullOrWhiteSpace($scsi1)) { $Options.Add('scsi1', $scsi1) }
	if ($scsi2 -and -not [String]::IsNullOrEmpty($scsi2) -and -not [String]::IsNullOrWhiteSpace($scsi2)) { $Options.Add('scsi2', $scsi2) }
	if ($scsi3 -and -not [String]::IsNullOrEmpty($scsi3) -and -not [String]::IsNullOrWhiteSpace($scsi3)) { $Options.Add('scsi3', $scsi3) }
	if ($scsi4 -and -not [String]::IsNullOrEmpty($scsi4) -and -not [String]::IsNullOrWhiteSpace($scsi4)) { $Options.Add('scsi4', $scsi4) }
	if ($scsi5 -and -not [String]::IsNullOrEmpty($scsi5) -and -not [String]::IsNullOrWhiteSpace($scsi5)) { $Options.Add('scsi5', $scsi5) }
	if ($scsi6 -and -not [String]::IsNullOrEmpty($scsi6) -and -not [String]::IsNullOrWhiteSpace($scsi6)) { $Options.Add('scsi6', $scsi6) }
	if ($scsi7 -and -not [String]::IsNullOrEmpty($scsi7) -and -not [String]::IsNullOrWhiteSpace($scsi7)) { $Options.Add('scsi7', $scsi7) }
	if ($scsi8 -and -not [String]::IsNullOrEmpty($scsi8) -and -not [String]::IsNullOrWhiteSpace($scsi8)) { $Options.Add('scsi8', $scsi8) }
	if ($scsi9 -and -not [String]::IsNullOrEmpty($scsi9) -and -not [String]::IsNullOrWhiteSpace($scsi9)) { $Options.Add('scsi9', $scsi9) }
	if ($scsi10 -and -not [String]::IsNullOrEmpty($scsi10) -and -not [String]::IsNullOrWhiteSpace($scsi10)) { $Options.Add('scsi10', $scsi10) }
	if ($scsi11 -and -not [String]::IsNullOrEmpty($scsi11) -and -not [String]::IsNullOrWhiteSpace($scsi11)) { $Options.Add('scsi11', $scsi11) }
	if ($scsi12 -and -not [String]::IsNullOrEmpty($scsi12) -and -not [String]::IsNullOrWhiteSpace($scsi12)) { $Options.Add('scsi12', $scsi12) }
	if ($scsi13 -and -not [String]::IsNullOrEmpty($scsi13) -and -not [String]::IsNullOrWhiteSpace($scsi13)) { $Options.Add('scsi13', $scsi13) }
	if ($scsi14 -and -not [String]::IsNullOrEmpty($scsi14) -and -not [String]::IsNullOrWhiteSpace($scsi14)) { $Options.Add('scsi14', $scsi14) }
	if ($scsi15 -and -not [String]::IsNullOrEmpty($scsi15) -and -not [String]::IsNullOrWhiteSpace($scsi15)) { $Options.Add('scsi15', $scsi15) }
	if ($scsi16 -and -not [String]::IsNullOrEmpty($scsi16) -and -not [String]::IsNullOrWhiteSpace($scsi16)) { $Options.Add('scsi16', $scsi16) }
	if ($scsi17 -and -not [String]::IsNullOrEmpty($scsi17) -and -not [String]::IsNullOrWhiteSpace($scsi17)) { $Options.Add('scsi17', $scsi17) }
	if ($scsi18 -and -not [String]::IsNullOrEmpty($scsi18) -and -not [String]::IsNullOrWhiteSpace($scsi18)) { $Options.Add('scsi18', $scsi18) }
	if ($scsi19 -and -not [String]::IsNullOrEmpty($scsi19) -and -not [String]::IsNullOrWhiteSpace($scsi19)) { $Options.Add('scsi19', $scsi19) }
	if ($scsi20 -and -not [String]::IsNullOrEmpty($scsi20) -and -not [String]::IsNullOrWhiteSpace($scsi20)) { $Options.Add('scsi20', $scsi20) }
	if ($scsi21 -and -not [String]::IsNullOrEmpty($scsi21) -and -not [String]::IsNullOrWhiteSpace($scsi21)) { $Options.Add('scsi21', $scsi21) }
	if ($scsi22 -and -not [String]::IsNullOrEmpty($scsi22) -and -not [String]::IsNullOrWhiteSpace($scsi22)) { $Options.Add('scsi22', $scsi22) }
	if ($scsi23 -and -not [String]::IsNullOrEmpty($scsi23) -and -not [String]::IsNullOrWhiteSpace($scsi23)) { $Options.Add('scsi23', $scsi23) }
	if ($scsi24 -and -not [String]::IsNullOrEmpty($scsi24) -and -not [String]::IsNullOrWhiteSpace($scsi24)) { $Options.Add('scsi24', $scsi24) }
	if ($scsi25 -and -not [String]::IsNullOrEmpty($scsi25) -and -not [String]::IsNullOrWhiteSpace($scsi25)) { $Options.Add('scsi25', $scsi25) }
	if ($scsi26 -and -not [String]::IsNullOrEmpty($scsi26) -and -not [String]::IsNullOrWhiteSpace($scsi26)) { $Options.Add('scsi26', $scsi26) }
	if ($scsi27 -and -not [String]::IsNullOrEmpty($scsi27) -and -not [String]::IsNullOrWhiteSpace($scsi27)) { $Options.Add('scsi27', $scsi27) }
	if ($scsi28 -and -not [String]::IsNullOrEmpty($scsi28) -and -not [String]::IsNullOrWhiteSpace($scsi28)) { $Options.Add('scsi28', $scsi28) }
	if ($scsi29 -and -not [String]::IsNullOrEmpty($scsi29) -and -not [String]::IsNullOrWhiteSpace($scsi29)) { $Options.Add('scsi29', $scsi29) }
	if ($scsi30 -and -not [String]::IsNullOrEmpty($scsi30) -and -not [String]::IsNullOrWhiteSpace($scsi30)) { $Options.Add('scsi30', $scsi30) }
	if ($searchdomain -and -not [String]::IsNullOrEmpty($searchdomain) -and -not [String]::IsNullOrWhiteSpace($searchdomain)) { $Options.Add('searchdomain', $searchdomain) }
	if ($serial0 -and -not [String]::IsNullOrEmpty($serial0) -and -not [String]::IsNullOrWhiteSpace($serial0)) { $Options.Add('serial0', $serial0) }
	if ($serial1 -and -not [String]::IsNullOrEmpty($serial1) -and -not [String]::IsNullOrWhiteSpace($serial1)) { $Options.Add('serial1', $serial1) }
	if ($serial2 -and -not [String]::IsNullOrEmpty($serial2) -and -not [String]::IsNullOrWhiteSpace($serial2)) { $Options.Add('serial2', $serial2) }
	if ($serial3 -and -not [String]::IsNullOrEmpty($serial3) -and -not [String]::IsNullOrWhiteSpace($serial3)) { $Options.Add('serial3', $serial3) }
	if ($shares -and -not [String]::IsNullOrEmpty($shares) -and -not [String]::IsNullOrWhiteSpace($shares)) { $Options.Add('shares', $shares) }
	if ($smbios1 -and -not [String]::IsNullOrEmpty($smbios1) -and -not [String]::IsNullOrWhiteSpace($smbios1)) { $Options.Add('smbios1', $smbios1) }
	if ($smp -and -not [String]::IsNullOrEmpty($smp) -and -not [String]::IsNullOrWhiteSpace($smp)) { $Options.Add('smp', $smp) }
	if ($sockets -and -not [String]::IsNullOrEmpty($sockets) -and -not [String]::IsNullOrWhiteSpace($sockets)) { $Options.Add('sockets', $sockets) }
	if ($spice_enhancements -and -not [String]::IsNullOrEmpty($spice_enhancements) -and -not [String]::IsNullOrWhiteSpace($spice_enhancements)) { $Options.Add('spice_enhancements', $spice_enhancements) }
	if ($sshkeys -and -not [String]::IsNullOrEmpty($sshkeys) -and -not [String]::IsNullOrWhiteSpace($sshkeys)) { $Options.Add('sshkeys', $sshkeys) }
	if ($start) { $Options.Add('start', $start) }
	if ($startdate -and -not [String]::IsNullOrEmpty($startdate) -and -not [String]::IsNullOrWhiteSpace($startdate)) { $Options.Add('startdate', $startdate) }
	if ($startup -and -not [String]::IsNullOrEmpty($startup) -and -not [String]::IsNullOrWhiteSpace($startup)) { $Options.Add('startup', $startup) }
	if ($storage -and -not [String]::IsNullOrEmpty($storage) -and -not [String]::IsNullOrWhiteSpace($storage)) { $Options.Add('storage', $storage) }
	if ($tablet) { $Options.Add('tablet', $tablet) }
	if ($tags -and -not [String]::IsNullOrEmpty($tags) -and -not [String]::IsNullOrWhiteSpace($tags)) { $Options.Add('tags', $tags) }
	if ($tdf) { $Options.Add('tdf', $tdf) }
	if ($template) { $Options.Add('template', $template) }
	if ($tpmstate0 -and -not [String]::IsNullOrEmpty($tpmstate0) -and -not [String]::IsNullOrWhiteSpace($tpmstate0)) { $Options.Add('tpmstate0', $tpmstate0) }
	if ($unique) { $Options.Add('unique', $unique) }
	if ($usb0 -and -not [String]::IsNullOrEmpty($usb0) -and -not [String]::IsNullOrWhiteSpace($usb0)) { $Options.Add('usb0', $usb0) }
	if ($usb1 -and -not [String]::IsNullOrEmpty($usb1) -and -not [String]::IsNullOrWhiteSpace($usb1)) { $Options.Add('usb1', $usb1) }
	if ($usb2 -and -not [String]::IsNullOrEmpty($usb2) -and -not [String]::IsNullOrWhiteSpace($usb2)) { $Options.Add('usb2', $usb2) }
	if ($usb3 -and -not [String]::IsNullOrEmpty($usb3) -and -not [String]::IsNullOrWhiteSpace($usb3)) { $Options.Add('usb3', $usb3) }
	if ($usb4 -and -not [String]::IsNullOrEmpty($usb4) -and -not [String]::IsNullOrWhiteSpace($usb4)) { $Options.Add('usb4', $usb4) }
	if ($vcpus -and -not [String]::IsNullOrEmpty($vcpus) -and -not [String]::IsNullOrWhiteSpace($vcpus)) { $Options.Add('vcpus', $vcpus) }
	if ($vga -and -not [String]::IsNullOrEmpty($vga) -and -not [String]::IsNullOrWhiteSpace($vga)) { $Options.Add('vga', $vga) }
	if ($virtio0 -and -not [String]::IsNullOrEmpty($virtio0) -and -not [String]::IsNullOrWhiteSpace($virtio0)) { $Options.Add('virtio0', $virtio0) }
	if ($virtio1 -and -not [String]::IsNullOrEmpty($virtio1) -and -not [String]::IsNullOrWhiteSpace($virtio1)) { $Options.Add('virtio1', $virtio1) }
	if ($virtio2 -and -not [String]::IsNullOrEmpty($virtio2) -and -not [String]::IsNullOrWhiteSpace($virtio2)) { $Options.Add('virtio2', $virtio2) }
	if ($virtio3 -and -not [String]::IsNullOrEmpty($virtio3) -and -not [String]::IsNullOrWhiteSpace($virtio3)) { $Options.Add('virtio3', $virtio3) }
	if ($virtio4 -and -not [String]::IsNullOrEmpty($virtio4) -and -not [String]::IsNullOrWhiteSpace($virtio4)) { $Options.Add('virtio4', $virtio4) }
	if ($virtio5 -and -not [String]::IsNullOrEmpty($virtio5) -and -not [String]::IsNullOrWhiteSpace($virtio5)) { $Options.Add('virtio5', $virtio5) }
	if ($virtio6 -and -not [String]::IsNullOrEmpty($virtio6) -and -not [String]::IsNullOrWhiteSpace($virtio6)) { $Options.Add('virtio6', $virtio6) }
	if ($virtio7 -and -not [String]::IsNullOrEmpty($virtio7) -and -not [String]::IsNullOrWhiteSpace($virtio7)) { $Options.Add('virtio7', $virtio7) }
	if ($virtio8 -and -not [String]::IsNullOrEmpty($virtio8) -and -not [String]::IsNullOrWhiteSpace($virtio8)) { $Options.Add('virtio8', $virtio8) }
	if ($virtio9 -and -not [String]::IsNullOrEmpty($virtio9) -and -not [String]::IsNullOrWhiteSpace($virtio9)) { $Options.Add('virtio9', $virtio9) }
	if ($virtio10 -and -not [String]::IsNullOrEmpty($virtio10) -and -not [String]::IsNullOrWhiteSpace($virtio10)) { $Options.Add('virtio10', $virtio10) }
	if ($virtio11 -and -not [String]::IsNullOrEmpty($virtio11) -and -not [String]::IsNullOrWhiteSpace($virtio11)) { $Options.Add('virtio11', $virtio11) }
	if ($virtio12 -and -not [String]::IsNullOrEmpty($virtio12) -and -not [String]::IsNullOrWhiteSpace($virtio12)) { $Options.Add('virtio12', $virtio12) }
	if ($virtio13 -and -not [String]::IsNullOrEmpty($virtio13) -and -not [String]::IsNullOrWhiteSpace($virtio13)) { $Options.Add('virtio13', $virtio13) }
	if ($virtio14 -and -not [String]::IsNullOrEmpty($virtio14) -and -not [String]::IsNullOrWhiteSpace($virtio14)) { $Options.Add('virtio14', $virtio14) }
	if ($virtio15 -and -not [String]::IsNullOrEmpty($virtio15) -and -not [String]::IsNullOrWhiteSpace($virtio15)) { $Options.Add('virtio15', $virtio15) }
	if ($vmgenid -and -not [String]::IsNullOrEmpty($vmgenid) -and -not [String]::IsNullOrWhiteSpace($vmgenid)) { $Options.Add('vmgenid', $vmgenid) }
	if ($vmstatestorage -and -not [String]::IsNullOrEmpty($vmstatestorage) -and -not [String]::IsNullOrWhiteSpace($vmstatestorage)) { $Options.Add('vmstatestorage', $vmstatestorage) }
	if ($watchdog -and -not [String]::IsNullOrEmpty($watchdog) -and -not [String]::IsNullOrWhiteSpace($watchdog)) { $Options.Add('watchdog', $watchdog) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu" -Options $Options
}
function Get-NodeQemuVmid {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}" -Options $Options
}
function Remove-NodeQemuVmid {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# If set, destroy additionally all disks not referenced in the config but with a matching VMID from all enabled storages.
		[switch]
		$destroyunreferenceddisks,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Remove VMID from configurations, like backup & replication jobs and HA.
		[switch]
		$purge,
		# Ignore locks - only root is allowed to use this option.
		[switch]
		$skiplock,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($destroyunreferenceddisks) { $Options.Add('destroy-unreferenced-disks', $destroyunreferenceddisks) }
	if ($purge) { $Options.Add('purge', $purge) }
	if ($skiplock) { $Options.Add('skiplock', $skiplock) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/qemu/{vmid}" -Options $Options
}
function Get-NodeQemuFirewall {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/firewall" -Options $Options
}
function Get-NodeQemuFirewallRules {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/firewall/rules" -Options $Options
}
function New-NodeQemuFirewallRules {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.
		[string]
		$action,
		# Descriptive comment.
		[string]
		$comment,
		# Restrict packet destination address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
		[string]
		$dest,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# Restrict TCP/UDP destination port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
		[string]
		$dport,
		# Flag to enable/disable a rule.
		[integer]
		$enable,
		# Specify icmp-type. Only valid if proto equals 'icmp'.
		[string]
		$icmptype,
		# Network interface name. You have to use network configuration key names for VMs and containers ('net\d+'). Host related rules can use arbitrary strings.
		[string]
		$iface,
		# Log level for firewall rule.
		[string]
		$log,
		# Use predefined standard macro.
		[string]
		$macro,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Update rule at position <pos>.
		[integer]
		$pos,
		# IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.
		[string]
		$proto,
		# Restrict packet source address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
		[string]
		$source,
		# Restrict TCP/UDP source port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
		[string]
		$sport,
		[Parameter(Mandatory)]
		# Rule type.
		[string]
		$type,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('action', $action)
	$Options.Add('node', $node)
	$Options.Add('type', $type)
	$Options.Add('vmid', $vmid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($dest -and -not [String]::IsNullOrEmpty($dest) -and -not [String]::IsNullOrWhiteSpace($dest)) { $Options.Add('dest', $dest) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($dport -and -not [String]::IsNullOrEmpty($dport) -and -not [String]::IsNullOrWhiteSpace($dport)) { $Options.Add('dport', $dport) }
	if ($enable -and -not [String]::IsNullOrEmpty($enable) -and -not [String]::IsNullOrWhiteSpace($enable)) { $Options.Add('enable', $enable) }
	if ($icmptype -and -not [String]::IsNullOrEmpty($icmptype) -and -not [String]::IsNullOrWhiteSpace($icmptype)) { $Options.Add('icmp-type', $icmptype) }
	if ($iface -and -not [String]::IsNullOrEmpty($iface) -and -not [String]::IsNullOrWhiteSpace($iface)) { $Options.Add('iface', $iface) }
	if ($log -and -not [String]::IsNullOrEmpty($log) -and -not [String]::IsNullOrWhiteSpace($log)) { $Options.Add('log', $log) }
	if ($macro -and -not [String]::IsNullOrEmpty($macro) -and -not [String]::IsNullOrWhiteSpace($macro)) { $Options.Add('macro', $macro) }
	if ($pos -and -not [String]::IsNullOrEmpty($pos) -and -not [String]::IsNullOrWhiteSpace($pos)) { $Options.Add('pos', $pos) }
	if ($proto -and -not [String]::IsNullOrEmpty($proto) -and -not [String]::IsNullOrWhiteSpace($proto)) { $Options.Add('proto', $proto) }
	if ($source -and -not [String]::IsNullOrEmpty($source) -and -not [String]::IsNullOrWhiteSpace($source)) { $Options.Add('source', $source) }
	if ($sport -and -not [String]::IsNullOrEmpty($sport) -and -not [String]::IsNullOrWhiteSpace($sport)) { $Options.Add('sport', $sport) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/firewall/rules" -Options $Options
}
function Get-NodeQemuFirewallRulesPos {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Update rule at position <pos>.
		[integer]
		$pos,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($pos -and -not [String]::IsNullOrEmpty($pos) -and -not [String]::IsNullOrWhiteSpace($pos)) { $Options.Add('pos', $pos) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/firewall/rules/{pos}" -Options $Options
}
function Set-NodeQemuFirewallRulesPos {
	[CmdletBinding()]
	param(
		# Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.
		[string]
		$action,
		# Descriptive comment.
		[string]
		$comment,
		# A list of settings you want to delete.
		[string]
		$delete,
		# Restrict packet destination address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
		[string]
		$dest,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# Restrict TCP/UDP destination port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
		[string]
		$dport,
		# Flag to enable/disable a rule.
		[integer]
		$enable,
		# Specify icmp-type. Only valid if proto equals 'icmp'.
		[string]
		$icmptype,
		# Network interface name. You have to use network configuration key names for VMs and containers ('net\d+'). Host related rules can use arbitrary strings.
		[string]
		$iface,
		# Log level for firewall rule.
		[string]
		$log,
		# Use predefined standard macro.
		[string]
		$macro,
		# Move rule to new position <moveto>. Other arguments are ignored.
		[integer]
		$moveto,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Update rule at position <pos>.
		[integer]
		$pos,
		# IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.
		[string]
		$proto,
		# Restrict packet source address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
		[string]
		$source,
		# Restrict TCP/UDP source port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
		[string]
		$sport,
		# Rule type.
		[string]
		$type,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($action -and -not [String]::IsNullOrEmpty($action) -and -not [String]::IsNullOrWhiteSpace($action)) { $Options.Add('action', $action) }
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($delete -and -not [String]::IsNullOrEmpty($delete) -and -not [String]::IsNullOrWhiteSpace($delete)) { $Options.Add('delete', $delete) }
	if ($dest -and -not [String]::IsNullOrEmpty($dest) -and -not [String]::IsNullOrWhiteSpace($dest)) { $Options.Add('dest', $dest) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($dport -and -not [String]::IsNullOrEmpty($dport) -and -not [String]::IsNullOrWhiteSpace($dport)) { $Options.Add('dport', $dport) }
	if ($enable -and -not [String]::IsNullOrEmpty($enable) -and -not [String]::IsNullOrWhiteSpace($enable)) { $Options.Add('enable', $enable) }
	if ($icmptype -and -not [String]::IsNullOrEmpty($icmptype) -and -not [String]::IsNullOrWhiteSpace($icmptype)) { $Options.Add('icmp-type', $icmptype) }
	if ($iface -and -not [String]::IsNullOrEmpty($iface) -and -not [String]::IsNullOrWhiteSpace($iface)) { $Options.Add('iface', $iface) }
	if ($log -and -not [String]::IsNullOrEmpty($log) -and -not [String]::IsNullOrWhiteSpace($log)) { $Options.Add('log', $log) }
	if ($macro -and -not [String]::IsNullOrEmpty($macro) -and -not [String]::IsNullOrWhiteSpace($macro)) { $Options.Add('macro', $macro) }
	if ($moveto -and -not [String]::IsNullOrEmpty($moveto) -and -not [String]::IsNullOrWhiteSpace($moveto)) { $Options.Add('moveto', $moveto) }
	if ($pos -and -not [String]::IsNullOrEmpty($pos) -and -not [String]::IsNullOrWhiteSpace($pos)) { $Options.Add('pos', $pos) }
	if ($proto -and -not [String]::IsNullOrEmpty($proto) -and -not [String]::IsNullOrWhiteSpace($proto)) { $Options.Add('proto', $proto) }
	if ($source -and -not [String]::IsNullOrEmpty($source) -and -not [String]::IsNullOrWhiteSpace($source)) { $Options.Add('source', $source) }
	if ($sport -and -not [String]::IsNullOrEmpty($sport) -and -not [String]::IsNullOrWhiteSpace($sport)) { $Options.Add('sport', $sport) }
	if ($type -and -not [String]::IsNullOrEmpty($type) -and -not [String]::IsNullOrWhiteSpace($type)) { $Options.Add('type', $type) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/qemu/{vmid}/firewall/rules/{pos}" -Options $Options
}
function Remove-NodeQemuFirewallRulesPos {
	[CmdletBinding()]
	param(
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Update rule at position <pos>.
		[integer]
		$pos,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($pos -and -not [String]::IsNullOrEmpty($pos) -and -not [String]::IsNullOrWhiteSpace($pos)) { $Options.Add('pos', $pos) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/qemu/{vmid}/firewall/rules/{pos}" -Options $Options
}
function Get-NodeQemuAgent {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/agent" -Options $Options
}
function New-NodeQemuAgent {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The QGA command.
		[string]
		$command,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('command', $command)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/agent" -Options $Options
}
function Get-NodeQemuFirewallAliases {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/firewall/aliases" -Options $Options
}
function New-NodeQemuFirewallAliases {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Network/IP specification in CIDR format.
		[string]
		$cidr,
		# 
		[string]
		$comment,
		[Parameter(Mandatory)]
		# Alias name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('cidr', $cidr)
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/firewall/aliases" -Options $Options
}
function Get-NodeQemuFirewallAliasesName {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# Alias name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/firewall/aliases/{name}" -Options $Options
}
function Set-NodeQemuFirewallAliasesName {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Network/IP specification in CIDR format.
		[string]
		$cidr,
		# 
		[string]
		$comment,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# Alias name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Rename an existing alias.
		[string]
		$rename,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('cidr', $cidr)
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($rename -and -not [String]::IsNullOrEmpty($rename) -and -not [String]::IsNullOrWhiteSpace($rename)) { $Options.Add('rename', $rename) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/qemu/{vmid}/firewall/aliases/{name}" -Options $Options
}
function Remove-NodeQemuFirewallAliasesName {
	[CmdletBinding()]
	param(
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# Alias name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/qemu/{vmid}/firewall/aliases/{name}" -Options $Options
}
function Get-NodeQemuRrd {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		# The RRD consolidation function
		[string]
		$cf,
		[Parameter(Mandatory)]
		# The list of datasources you want to display.
		[string]
		$ds,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Specify the time frame you are interested in.
		[string]
		$timeframe,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('ds', $ds)
	$Options.Add('node', $node)
	$Options.Add('timeframe', $timeframe)
	$Options.Add('vmid', $vmid)
	if ($cf -and -not [String]::IsNullOrEmpty($cf) -and -not [String]::IsNullOrWhiteSpace($cf)) { $Options.Add('cf', $cf) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/rrd" -Options $Options
}
function Get-NodeQemuFirewallIpset {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/firewall/ipset" -Options $Options
}
function New-NodeQemuFirewallIpset {
	[CmdletBinding()]
	param(
		# 
		[string]
		$comment,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Rename an existing IPSet. You can set 'rename' to the same value as 'name' to update the 'comment' of an existing IPSet.
		[string]
		$rename,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($rename -and -not [String]::IsNullOrEmpty($rename) -and -not [String]::IsNullOrWhiteSpace($rename)) { $Options.Add('rename', $rename) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/firewall/ipset" -Options $Options
}
function Get-NodeQemuFirewallIpsetName {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}" -Options $Options
}
function New-NodeQemuFirewallIpsetName {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Network/IP specification in CIDR format.
		[string]
		$cidr,
		# 
		[string]
		$comment,
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# 
		[switch]
		$nomatch,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('cidr', $cidr)
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($nomatch) { $Options.Add('nomatch', $nomatch) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}" -Options $Options
}
function Remove-NodeQemuFirewallIpsetName {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}" -Options $Options
}
function Get-NodeQemuFirewallIpsetNameCidr {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# Network/IP specification in CIDR format.
		[string]
		$cidr,
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('cidr', $cidr)
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}/{cidr}" -Options $Options
}
function Set-NodeQemuFirewallIpsetNameCidr {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Network/IP specification in CIDR format.
		[string]
		$cidr,
		# 
		[string]
		$comment,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# 
		[switch]
		$nomatch,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('cidr', $cidr)
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($nomatch) { $Options.Add('nomatch', $nomatch) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}/{cidr}" -Options $Options
}
function Remove-NodeQemuFirewallIpsetNameCidr {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Network/IP specification in CIDR format.
		[string]
		$cidr,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('cidr', $cidr)
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}/{cidr}" -Options $Options
}
function Get-NodeQemuRrddata {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# The RRD consolidation function
		[string]
		$cf,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Specify the time frame you are interested in.
		[string]
		$timeframe,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('timeframe', $timeframe)
	$Options.Add('vmid', $vmid)
	if ($cf -and -not [String]::IsNullOrEmpty($cf) -and -not [String]::IsNullOrWhiteSpace($cf)) { $Options.Add('cf', $cf) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/rrddata" -Options $Options
}
function Get-NodeQemuFirewallOptions {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/firewall/options" -Options $Options
}
function Set-NodeQemuFirewallOptions {
	[CmdletBinding()]
	param(
		# A list of settings you want to delete.
		[string]
		$delete,
		# Enable DHCP.
		[switch]
		$dhcp,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# Enable/disable firewall rules.
		[switch]
		$enable,
		# Enable default IP filters. This is equivalent to adding an empty ipfilter-net<id> ipset for every interface. Such ipsets implicitly contain sane default restrictions such as restricting IPv6 link local addresses to the one derived from the interface's MAC address. For containers the configured IP addresses will be implicitly added.
		[switch]
		$ipfilter,
		# Log level for incoming traffic.
		[string]
		$log_level_in,
		# Log level for outgoing traffic.
		[string]
		$log_level_out,
		# Enable/disable MAC address filter.
		[switch]
		$macfilter,
		# Enable NDP (Neighbor Discovery Protocol).
		[switch]
		$ndp,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Input policy.
		[string]
		$policy_in,
		# Output policy.
		[string]
		$policy_out,
		# Allow sending Router Advertisement.
		[switch]
		$radv,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($delete -and -not [String]::IsNullOrEmpty($delete) -and -not [String]::IsNullOrWhiteSpace($delete)) { $Options.Add('delete', $delete) }
	if ($dhcp) { $Options.Add('dhcp', $dhcp) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($enable) { $Options.Add('enable', $enable) }
	if ($ipfilter) { $Options.Add('ipfilter', $ipfilter) }
	if ($log_level_in -and -not [String]::IsNullOrEmpty($log_level_in) -and -not [String]::IsNullOrWhiteSpace($log_level_in)) { $Options.Add('log_level_in', $log_level_in) }
	if ($log_level_out -and -not [String]::IsNullOrEmpty($log_level_out) -and -not [String]::IsNullOrWhiteSpace($log_level_out)) { $Options.Add('log_level_out', $log_level_out) }
	if ($macfilter) { $Options.Add('macfilter', $macfilter) }
	if ($ndp) { $Options.Add('ndp', $ndp) }
	if ($policy_in -and -not [String]::IsNullOrEmpty($policy_in) -and -not [String]::IsNullOrWhiteSpace($policy_in)) { $Options.Add('policy_in', $policy_in) }
	if ($policy_out -and -not [String]::IsNullOrEmpty($policy_out) -and -not [String]::IsNullOrWhiteSpace($policy_out)) { $Options.Add('policy_out', $policy_out) }
	if ($radv) { $Options.Add('radv', $radv) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/qemu/{vmid}/firewall/options" -Options $Options
}
function Get-NodeQemuConfig {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		# Get current values (instead of pending values).
		[switch]
		$current,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Fetch config values from given snapshot.
		[string]
		$snapshot,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($current) { $Options.Add('current', $current) }
	if ($snapshot -and -not [String]::IsNullOrEmpty($snapshot) -and -not [String]::IsNullOrWhiteSpace($snapshot)) { $Options.Add('snapshot', $snapshot) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/config" -Options $Options
}
function New-NodeQemuConfig {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Enable/disable ACPI.
		[switch]
		$acpi,
		# Enable/disable communication with the Qemu Guest Agent and its properties.
		[string]
		$agent,
		# Virtual processor architecture. Defaults to the host.
		[string]
		$arch,
		# Arbitrary arguments passed to kvm.
		[string]
		$AudioArgs,
		# Configure a audio device, useful in combination with QXL/Spice.
		[string]
		$audio0,
		# Automatic restart after crash (currently ignored).
		[switch]
		$autostart,
		# Time to wait for the task to finish. We return 'null' if the task finish within that time.
		[integer]
		$background_delay,
		# Amount of target RAM for the VM in MB. Using zero disables the ballon driver.
		[integer]
		$balloon,
		# Select BIOS implementation.
		[string]
		$bios,
		# Specify guest boot order. Use the 'order=' sub-property as usage with no key or 'legacy=' is deprecated.
		[string]
		$boot,
		# Enable booting from specified disk. Deprecated: Use 'boot: order=foo;bar' instead.
		[string]
		$bootdisk,
		# This is an alias for option -ide2
		[string]
		$cdrom,
		# cloud-init: Specify custom files to replace the automatically generated ones at start.
		[string]
		$cicustom,
		# cloud-init: Password to assign the user. Using this is generally not recommended. Use ssh keys instead. Also note that older cloud-init versions do not support hashed passwords.
		[securestring]
		$cipassword,
		# Specifies the cloud-init configuration format. The default depends on the configured operating system type (`ostype`. We use the `nocloud` format for Linux, and `configdrive2` for windows.
		[string]
		$citype,
		# cloud-init: User name to change ssh keys and password for instead of the image's configured default user.
		[string]
		$ciuser,
		# The number of cores per socket.
		[integer]
		$cores,
		# Emulated CPU type.
		[string]
		$cpu,
		# Limit of CPU usage.
		[number]
		$cpulimit,
		# CPU weight for a VM, will be clamped to [1, 10000] in cgroup v2.
		[integer]
		$cpuunits,
		# A list of settings you want to delete.
		[string]
		$delete,
		# Description for the VM. Shown in the web-interface VM's summary. This is saved as comment inside the configuration file.
		[string]
		$description,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# Configure a Disk for storing EFI vars. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume. Note that SIZE_IN_GiB is ignored here and that the default EFI vars are copied to the volume instead.
		[string]
		$efidisk0,
		# Freeze CPU at startup (use 'c' monitor command to start execution).
		[switch]
		$freeze,
		# Script that will be executed during various steps in the vms lifetime.
		[string]
		$hookscript,
		# Map host PCI devices into guest.
		[string]
		$hostpci0,
		# Map host PCI devices into guest.
		[string]
		$hostpci1,
		# Map host PCI devices into guest.
		[string]
		$hostpci2,
		# Map host PCI devices into guest.
		[string]
		$hostpci3,
		# Map host PCI devices into guest.
		[string]
		$hostpci4,
		# Map host PCI devices into guest.
		[string]
		$hostpci5,
		# Map host PCI devices into guest.
		[string]
		$hostpci6,
		# Map host PCI devices into guest.
		[string]
		$hostpci7,
		# Map host PCI devices into guest.
		[string]
		$hostpci8,
		# Map host PCI devices into guest.
		[string]
		$hostpci9,
		# Map host PCI devices into guest.
		[string]
		$hostpci10,
		# Selectively enable hotplug features. This is a comma separated list of hotplug features: 'network', 'disk', 'cpu', 'memory' and 'usb'. Use '0' to disable hotplug completely. Using '1' as value is an alias for the default `network,disk,usb`.
		[string]
		$hotplug,
		# Enable/disable hugepages memory.
		[string]
		$hugepages,
		# Use volume as IDE hard disk or CD-ROM (n is 0 to 3). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$ide0,
		# Use volume as IDE hard disk or CD-ROM (n is 0 to 3). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$ide1,
		# Use volume as IDE hard disk or CD-ROM (n is 0 to 3). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$ide2,
		# Use volume as IDE hard disk or CD-ROM (n is 0 to 3). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$ide3,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig0,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig1,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig2,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig3,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig4,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig5,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig6,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig7,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig8,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig9,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig10,
		# Inter-VM shared memory. Useful for direct communication between VMs, or to the host.
		[string]
		$ivshmem,
		# Use together with hugepages. If enabled, hugepages will not not be deleted after VM shutdown and can be used for subsequent starts.
		[switch]
		$keephugepages,
		# Keyboard layout for VNC server. The default is read from the'/etc/pve/datacenter.cfg' configuration file. It should not be necessary to set it.
		[string]
		$keyboard,
		# Enable/disable KVM hardware virtualization.
		[switch]
		$kvm,
		# Set the real time clock (RTC) to local time. This is enabled by default if the `ostype` indicates a Microsoft Windows OS.
		[switch]
		$localtime,
		# Lock/unlock the VM.
		[string]
		$lock,
		# Specifies the Qemu machine type.
		[string]
		$machine,
		# Amount of RAM for the VM in MB. This is the maximum available memory when you use the balloon device.
		[integer]
		$memory,
		# Set maximum tolerated downtime (in seconds) for migrations.
		[number]
		$migrate_downtime,
		# Set maximum speed (in MB/s) for migrations. Value 0 is no limit.
		[integer]
		$migrate_speed,
		# Set a name for the VM. Only used on the configuration web interface.
		[string]
		$name,
		# cloud-init: Sets DNS server IP address for a container. Create will'
		[string]
		$nameserver,
		# Specify network devices.
		[string]
		$net0,
		# Specify network devices.
		[string]
		$net1,
		# Specify network devices.
		[string]
		$net2,
		# Specify network devices.
		[string]
		$net3,
		# Specify network devices.
		[string]
		$net4,
		# Specify network devices.
		[string]
		$net5,
		# Specify network devices.
		[string]
		$net6,
		# Specify network devices.
		[string]
		$net7,
		# Specify network devices.
		[string]
		$net8,
		# Specify network devices.
		[string]
		$net9,
		# Specify network devices.
		[string]
		$net10,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Enable/disable NUMA.
		[switch]
		$numa,
		# NUMA topology.
		[string]
		$numa0,
		# NUMA topology.
		[string]
		$numa1,
		# NUMA topology.
		[string]
		$numa2,
		# NUMA topology.
		[string]
		$numa3,
		# NUMA topology.
		[string]
		$numa4,
		# NUMA topology.
		[string]
		$numa5,
		# NUMA topology.
		[string]
		$numa6,
		# NUMA topology.
		[string]
		$numa7,
		# NUMA topology.
		[string]
		$numa8,
		# NUMA topology.
		[string]
		$numa9,
		# NUMA topology.
		[string]
		$numa10,
		# Specifies whether a VM will be started during system bootup.
		[switch]
		$onboot,
		# Specify guest operating system.
		[string]
		$ostype,
		# Map host parallel devices (n is 0 to 2).
		[string]
		$parallel0,
		# Map host parallel devices (n is 0 to 2).
		[string]
		$parallel1,
		# Map host parallel devices (n is 0 to 2).
		[string]
		$parallel2,
		# Sets the protection flag of the VM. This will disable the remove VM and remove disk operations.
		[switch]
		$protection,
		# Allow reboot. If set to '0' the VM exit on reboot.
		[switch]
		$reboot,
		# Revert a pending change.
		[string]
		$revert,
		# Configure a VirtIO-based Random Number Generator.
		[string]
		$rng0,
		# Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$sata0,
		# Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$sata1,
		# Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$sata2,
		# Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$sata3,
		# Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$sata4,
		# Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$sata5,
		# SCSI controller model
		[string]
		$scsihw,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi0,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi1,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi2,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi3,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi4,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi5,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi6,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi7,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi8,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi9,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi10,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi11,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi12,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi13,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi14,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi15,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi16,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi17,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi18,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi19,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi20,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi21,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi22,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi23,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi24,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi25,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi26,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi27,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi28,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi29,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi30,
		# cloud-init: Sets DNS search domains for a container. Create will'
		[string]
		$searchdomain,
		# Create a serial device inside the VM (n is 0 to 3)
		[string]
		$serial0,
		# Create a serial device inside the VM (n is 0 to 3)
		[string]
		$serial1,
		# Create a serial device inside the VM (n is 0 to 3)
		[string]
		$serial2,
		# Create a serial device inside the VM (n is 0 to 3)
		[string]
		$serial3,
		# Amount of memory shares for auto-ballooning. The larger the number is, the more memory this VM gets. Number is relative to weights of all other running VMs. Using zero disables auto-ballooning. Auto-ballooning is done by pvestatd.
		[integer]
		$shares,
		# Ignore locks - only root is allowed to use this option.
		[switch]
		$skiplock,
		# Specify SMBIOS type 1 fields.
		[string]
		$smbios1,
		# The number of CPUs. Please use option -sockets instead.
		[integer]
		$smp,
		# The number of CPU sockets.
		[integer]
		$sockets,
		# Configure additional enhancements for SPICE.
		[string]
		$spice_enhancements,
		# cloud-init: Setup public SSH keys (one key per line, OpenSSH format).
		[string]
		$sshkeys,
		# Set the initial date of the real time clock. Valid format for date are:'now' or '2006-06-17T16:01:21' or '2006-06-17'.
		[string]
		$startdate,
		# Startup and shutdown behavior. Order is a non-negative number defining the general startup order. Shutdown in done with reverse ordering. Additionally you can set the 'up' or 'down' delay in seconds, which specifies a delay to wait before the next VM is started or stopped.
		[string]
		$startup,
		# Enable/disable the USB tablet device.
		[switch]
		$tablet,
		# Tags of the VM. This is only meta information.
		[string]
		$tags,
		# Enable/disable time drift fix.
		[switch]
		$tdf,
		# Enable/disable Template.
		[switch]
		$template,
		# Configure a Disk for storing TPM state. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume. Note that SIZE_IN_GiB is ignored here and that the default size of 4 MiB will always be used instead. The format is also fixed to 'raw'.
		[string]
		$tpmstate0,
		# Configure an USB device (n is 0 to 4).
		[string]
		$usb0,
		# Configure an USB device (n is 0 to 4).
		[string]
		$usb1,
		# Configure an USB device (n is 0 to 4).
		[string]
		$usb2,
		# Configure an USB device (n is 0 to 4).
		[string]
		$usb3,
		# Configure an USB device (n is 0 to 4).
		[string]
		$usb4,
		# Number of hotplugged vcpus.
		[integer]
		$vcpus,
		# Configure the VGA hardware.
		[string]
		$vga,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio0,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio1,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio2,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio3,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio4,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio5,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio6,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio7,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio8,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio9,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio10,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio11,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio12,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio13,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio14,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio15,
		# Set VM Generation ID. Use '1' to autogenerate on create or update, pass '0' to disable explicitly.
		[string]
		$vmgenid,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid,
		# Default storage for VM state volumes/files.
		[string]
		$vmstatestorage,
		# Create a virtual hardware watchdog device.
		[string]
		$watchdog
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($acpi) { $Options.Add('acpi', $acpi) }
	if ($agent -and -not [String]::IsNullOrEmpty($agent) -and -not [String]::IsNullOrWhiteSpace($agent)) { $Options.Add('agent', $agent) }
	if ($arch -and -not [String]::IsNullOrEmpty($arch) -and -not [String]::IsNullOrWhiteSpace($arch)) { $Options.Add('arch', $arch) }
	if ($AudioArgs -and -not [String]::IsNullOrEmpty($AudioArgs) -and -not [String]::IsNullOrWhiteSpace($AudioArgs)) { $Options.Add('args', $AudioArgs) }
	if ($audio0 -and -not [String]::IsNullOrEmpty($audio0) -and -not [String]::IsNullOrWhiteSpace($audio0)) { $Options.Add('audio0', $audio0) }
	if ($autostart) { $Options.Add('autostart', $autostart) }
	if ($background_delay -and -not [String]::IsNullOrEmpty($background_delay) -and -not [String]::IsNullOrWhiteSpace($background_delay)) { $Options.Add('background_delay', $background_delay) }
	if ($balloon -and -not [String]::IsNullOrEmpty($balloon) -and -not [String]::IsNullOrWhiteSpace($balloon)) { $Options.Add('balloon', $balloon) }
	if ($bios -and -not [String]::IsNullOrEmpty($bios) -and -not [String]::IsNullOrWhiteSpace($bios)) { $Options.Add('bios', $bios) }
	if ($boot -and -not [String]::IsNullOrEmpty($boot) -and -not [String]::IsNullOrWhiteSpace($boot)) { $Options.Add('boot', $boot) }
	if ($bootdisk -and -not [String]::IsNullOrEmpty($bootdisk) -and -not [String]::IsNullOrWhiteSpace($bootdisk)) { $Options.Add('bootdisk', $bootdisk) }
	if ($cdrom -and -not [String]::IsNullOrEmpty($cdrom) -and -not [String]::IsNullOrWhiteSpace($cdrom)) { $Options.Add('cdrom', $cdrom) }
	if ($cicustom -and -not [String]::IsNullOrEmpty($cicustom) -and -not [String]::IsNullOrWhiteSpace($cicustom)) { $Options.Add('cicustom', $cicustom) }
	if ($cipassword) { $Options.Add('cipassword', $($cipassword | ConvertFrom-SecureString -AsPlainText)) }
	if ($citype -and -not [String]::IsNullOrEmpty($citype) -and -not [String]::IsNullOrWhiteSpace($citype)) { $Options.Add('citype', $citype) }
	if ($ciuser -and -not [String]::IsNullOrEmpty($ciuser) -and -not [String]::IsNullOrWhiteSpace($ciuser)) { $Options.Add('ciuser', $ciuser) }
	if ($cores -and -not [String]::IsNullOrEmpty($cores) -and -not [String]::IsNullOrWhiteSpace($cores)) { $Options.Add('cores', $cores) }
	if ($cpu -and -not [String]::IsNullOrEmpty($cpu) -and -not [String]::IsNullOrWhiteSpace($cpu)) { $Options.Add('cpu', $cpu) }
	if ($cpulimit -and -not [String]::IsNullOrEmpty($cpulimit) -and -not [String]::IsNullOrWhiteSpace($cpulimit)) { $Options.Add('cpulimit', $cpulimit) }
	if ($cpuunits -and -not [String]::IsNullOrEmpty($cpuunits) -and -not [String]::IsNullOrWhiteSpace($cpuunits)) { $Options.Add('cpuunits', $cpuunits) }
	if ($delete -and -not [String]::IsNullOrEmpty($delete) -and -not [String]::IsNullOrWhiteSpace($delete)) { $Options.Add('delete', $delete) }
	if ($description -and -not [String]::IsNullOrEmpty($description) -and -not [String]::IsNullOrWhiteSpace($description)) { $Options.Add('description', $description) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($efidisk0 -and -not [String]::IsNullOrEmpty($efidisk0) -and -not [String]::IsNullOrWhiteSpace($efidisk0)) { $Options.Add('efidisk0', $efidisk0) }
	if ($force) { $Options.Add('force', $force) }
	if ($freeze) { $Options.Add('freeze', $freeze) }
	if ($hookscript -and -not [String]::IsNullOrEmpty($hookscript) -and -not [String]::IsNullOrWhiteSpace($hookscript)) { $Options.Add('hookscript', $hookscript) }
	if ($hostpci0 -and -not [String]::IsNullOrEmpty($hostpci0) -and -not [String]::IsNullOrWhiteSpace($hostpci0)) { $Options.Add('hostpci0', $hostpci0) }
	if ($hostpci1 -and -not [String]::IsNullOrEmpty($hostpci1) -and -not [String]::IsNullOrWhiteSpace($hostpci1)) { $Options.Add('hostpci1', $hostpci1) }
	if ($hostpci2 -and -not [String]::IsNullOrEmpty($hostpci2) -and -not [String]::IsNullOrWhiteSpace($hostpci2)) { $Options.Add('hostpci2', $hostpci2) }
	if ($hostpci3 -and -not [String]::IsNullOrEmpty($hostpci3) -and -not [String]::IsNullOrWhiteSpace($hostpci3)) { $Options.Add('hostpci3', $hostpci3) }
	if ($hostpci4 -and -not [String]::IsNullOrEmpty($hostpci4) -and -not [String]::IsNullOrWhiteSpace($hostpci4)) { $Options.Add('hostpci4', $hostpci4) }
	if ($hostpci5 -and -not [String]::IsNullOrEmpty($hostpci5) -and -not [String]::IsNullOrWhiteSpace($hostpci5)) { $Options.Add('hostpci5', $hostpci5) }
	if ($hostpci6 -and -not [String]::IsNullOrEmpty($hostpci6) -and -not [String]::IsNullOrWhiteSpace($hostpci6)) { $Options.Add('hostpci6', $hostpci6) }
	if ($hostpci7 -and -not [String]::IsNullOrEmpty($hostpci7) -and -not [String]::IsNullOrWhiteSpace($hostpci7)) { $Options.Add('hostpci7', $hostpci7) }
	if ($hostpci8 -and -not [String]::IsNullOrEmpty($hostpci8) -and -not [String]::IsNullOrWhiteSpace($hostpci8)) { $Options.Add('hostpci8', $hostpci8) }
	if ($hostpci9 -and -not [String]::IsNullOrEmpty($hostpci9) -and -not [String]::IsNullOrWhiteSpace($hostpci9)) { $Options.Add('hostpci9', $hostpci9) }
	if ($hostpci10 -and -not [String]::IsNullOrEmpty($hostpci10) -and -not [String]::IsNullOrWhiteSpace($hostpci10)) { $Options.Add('hostpci10', $hostpci10) }
	if ($hotplug -and -not [String]::IsNullOrEmpty($hotplug) -and -not [String]::IsNullOrWhiteSpace($hotplug)) { $Options.Add('hotplug', $hotplug) }
	if ($hugepages -and -not [String]::IsNullOrEmpty($hugepages) -and -not [String]::IsNullOrWhiteSpace($hugepages)) { $Options.Add('hugepages', $hugepages) }
	if ($ide0 -and -not [String]::IsNullOrEmpty($ide0) -and -not [String]::IsNullOrWhiteSpace($ide0)) { $Options.Add('ide0', $ide0) }
	if ($ide1 -and -not [String]::IsNullOrEmpty($ide1) -and -not [String]::IsNullOrWhiteSpace($ide1)) { $Options.Add('ide1', $ide1) }
	if ($ide2 -and -not [String]::IsNullOrEmpty($ide2) -and -not [String]::IsNullOrWhiteSpace($ide2)) { $Options.Add('ide2', $ide2) }
	if ($ide3 -and -not [String]::IsNullOrEmpty($ide3) -and -not [String]::IsNullOrWhiteSpace($ide3)) { $Options.Add('ide3', $ide3) }
	if ($ipconfig0 -and -not [String]::IsNullOrEmpty($ipconfig0) -and -not [String]::IsNullOrWhiteSpace($ipconfig0)) { $Options.Add('ipconfig0', $ipconfig0) }
	if ($ipconfig1 -and -not [String]::IsNullOrEmpty($ipconfig1) -and -not [String]::IsNullOrWhiteSpace($ipconfig1)) { $Options.Add('ipconfig1', $ipconfig1) }
	if ($ipconfig2 -and -not [String]::IsNullOrEmpty($ipconfig2) -and -not [String]::IsNullOrWhiteSpace($ipconfig2)) { $Options.Add('ipconfig2', $ipconfig2) }
	if ($ipconfig3 -and -not [String]::IsNullOrEmpty($ipconfig3) -and -not [String]::IsNullOrWhiteSpace($ipconfig3)) { $Options.Add('ipconfig3', $ipconfig3) }
	if ($ipconfig4 -and -not [String]::IsNullOrEmpty($ipconfig4) -and -not [String]::IsNullOrWhiteSpace($ipconfig4)) { $Options.Add('ipconfig4', $ipconfig4) }
	if ($ipconfig5 -and -not [String]::IsNullOrEmpty($ipconfig5) -and -not [String]::IsNullOrWhiteSpace($ipconfig5)) { $Options.Add('ipconfig5', $ipconfig5) }
	if ($ipconfig6 -and -not [String]::IsNullOrEmpty($ipconfig6) -and -not [String]::IsNullOrWhiteSpace($ipconfig6)) { $Options.Add('ipconfig6', $ipconfig6) }
	if ($ipconfig7 -and -not [String]::IsNullOrEmpty($ipconfig7) -and -not [String]::IsNullOrWhiteSpace($ipconfig7)) { $Options.Add('ipconfig7', $ipconfig7) }
	if ($ipconfig8 -and -not [String]::IsNullOrEmpty($ipconfig8) -and -not [String]::IsNullOrWhiteSpace($ipconfig8)) { $Options.Add('ipconfig8', $ipconfig8) }
	if ($ipconfig9 -and -not [String]::IsNullOrEmpty($ipconfig9) -and -not [String]::IsNullOrWhiteSpace($ipconfig9)) { $Options.Add('ipconfig9', $ipconfig9) }
	if ($ipconfig10 -and -not [String]::IsNullOrEmpty($ipconfig10) -and -not [String]::IsNullOrWhiteSpace($ipconfig10)) { $Options.Add('ipconfig10', $ipconfig10) }
	if ($ivshmem -and -not [String]::IsNullOrEmpty($ivshmem) -and -not [String]::IsNullOrWhiteSpace($ivshmem)) { $Options.Add('ivshmem', $ivshmem) }
	if ($keephugepages) { $Options.Add('keephugepages', $keephugepages) }
	if ($keyboard -and -not [String]::IsNullOrEmpty($keyboard) -and -not [String]::IsNullOrWhiteSpace($keyboard)) { $Options.Add('keyboard', $keyboard) }
	if ($kvm) { $Options.Add('kvm', $kvm) }
	if ($localtime) { $Options.Add('localtime', $localtime) }
	if ($lock -and -not [String]::IsNullOrEmpty($lock) -and -not [String]::IsNullOrWhiteSpace($lock)) { $Options.Add('lock', $lock) }
	if ($machine -and -not [String]::IsNullOrEmpty($machine) -and -not [String]::IsNullOrWhiteSpace($machine)) { $Options.Add('machine', $machine) }
	if ($memory -and -not [String]::IsNullOrEmpty($memory) -and -not [String]::IsNullOrWhiteSpace($memory)) { $Options.Add('memory', $memory) }
	if ($migrate_downtime -and -not [String]::IsNullOrEmpty($migrate_downtime) -and -not [String]::IsNullOrWhiteSpace($migrate_downtime)) { $Options.Add('migrate_downtime', $migrate_downtime) }
	if ($migrate_speed -and -not [String]::IsNullOrEmpty($migrate_speed) -and -not [String]::IsNullOrWhiteSpace($migrate_speed)) { $Options.Add('migrate_speed', $migrate_speed) }
	if ($name -and -not [String]::IsNullOrEmpty($name) -and -not [String]::IsNullOrWhiteSpace($name)) { $Options.Add('name', $name) }
	if ($nameserver -and -not [String]::IsNullOrEmpty($nameserver) -and -not [String]::IsNullOrWhiteSpace($nameserver)) { $Options.Add('nameserver', $nameserver) }
	if ($net0 -and -not [String]::IsNullOrEmpty($net0) -and -not [String]::IsNullOrWhiteSpace($net0)) { $Options.Add('net0', $net0) }
	if ($net1 -and -not [String]::IsNullOrEmpty($net1) -and -not [String]::IsNullOrWhiteSpace($net1)) { $Options.Add('net1', $net1) }
	if ($net2 -and -not [String]::IsNullOrEmpty($net2) -and -not [String]::IsNullOrWhiteSpace($net2)) { $Options.Add('net2', $net2) }
	if ($net3 -and -not [String]::IsNullOrEmpty($net3) -and -not [String]::IsNullOrWhiteSpace($net3)) { $Options.Add('net3', $net3) }
	if ($net4 -and -not [String]::IsNullOrEmpty($net4) -and -not [String]::IsNullOrWhiteSpace($net4)) { $Options.Add('net4', $net4) }
	if ($net5 -and -not [String]::IsNullOrEmpty($net5) -and -not [String]::IsNullOrWhiteSpace($net5)) { $Options.Add('net5', $net5) }
	if ($net6 -and -not [String]::IsNullOrEmpty($net6) -and -not [String]::IsNullOrWhiteSpace($net6)) { $Options.Add('net6', $net6) }
	if ($net7 -and -not [String]::IsNullOrEmpty($net7) -and -not [String]::IsNullOrWhiteSpace($net7)) { $Options.Add('net7', $net7) }
	if ($net8 -and -not [String]::IsNullOrEmpty($net8) -and -not [String]::IsNullOrWhiteSpace($net8)) { $Options.Add('net8', $net8) }
	if ($net9 -and -not [String]::IsNullOrEmpty($net9) -and -not [String]::IsNullOrWhiteSpace($net9)) { $Options.Add('net9', $net9) }
	if ($net10 -and -not [String]::IsNullOrEmpty($net10) -and -not [String]::IsNullOrWhiteSpace($net10)) { $Options.Add('net10', $net10) }
	if ($numa) { $Options.Add('numa', $numa) }
	if ($numa0 -and -not [String]::IsNullOrEmpty($numa0) -and -not [String]::IsNullOrWhiteSpace($numa0)) { $Options.Add('numa0', $numa0) }
	if ($numa1 -and -not [String]::IsNullOrEmpty($numa1) -and -not [String]::IsNullOrWhiteSpace($numa1)) { $Options.Add('numa1', $numa1) }
	if ($numa2 -and -not [String]::IsNullOrEmpty($numa2) -and -not [String]::IsNullOrWhiteSpace($numa2)) { $Options.Add('numa2', $numa2) }
	if ($numa3 -and -not [String]::IsNullOrEmpty($numa3) -and -not [String]::IsNullOrWhiteSpace($numa3)) { $Options.Add('numa3', $numa3) }
	if ($numa4 -and -not [String]::IsNullOrEmpty($numa4) -and -not [String]::IsNullOrWhiteSpace($numa4)) { $Options.Add('numa4', $numa4) }
	if ($numa5 -and -not [String]::IsNullOrEmpty($numa5) -and -not [String]::IsNullOrWhiteSpace($numa5)) { $Options.Add('numa5', $numa5) }
	if ($numa6 -and -not [String]::IsNullOrEmpty($numa6) -and -not [String]::IsNullOrWhiteSpace($numa6)) { $Options.Add('numa6', $numa6) }
	if ($numa7 -and -not [String]::IsNullOrEmpty($numa7) -and -not [String]::IsNullOrWhiteSpace($numa7)) { $Options.Add('numa7', $numa7) }
	if ($numa8 -and -not [String]::IsNullOrEmpty($numa8) -and -not [String]::IsNullOrWhiteSpace($numa8)) { $Options.Add('numa8', $numa8) }
	if ($numa9 -and -not [String]::IsNullOrEmpty($numa9) -and -not [String]::IsNullOrWhiteSpace($numa9)) { $Options.Add('numa9', $numa9) }
	if ($numa10 -and -not [String]::IsNullOrEmpty($numa10) -and -not [String]::IsNullOrWhiteSpace($numa10)) { $Options.Add('numa10', $numa10) }
	if ($onboot) { $Options.Add('onboot', $onboot) }
	if ($ostype -and -not [String]::IsNullOrEmpty($ostype) -and -not [String]::IsNullOrWhiteSpace($ostype)) { $Options.Add('ostype', $ostype) }
	if ($parallel0 -and -not [String]::IsNullOrEmpty($parallel0) -and -not [String]::IsNullOrWhiteSpace($parallel0)) { $Options.Add('parallel0', $parallel0) }
	if ($parallel1 -and -not [String]::IsNullOrEmpty($parallel1) -and -not [String]::IsNullOrWhiteSpace($parallel1)) { $Options.Add('parallel1', $parallel1) }
	if ($parallel2 -and -not [String]::IsNullOrEmpty($parallel2) -and -not [String]::IsNullOrWhiteSpace($parallel2)) { $Options.Add('parallel2', $parallel2) }
	if ($protection) { $Options.Add('protection', $protection) }
	if ($reboot) { $Options.Add('reboot', $reboot) }
	if ($revert -and -not [String]::IsNullOrEmpty($revert) -and -not [String]::IsNullOrWhiteSpace($revert)) { $Options.Add('revert', $revert) }
	if ($rng0 -and -not [String]::IsNullOrEmpty($rng0) -and -not [String]::IsNullOrWhiteSpace($rng0)) { $Options.Add('rng0', $rng0) }
	if ($sata0 -and -not [String]::IsNullOrEmpty($sata0) -and -not [String]::IsNullOrWhiteSpace($sata0)) { $Options.Add('sata0', $sata0) }
	if ($sata1 -and -not [String]::IsNullOrEmpty($sata1) -and -not [String]::IsNullOrWhiteSpace($sata1)) { $Options.Add('sata1', $sata1) }
	if ($sata2 -and -not [String]::IsNullOrEmpty($sata2) -and -not [String]::IsNullOrWhiteSpace($sata2)) { $Options.Add('sata2', $sata2) }
	if ($sata3 -and -not [String]::IsNullOrEmpty($sata3) -and -not [String]::IsNullOrWhiteSpace($sata3)) { $Options.Add('sata3', $sata3) }
	if ($sata4 -and -not [String]::IsNullOrEmpty($sata4) -and -not [String]::IsNullOrWhiteSpace($sata4)) { $Options.Add('sata4', $sata4) }
	if ($sata5 -and -not [String]::IsNullOrEmpty($sata5) -and -not [String]::IsNullOrWhiteSpace($sata5)) { $Options.Add('sata5', $sata5) }
	if ($scsihw -and -not [String]::IsNullOrEmpty($scsihw) -and -not [String]::IsNullOrWhiteSpace($scsihw)) { $Options.Add('scsihw', $scsihw) }
	if ($scsi0 -and -not [String]::IsNullOrEmpty($scsi0) -and -not [String]::IsNullOrWhiteSpace($scsi0)) { $Options.Add('scsi0', $scsi0) }
	if ($scsi1 -and -not [String]::IsNullOrEmpty($scsi1) -and -not [String]::IsNullOrWhiteSpace($scsi1)) { $Options.Add('scsi1', $scsi1) }
	if ($scsi2 -and -not [String]::IsNullOrEmpty($scsi2) -and -not [String]::IsNullOrWhiteSpace($scsi2)) { $Options.Add('scsi2', $scsi2) }
	if ($scsi3 -and -not [String]::IsNullOrEmpty($scsi3) -and -not [String]::IsNullOrWhiteSpace($scsi3)) { $Options.Add('scsi3', $scsi3) }
	if ($scsi4 -and -not [String]::IsNullOrEmpty($scsi4) -and -not [String]::IsNullOrWhiteSpace($scsi4)) { $Options.Add('scsi4', $scsi4) }
	if ($scsi5 -and -not [String]::IsNullOrEmpty($scsi5) -and -not [String]::IsNullOrWhiteSpace($scsi5)) { $Options.Add('scsi5', $scsi5) }
	if ($scsi6 -and -not [String]::IsNullOrEmpty($scsi6) -and -not [String]::IsNullOrWhiteSpace($scsi6)) { $Options.Add('scsi6', $scsi6) }
	if ($scsi7 -and -not [String]::IsNullOrEmpty($scsi7) -and -not [String]::IsNullOrWhiteSpace($scsi7)) { $Options.Add('scsi7', $scsi7) }
	if ($scsi8 -and -not [String]::IsNullOrEmpty($scsi8) -and -not [String]::IsNullOrWhiteSpace($scsi8)) { $Options.Add('scsi8', $scsi8) }
	if ($scsi9 -and -not [String]::IsNullOrEmpty($scsi9) -and -not [String]::IsNullOrWhiteSpace($scsi9)) { $Options.Add('scsi9', $scsi9) }
	if ($scsi10 -and -not [String]::IsNullOrEmpty($scsi10) -and -not [String]::IsNullOrWhiteSpace($scsi10)) { $Options.Add('scsi10', $scsi10) }
	if ($scsi11 -and -not [String]::IsNullOrEmpty($scsi11) -and -not [String]::IsNullOrWhiteSpace($scsi11)) { $Options.Add('scsi11', $scsi11) }
	if ($scsi12 -and -not [String]::IsNullOrEmpty($scsi12) -and -not [String]::IsNullOrWhiteSpace($scsi12)) { $Options.Add('scsi12', $scsi12) }
	if ($scsi13 -and -not [String]::IsNullOrEmpty($scsi13) -and -not [String]::IsNullOrWhiteSpace($scsi13)) { $Options.Add('scsi13', $scsi13) }
	if ($scsi14 -and -not [String]::IsNullOrEmpty($scsi14) -and -not [String]::IsNullOrWhiteSpace($scsi14)) { $Options.Add('scsi14', $scsi14) }
	if ($scsi15 -and -not [String]::IsNullOrEmpty($scsi15) -and -not [String]::IsNullOrWhiteSpace($scsi15)) { $Options.Add('scsi15', $scsi15) }
	if ($scsi16 -and -not [String]::IsNullOrEmpty($scsi16) -and -not [String]::IsNullOrWhiteSpace($scsi16)) { $Options.Add('scsi16', $scsi16) }
	if ($scsi17 -and -not [String]::IsNullOrEmpty($scsi17) -and -not [String]::IsNullOrWhiteSpace($scsi17)) { $Options.Add('scsi17', $scsi17) }
	if ($scsi18 -and -not [String]::IsNullOrEmpty($scsi18) -and -not [String]::IsNullOrWhiteSpace($scsi18)) { $Options.Add('scsi18', $scsi18) }
	if ($scsi19 -and -not [String]::IsNullOrEmpty($scsi19) -and -not [String]::IsNullOrWhiteSpace($scsi19)) { $Options.Add('scsi19', $scsi19) }
	if ($scsi20 -and -not [String]::IsNullOrEmpty($scsi20) -and -not [String]::IsNullOrWhiteSpace($scsi20)) { $Options.Add('scsi20', $scsi20) }
	if ($scsi21 -and -not [String]::IsNullOrEmpty($scsi21) -and -not [String]::IsNullOrWhiteSpace($scsi21)) { $Options.Add('scsi21', $scsi21) }
	if ($scsi22 -and -not [String]::IsNullOrEmpty($scsi22) -and -not [String]::IsNullOrWhiteSpace($scsi22)) { $Options.Add('scsi22', $scsi22) }
	if ($scsi23 -and -not [String]::IsNullOrEmpty($scsi23) -and -not [String]::IsNullOrWhiteSpace($scsi23)) { $Options.Add('scsi23', $scsi23) }
	if ($scsi24 -and -not [String]::IsNullOrEmpty($scsi24) -and -not [String]::IsNullOrWhiteSpace($scsi24)) { $Options.Add('scsi24', $scsi24) }
	if ($scsi25 -and -not [String]::IsNullOrEmpty($scsi25) -and -not [String]::IsNullOrWhiteSpace($scsi25)) { $Options.Add('scsi25', $scsi25) }
	if ($scsi26 -and -not [String]::IsNullOrEmpty($scsi26) -and -not [String]::IsNullOrWhiteSpace($scsi26)) { $Options.Add('scsi26', $scsi26) }
	if ($scsi27 -and -not [String]::IsNullOrEmpty($scsi27) -and -not [String]::IsNullOrWhiteSpace($scsi27)) { $Options.Add('scsi27', $scsi27) }
	if ($scsi28 -and -not [String]::IsNullOrEmpty($scsi28) -and -not [String]::IsNullOrWhiteSpace($scsi28)) { $Options.Add('scsi28', $scsi28) }
	if ($scsi29 -and -not [String]::IsNullOrEmpty($scsi29) -and -not [String]::IsNullOrWhiteSpace($scsi29)) { $Options.Add('scsi29', $scsi29) }
	if ($scsi30 -and -not [String]::IsNullOrEmpty($scsi30) -and -not [String]::IsNullOrWhiteSpace($scsi30)) { $Options.Add('scsi30', $scsi30) }
	if ($searchdomain -and -not [String]::IsNullOrEmpty($searchdomain) -and -not [String]::IsNullOrWhiteSpace($searchdomain)) { $Options.Add('searchdomain', $searchdomain) }
	if ($serial0 -and -not [String]::IsNullOrEmpty($serial0) -and -not [String]::IsNullOrWhiteSpace($serial0)) { $Options.Add('serial0', $serial0) }
	if ($serial1 -and -not [String]::IsNullOrEmpty($serial1) -and -not [String]::IsNullOrWhiteSpace($serial1)) { $Options.Add('serial1', $serial1) }
	if ($serial2 -and -not [String]::IsNullOrEmpty($serial2) -and -not [String]::IsNullOrWhiteSpace($serial2)) { $Options.Add('serial2', $serial2) }
	if ($serial3 -and -not [String]::IsNullOrEmpty($serial3) -and -not [String]::IsNullOrWhiteSpace($serial3)) { $Options.Add('serial3', $serial3) }
	if ($shares -and -not [String]::IsNullOrEmpty($shares) -and -not [String]::IsNullOrWhiteSpace($shares)) { $Options.Add('shares', $shares) }
	if ($skiplock) { $Options.Add('skiplock', $skiplock) }
	if ($smbios1 -and -not [String]::IsNullOrEmpty($smbios1) -and -not [String]::IsNullOrWhiteSpace($smbios1)) { $Options.Add('smbios1', $smbios1) }
	if ($smp -and -not [String]::IsNullOrEmpty($smp) -and -not [String]::IsNullOrWhiteSpace($smp)) { $Options.Add('smp', $smp) }
	if ($sockets -and -not [String]::IsNullOrEmpty($sockets) -and -not [String]::IsNullOrWhiteSpace($sockets)) { $Options.Add('sockets', $sockets) }
	if ($spice_enhancements -and -not [String]::IsNullOrEmpty($spice_enhancements) -and -not [String]::IsNullOrWhiteSpace($spice_enhancements)) { $Options.Add('spice_enhancements', $spice_enhancements) }
	if ($sshkeys -and -not [String]::IsNullOrEmpty($sshkeys) -and -not [String]::IsNullOrWhiteSpace($sshkeys)) { $Options.Add('sshkeys', $sshkeys) }
	if ($startdate -and -not [String]::IsNullOrEmpty($startdate) -and -not [String]::IsNullOrWhiteSpace($startdate)) { $Options.Add('startdate', $startdate) }
	if ($startup -and -not [String]::IsNullOrEmpty($startup) -and -not [String]::IsNullOrWhiteSpace($startup)) { $Options.Add('startup', $startup) }
	if ($tablet) { $Options.Add('tablet', $tablet) }
	if ($tags -and -not [String]::IsNullOrEmpty($tags) -and -not [String]::IsNullOrWhiteSpace($tags)) { $Options.Add('tags', $tags) }
	if ($tdf) { $Options.Add('tdf', $tdf) }
	if ($template) { $Options.Add('template', $template) }
	if ($tpmstate0 -and -not [String]::IsNullOrEmpty($tpmstate0) -and -not [String]::IsNullOrWhiteSpace($tpmstate0)) { $Options.Add('tpmstate0', $tpmstate0) }
	if ($usb0 -and -not [String]::IsNullOrEmpty($usb0) -and -not [String]::IsNullOrWhiteSpace($usb0)) { $Options.Add('usb0', $usb0) }
	if ($usb1 -and -not [String]::IsNullOrEmpty($usb1) -and -not [String]::IsNullOrWhiteSpace($usb1)) { $Options.Add('usb1', $usb1) }
	if ($usb2 -and -not [String]::IsNullOrEmpty($usb2) -and -not [String]::IsNullOrWhiteSpace($usb2)) { $Options.Add('usb2', $usb2) }
	if ($usb3 -and -not [String]::IsNullOrEmpty($usb3) -and -not [String]::IsNullOrWhiteSpace($usb3)) { $Options.Add('usb3', $usb3) }
	if ($usb4 -and -not [String]::IsNullOrEmpty($usb4) -and -not [String]::IsNullOrWhiteSpace($usb4)) { $Options.Add('usb4', $usb4) }
	if ($vcpus -and -not [String]::IsNullOrEmpty($vcpus) -and -not [String]::IsNullOrWhiteSpace($vcpus)) { $Options.Add('vcpus', $vcpus) }
	if ($vga -and -not [String]::IsNullOrEmpty($vga) -and -not [String]::IsNullOrWhiteSpace($vga)) { $Options.Add('vga', $vga) }
	if ($virtio0 -and -not [String]::IsNullOrEmpty($virtio0) -and -not [String]::IsNullOrWhiteSpace($virtio0)) { $Options.Add('virtio0', $virtio0) }
	if ($virtio1 -and -not [String]::IsNullOrEmpty($virtio1) -and -not [String]::IsNullOrWhiteSpace($virtio1)) { $Options.Add('virtio1', $virtio1) }
	if ($virtio2 -and -not [String]::IsNullOrEmpty($virtio2) -and -not [String]::IsNullOrWhiteSpace($virtio2)) { $Options.Add('virtio2', $virtio2) }
	if ($virtio3 -and -not [String]::IsNullOrEmpty($virtio3) -and -not [String]::IsNullOrWhiteSpace($virtio3)) { $Options.Add('virtio3', $virtio3) }
	if ($virtio4 -and -not [String]::IsNullOrEmpty($virtio4) -and -not [String]::IsNullOrWhiteSpace($virtio4)) { $Options.Add('virtio4', $virtio4) }
	if ($virtio5 -and -not [String]::IsNullOrEmpty($virtio5) -and -not [String]::IsNullOrWhiteSpace($virtio5)) { $Options.Add('virtio5', $virtio5) }
	if ($virtio6 -and -not [String]::IsNullOrEmpty($virtio6) -and -not [String]::IsNullOrWhiteSpace($virtio6)) { $Options.Add('virtio6', $virtio6) }
	if ($virtio7 -and -not [String]::IsNullOrEmpty($virtio7) -and -not [String]::IsNullOrWhiteSpace($virtio7)) { $Options.Add('virtio7', $virtio7) }
	if ($virtio8 -and -not [String]::IsNullOrEmpty($virtio8) -and -not [String]::IsNullOrWhiteSpace($virtio8)) { $Options.Add('virtio8', $virtio8) }
	if ($virtio9 -and -not [String]::IsNullOrEmpty($virtio9) -and -not [String]::IsNullOrWhiteSpace($virtio9)) { $Options.Add('virtio9', $virtio9) }
	if ($virtio10 -and -not [String]::IsNullOrEmpty($virtio10) -and -not [String]::IsNullOrWhiteSpace($virtio10)) { $Options.Add('virtio10', $virtio10) }
	if ($virtio11 -and -not [String]::IsNullOrEmpty($virtio11) -and -not [String]::IsNullOrWhiteSpace($virtio11)) { $Options.Add('virtio11', $virtio11) }
	if ($virtio12 -and -not [String]::IsNullOrEmpty($virtio12) -and -not [String]::IsNullOrWhiteSpace($virtio12)) { $Options.Add('virtio12', $virtio12) }
	if ($virtio13 -and -not [String]::IsNullOrEmpty($virtio13) -and -not [String]::IsNullOrWhiteSpace($virtio13)) { $Options.Add('virtio13', $virtio13) }
	if ($virtio14 -and -not [String]::IsNullOrEmpty($virtio14) -and -not [String]::IsNullOrWhiteSpace($virtio14)) { $Options.Add('virtio14', $virtio14) }
	if ($virtio15 -and -not [String]::IsNullOrEmpty($virtio15) -and -not [String]::IsNullOrWhiteSpace($virtio15)) { $Options.Add('virtio15', $virtio15) }
	if ($vmgenid -and -not [String]::IsNullOrEmpty($vmgenid) -and -not [String]::IsNullOrWhiteSpace($vmgenid)) { $Options.Add('vmgenid', $vmgenid) }
	if ($vmstatestorage -and -not [String]::IsNullOrEmpty($vmstatestorage) -and -not [String]::IsNullOrWhiteSpace($vmstatestorage)) { $Options.Add('vmstatestorage', $vmstatestorage) }
	if ($watchdog -and -not [String]::IsNullOrEmpty($watchdog) -and -not [String]::IsNullOrWhiteSpace($watchdog)) { $Options.Add('watchdog', $watchdog) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/config" -Options $Options
}
function Set-NodeQemuConfig {
	[CmdletBinding()]
	param(
		# Enable/disable ACPI.
		[switch]
		$acpi,
		# Enable/disable communication with the Qemu Guest Agent and its properties.
		[string]
		$agent,
		# Virtual processor architecture. Defaults to the host.
		[string]
		$arch,
		# Arbitrary arguments passed to kvm.
		[string]
		$AudioArgs,
		# Configure a audio device, useful in combination with QXL/Spice.
		[string]
		$audio0,
		# Automatic restart after crash (currently ignored).
		[switch]
		$autostart,
		# Amount of target RAM for the VM in MB. Using zero disables the ballon driver.
		[integer]
		$balloon,
		# Select BIOS implementation.
		[string]
		$bios,
		# Specify guest boot order. Use the 'order=' sub-property as usage with no key or 'legacy=' is deprecated.
		[string]
		$boot,
		# Enable booting from specified disk. Deprecated: Use 'boot: order=foo;bar' instead.
		[string]
		$bootdisk,
		# This is an alias for option -ide2
		[string]
		$cdrom,
		# cloud-init: Specify custom files to replace the automatically generated ones at start.
		[string]
		$cicustom,
		# cloud-init: Password to assign the user. Using this is generally not recommended. Use ssh keys instead. Also note that older cloud-init versions do not support hashed passwords.
		[securestring]
		$cipassword,
		# Specifies the cloud-init configuration format. The default depends on the configured operating system type (`ostype`. We use the `nocloud` format for Linux, and `configdrive2` for windows.
		[string]
		$citype,
		# cloud-init: User name to change ssh keys and password for instead of the image's configured default user.
		[string]
		$ciuser,
		# The number of cores per socket.
		[integer]
		$cores,
		# Emulated CPU type.
		[string]
		$cpu,
		# Limit of CPU usage.
		[number]
		$cpulimit,
		# CPU weight for a VM, will be clamped to [1, 10000] in cgroup v2.
		[integer]
		$cpuunits,
		# A list of settings you want to delete.
		[string]
		$delete,
		# Description for the VM. Shown in the web-interface VM's summary. This is saved as comment inside the configuration file.
		[string]
		$description,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# Configure a Disk for storing EFI vars. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume. Note that SIZE_IN_GiB is ignored here and that the default EFI vars are copied to the volume instead.
		[string]
		$efidisk0,
		# Freeze CPU at startup (use 'c' monitor command to start execution).
		[switch]
		$freeze,
		# Script that will be executed during various steps in the vms lifetime.
		[string]
		$hookscript,
		# Map host PCI devices into guest.
		[string]
		$hostpci0,
		# Map host PCI devices into guest.
		[string]
		$hostpci1,
		# Map host PCI devices into guest.
		[string]
		$hostpci2,
		# Map host PCI devices into guest.
		[string]
		$hostpci3,
		# Map host PCI devices into guest.
		[string]
		$hostpci4,
		# Map host PCI devices into guest.
		[string]
		$hostpci5,
		# Map host PCI devices into guest.
		[string]
		$hostpci6,
		# Map host PCI devices into guest.
		[string]
		$hostpci7,
		# Map host PCI devices into guest.
		[string]
		$hostpci8,
		# Map host PCI devices into guest.
		[string]
		$hostpci9,
		# Map host PCI devices into guest.
		[string]
		$hostpci10,
		# Selectively enable hotplug features. This is a comma separated list of hotplug features: 'network', 'disk', 'cpu', 'memory' and 'usb'. Use '0' to disable hotplug completely. Using '1' as value is an alias for the default `network,disk,usb`.
		[string]
		$hotplug,
		# Enable/disable hugepages memory.
		[string]
		$hugepages,
		# Use volume as IDE hard disk or CD-ROM (n is 0 to 3). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$ide0,
		# Use volume as IDE hard disk or CD-ROM (n is 0 to 3). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$ide1,
		# Use volume as IDE hard disk or CD-ROM (n is 0 to 3). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$ide2,
		# Use volume as IDE hard disk or CD-ROM (n is 0 to 3). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$ide3,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig0,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig1,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig2,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig3,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig4,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig5,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig6,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig7,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig8,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig9,
		# cloud-init: Specify IP addresses and gateways for the corresponding interface.
		[string]
		$ipconfig10,
		# Inter-VM shared memory. Useful for direct communication between VMs, or to the host.
		[string]
		$ivshmem,
		# Use together with hugepages. If enabled, hugepages will not not be deleted after VM shutdown and can be used for subsequent starts.
		[switch]
		$keephugepages,
		# Keyboard layout for VNC server. The default is read from the'/etc/pve/datacenter.cfg' configuration file. It should not be necessary to set it.
		[string]
		$keyboard,
		# Enable/disable KVM hardware virtualization.
		[switch]
		$kvm,
		# Set the real time clock (RTC) to local time. This is enabled by default if the `ostype` indicates a Microsoft Windows OS.
		[switch]
		$localtime,
		# Lock/unlock the VM.
		[string]
		$lock,
		# Specifies the Qemu machine type.
		[string]
		$machine,
		# Amount of RAM for the VM in MB. This is the maximum available memory when you use the balloon device.
		[integer]
		$memory,
		# Set maximum tolerated downtime (in seconds) for migrations.
		[number]
		$migrate_downtime,
		# Set maximum speed (in MB/s) for migrations. Value 0 is no limit.
		[integer]
		$migrate_speed,
		# Set a name for the VM. Only used on the configuration web interface.
		[string]
		$name,
		# cloud-init: Sets DNS server IP address for a container. Create will'
		[string]
		$nameserver,
		# Specify network devices.
		[string]
		$net0,
		# Specify network devices.
		[string]
		$net1,
		# Specify network devices.
		[string]
		$net2,
		# Specify network devices.
		[string]
		$net3,
		# Specify network devices.
		[string]
		$net4,
		# Specify network devices.
		[string]
		$net5,
		# Specify network devices.
		[string]
		$net6,
		# Specify network devices.
		[string]
		$net7,
		# Specify network devices.
		[string]
		$net8,
		# Specify network devices.
		[string]
		$net9,
		# Specify network devices.
		[string]
		$net10,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Enable/disable NUMA.
		[switch]
		$numa,
		# NUMA topology.
		[string]
		$numa0,
		# NUMA topology.
		[string]
		$numa1,
		# NUMA topology.
		[string]
		$numa2,
		# NUMA topology.
		[string]
		$numa3,
		# NUMA topology.
		[string]
		$numa4,
		# NUMA topology.
		[string]
		$numa5,
		# NUMA topology.
		[string]
		$numa6,
		# NUMA topology.
		[string]
		$numa7,
		# NUMA topology.
		[string]
		$numa8,
		# NUMA topology.
		[string]
		$numa9,
		# NUMA topology.
		[string]
		$numa10,
		# Specifies whether a VM will be started during system bootup.
		[switch]
		$onboot,
		# Specify guest operating system.
		[string]
		$ostype,
		# Map host parallel devices (n is 0 to 2).
		[string]
		$parallel0,
		# Map host parallel devices (n is 0 to 2).
		[string]
		$parallel1,
		# Map host parallel devices (n is 0 to 2).
		[string]
		$parallel2,
		# Sets the protection flag of the VM. This will disable the remove VM and remove disk operations.
		[switch]
		$protection,
		# Allow reboot. If set to '0' the VM exit on reboot.
		[switch]
		$reboot,
		# Revert a pending change.
		[string]
		$revert,
		# Configure a VirtIO-based Random Number Generator.
		[string]
		$rng0,
		# Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$sata0,
		# Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$sata1,
		# Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$sata2,
		# Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$sata3,
		# Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$sata4,
		# Use volume as SATA hard disk or CD-ROM (n is 0 to 5). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$sata5,
		# SCSI controller model
		[string]
		$scsihw,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi0,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi1,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi2,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi3,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi4,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi5,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi6,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi7,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi8,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi9,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi10,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi11,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi12,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi13,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi14,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi15,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi16,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi17,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi18,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi19,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi20,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi21,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi22,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi23,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi24,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi25,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi26,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi27,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi28,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi29,
		# Use volume as SCSI hard disk or CD-ROM (n is 0 to 30). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$scsi30,
		# cloud-init: Sets DNS search domains for a container. Create will'
		[string]
		$searchdomain,
		# Create a serial device inside the VM (n is 0 to 3)
		[string]
		$serial0,
		# Create a serial device inside the VM (n is 0 to 3)
		[string]
		$serial1,
		# Create a serial device inside the VM (n is 0 to 3)
		[string]
		$serial2,
		# Create a serial device inside the VM (n is 0 to 3)
		[string]
		$serial3,
		# Amount of memory shares for auto-ballooning. The larger the number is, the more memory this VM gets. Number is relative to weights of all other running VMs. Using zero disables auto-ballooning. Auto-ballooning is done by pvestatd.
		[integer]
		$shares,
		# Ignore locks - only root is allowed to use this option.
		[switch]
		$skiplock,
		# Specify SMBIOS type 1 fields.
		[string]
		$smbios1,
		# The number of CPUs. Please use option -sockets instead.
		[integer]
		$smp,
		# The number of CPU sockets.
		[integer]
		$sockets,
		# Configure additional enhancements for SPICE.
		[string]
		$spice_enhancements,
		# cloud-init: Setup public SSH keys (one key per line, OpenSSH format).
		[string]
		$sshkeys,
		# Set the initial date of the real time clock. Valid format for date are:'now' or '2006-06-17T16:01:21' or '2006-06-17'.
		[string]
		$startdate,
		# Startup and shutdown behavior. Order is a non-negative number defining the general startup order. Shutdown in done with reverse ordering. Additionally you can set the 'up' or 'down' delay in seconds, which specifies a delay to wait before the next VM is started or stopped.
		[string]
		$startup,
		# Enable/disable the USB tablet device.
		[switch]
		$tablet,
		# Tags of the VM. This is only meta information.
		[string]
		$tags,
		# Enable/disable time drift fix.
		[switch]
		$tdf,
		# Enable/disable Template.
		[switch]
		$template,
		# Configure a Disk for storing TPM state. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume. Note that SIZE_IN_GiB is ignored here and that the default size of 4 MiB will always be used instead. The format is also fixed to 'raw'.
		[string]
		$tpmstate0,
		# Configure an USB device (n is 0 to 4).
		[string]
		$usb0,
		# Configure an USB device (n is 0 to 4).
		[string]
		$usb1,
		# Configure an USB device (n is 0 to 4).
		[string]
		$usb2,
		# Configure an USB device (n is 0 to 4).
		[string]
		$usb3,
		# Configure an USB device (n is 0 to 4).
		[string]
		$usb4,
		# Number of hotplugged vcpus.
		[integer]
		$vcpus,
		# Configure the VGA hardware.
		[string]
		$vga,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio0,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio1,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio2,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio3,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio4,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio5,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio6,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio7,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio8,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio9,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio10,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio11,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio12,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio13,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio14,
		# Use volume as VIRTIO hard disk (n is 0 to 15). Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$virtio15,
		# Set VM Generation ID. Use '1' to autogenerate on create or update, pass '0' to disable explicitly.
		[string]
		$vmgenid,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid,
		# Default storage for VM state volumes/files.
		[string]
		$vmstatestorage,
		# Create a virtual hardware watchdog device.
		[string]
		$watchdog
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($acpi) { $Options.Add('acpi', $acpi) }
	if ($agent -and -not [String]::IsNullOrEmpty($agent) -and -not [String]::IsNullOrWhiteSpace($agent)) { $Options.Add('agent', $agent) }
	if ($arch -and -not [String]::IsNullOrEmpty($arch) -and -not [String]::IsNullOrWhiteSpace($arch)) { $Options.Add('arch', $arch) }
	if ($AudioArgs -and -not [String]::IsNullOrEmpty($AudioArgs) -and -not [String]::IsNullOrWhiteSpace($AudioArgs)) { $Options.Add('args', $AudioArgs) }
	if ($audio0 -and -not [String]::IsNullOrEmpty($audio0) -and -not [String]::IsNullOrWhiteSpace($audio0)) { $Options.Add('audio0', $audio0) }
	if ($autostart) { $Options.Add('autostart', $autostart) }
	if ($balloon -and -not [String]::IsNullOrEmpty($balloon) -and -not [String]::IsNullOrWhiteSpace($balloon)) { $Options.Add('balloon', $balloon) }
	if ($bios -and -not [String]::IsNullOrEmpty($bios) -and -not [String]::IsNullOrWhiteSpace($bios)) { $Options.Add('bios', $bios) }
	if ($boot -and -not [String]::IsNullOrEmpty($boot) -and -not [String]::IsNullOrWhiteSpace($boot)) { $Options.Add('boot', $boot) }
	if ($bootdisk -and -not [String]::IsNullOrEmpty($bootdisk) -and -not [String]::IsNullOrWhiteSpace($bootdisk)) { $Options.Add('bootdisk', $bootdisk) }
	if ($cdrom -and -not [String]::IsNullOrEmpty($cdrom) -and -not [String]::IsNullOrWhiteSpace($cdrom)) { $Options.Add('cdrom', $cdrom) }
	if ($cicustom -and -not [String]::IsNullOrEmpty($cicustom) -and -not [String]::IsNullOrWhiteSpace($cicustom)) { $Options.Add('cicustom', $cicustom) }
	if ($cipassword) { $Options.Add('cipassword', $($cipassword | ConvertFrom-SecureString -AsPlainText)) }
	if ($citype -and -not [String]::IsNullOrEmpty($citype) -and -not [String]::IsNullOrWhiteSpace($citype)) { $Options.Add('citype', $citype) }
	if ($ciuser -and -not [String]::IsNullOrEmpty($ciuser) -and -not [String]::IsNullOrWhiteSpace($ciuser)) { $Options.Add('ciuser', $ciuser) }
	if ($cores -and -not [String]::IsNullOrEmpty($cores) -and -not [String]::IsNullOrWhiteSpace($cores)) { $Options.Add('cores', $cores) }
	if ($cpu -and -not [String]::IsNullOrEmpty($cpu) -and -not [String]::IsNullOrWhiteSpace($cpu)) { $Options.Add('cpu', $cpu) }
	if ($cpulimit -and -not [String]::IsNullOrEmpty($cpulimit) -and -not [String]::IsNullOrWhiteSpace($cpulimit)) { $Options.Add('cpulimit', $cpulimit) }
	if ($cpuunits -and -not [String]::IsNullOrEmpty($cpuunits) -and -not [String]::IsNullOrWhiteSpace($cpuunits)) { $Options.Add('cpuunits', $cpuunits) }
	if ($delete -and -not [String]::IsNullOrEmpty($delete) -and -not [String]::IsNullOrWhiteSpace($delete)) { $Options.Add('delete', $delete) }
	if ($description -and -not [String]::IsNullOrEmpty($description) -and -not [String]::IsNullOrWhiteSpace($description)) { $Options.Add('description', $description) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($efidisk0 -and -not [String]::IsNullOrEmpty($efidisk0) -and -not [String]::IsNullOrWhiteSpace($efidisk0)) { $Options.Add('efidisk0', $efidisk0) }
	if ($force) { $Options.Add('force', $force) }
	if ($freeze) { $Options.Add('freeze', $freeze) }
	if ($hookscript -and -not [String]::IsNullOrEmpty($hookscript) -and -not [String]::IsNullOrWhiteSpace($hookscript)) { $Options.Add('hookscript', $hookscript) }
	if ($hostpci0 -and -not [String]::IsNullOrEmpty($hostpci0) -and -not [String]::IsNullOrWhiteSpace($hostpci0)) { $Options.Add('hostpci0', $hostpci0) }
	if ($hostpci1 -and -not [String]::IsNullOrEmpty($hostpci1) -and -not [String]::IsNullOrWhiteSpace($hostpci1)) { $Options.Add('hostpci1', $hostpci1) }
	if ($hostpci2 -and -not [String]::IsNullOrEmpty($hostpci2) -and -not [String]::IsNullOrWhiteSpace($hostpci2)) { $Options.Add('hostpci2', $hostpci2) }
	if ($hostpci3 -and -not [String]::IsNullOrEmpty($hostpci3) -and -not [String]::IsNullOrWhiteSpace($hostpci3)) { $Options.Add('hostpci3', $hostpci3) }
	if ($hostpci4 -and -not [String]::IsNullOrEmpty($hostpci4) -and -not [String]::IsNullOrWhiteSpace($hostpci4)) { $Options.Add('hostpci4', $hostpci4) }
	if ($hostpci5 -and -not [String]::IsNullOrEmpty($hostpci5) -and -not [String]::IsNullOrWhiteSpace($hostpci5)) { $Options.Add('hostpci5', $hostpci5) }
	if ($hostpci6 -and -not [String]::IsNullOrEmpty($hostpci6) -and -not [String]::IsNullOrWhiteSpace($hostpci6)) { $Options.Add('hostpci6', $hostpci6) }
	if ($hostpci7 -and -not [String]::IsNullOrEmpty($hostpci7) -and -not [String]::IsNullOrWhiteSpace($hostpci7)) { $Options.Add('hostpci7', $hostpci7) }
	if ($hostpci8 -and -not [String]::IsNullOrEmpty($hostpci8) -and -not [String]::IsNullOrWhiteSpace($hostpci8)) { $Options.Add('hostpci8', $hostpci8) }
	if ($hostpci9 -and -not [String]::IsNullOrEmpty($hostpci9) -and -not [String]::IsNullOrWhiteSpace($hostpci9)) { $Options.Add('hostpci9', $hostpci9) }
	if ($hostpci10 -and -not [String]::IsNullOrEmpty($hostpci10) -and -not [String]::IsNullOrWhiteSpace($hostpci10)) { $Options.Add('hostpci10', $hostpci10) }
	if ($hotplug -and -not [String]::IsNullOrEmpty($hotplug) -and -not [String]::IsNullOrWhiteSpace($hotplug)) { $Options.Add('hotplug', $hotplug) }
	if ($hugepages -and -not [String]::IsNullOrEmpty($hugepages) -and -not [String]::IsNullOrWhiteSpace($hugepages)) { $Options.Add('hugepages', $hugepages) }
	if ($ide0 -and -not [String]::IsNullOrEmpty($ide0) -and -not [String]::IsNullOrWhiteSpace($ide0)) { $Options.Add('ide0', $ide0) }
	if ($ide1 -and -not [String]::IsNullOrEmpty($ide1) -and -not [String]::IsNullOrWhiteSpace($ide1)) { $Options.Add('ide1', $ide1) }
	if ($ide2 -and -not [String]::IsNullOrEmpty($ide2) -and -not [String]::IsNullOrWhiteSpace($ide2)) { $Options.Add('ide2', $ide2) }
	if ($ide3 -and -not [String]::IsNullOrEmpty($ide3) -and -not [String]::IsNullOrWhiteSpace($ide3)) { $Options.Add('ide3', $ide3) }
	if ($ipconfig0 -and -not [String]::IsNullOrEmpty($ipconfig0) -and -not [String]::IsNullOrWhiteSpace($ipconfig0)) { $Options.Add('ipconfig0', $ipconfig0) }
	if ($ipconfig1 -and -not [String]::IsNullOrEmpty($ipconfig1) -and -not [String]::IsNullOrWhiteSpace($ipconfig1)) { $Options.Add('ipconfig1', $ipconfig1) }
	if ($ipconfig2 -and -not [String]::IsNullOrEmpty($ipconfig2) -and -not [String]::IsNullOrWhiteSpace($ipconfig2)) { $Options.Add('ipconfig2', $ipconfig2) }
	if ($ipconfig3 -and -not [String]::IsNullOrEmpty($ipconfig3) -and -not [String]::IsNullOrWhiteSpace($ipconfig3)) { $Options.Add('ipconfig3', $ipconfig3) }
	if ($ipconfig4 -and -not [String]::IsNullOrEmpty($ipconfig4) -and -not [String]::IsNullOrWhiteSpace($ipconfig4)) { $Options.Add('ipconfig4', $ipconfig4) }
	if ($ipconfig5 -and -not [String]::IsNullOrEmpty($ipconfig5) -and -not [String]::IsNullOrWhiteSpace($ipconfig5)) { $Options.Add('ipconfig5', $ipconfig5) }
	if ($ipconfig6 -and -not [String]::IsNullOrEmpty($ipconfig6) -and -not [String]::IsNullOrWhiteSpace($ipconfig6)) { $Options.Add('ipconfig6', $ipconfig6) }
	if ($ipconfig7 -and -not [String]::IsNullOrEmpty($ipconfig7) -and -not [String]::IsNullOrWhiteSpace($ipconfig7)) { $Options.Add('ipconfig7', $ipconfig7) }
	if ($ipconfig8 -and -not [String]::IsNullOrEmpty($ipconfig8) -and -not [String]::IsNullOrWhiteSpace($ipconfig8)) { $Options.Add('ipconfig8', $ipconfig8) }
	if ($ipconfig9 -and -not [String]::IsNullOrEmpty($ipconfig9) -and -not [String]::IsNullOrWhiteSpace($ipconfig9)) { $Options.Add('ipconfig9', $ipconfig9) }
	if ($ipconfig10 -and -not [String]::IsNullOrEmpty($ipconfig10) -and -not [String]::IsNullOrWhiteSpace($ipconfig10)) { $Options.Add('ipconfig10', $ipconfig10) }
	if ($ivshmem -and -not [String]::IsNullOrEmpty($ivshmem) -and -not [String]::IsNullOrWhiteSpace($ivshmem)) { $Options.Add('ivshmem', $ivshmem) }
	if ($keephugepages) { $Options.Add('keephugepages', $keephugepages) }
	if ($keyboard -and -not [String]::IsNullOrEmpty($keyboard) -and -not [String]::IsNullOrWhiteSpace($keyboard)) { $Options.Add('keyboard', $keyboard) }
	if ($kvm) { $Options.Add('kvm', $kvm) }
	if ($localtime) { $Options.Add('localtime', $localtime) }
	if ($lock -and -not [String]::IsNullOrEmpty($lock) -and -not [String]::IsNullOrWhiteSpace($lock)) { $Options.Add('lock', $lock) }
	if ($machine -and -not [String]::IsNullOrEmpty($machine) -and -not [String]::IsNullOrWhiteSpace($machine)) { $Options.Add('machine', $machine) }
	if ($memory -and -not [String]::IsNullOrEmpty($memory) -and -not [String]::IsNullOrWhiteSpace($memory)) { $Options.Add('memory', $memory) }
	if ($migrate_downtime -and -not [String]::IsNullOrEmpty($migrate_downtime) -and -not [String]::IsNullOrWhiteSpace($migrate_downtime)) { $Options.Add('migrate_downtime', $migrate_downtime) }
	if ($migrate_speed -and -not [String]::IsNullOrEmpty($migrate_speed) -and -not [String]::IsNullOrWhiteSpace($migrate_speed)) { $Options.Add('migrate_speed', $migrate_speed) }
	if ($name -and -not [String]::IsNullOrEmpty($name) -and -not [String]::IsNullOrWhiteSpace($name)) { $Options.Add('name', $name) }
	if ($nameserver -and -not [String]::IsNullOrEmpty($nameserver) -and -not [String]::IsNullOrWhiteSpace($nameserver)) { $Options.Add('nameserver', $nameserver) }
	if ($net0 -and -not [String]::IsNullOrEmpty($net0) -and -not [String]::IsNullOrWhiteSpace($net0)) { $Options.Add('net0', $net0) }
	if ($net1 -and -not [String]::IsNullOrEmpty($net1) -and -not [String]::IsNullOrWhiteSpace($net1)) { $Options.Add('net1', $net1) }
	if ($net2 -and -not [String]::IsNullOrEmpty($net2) -and -not [String]::IsNullOrWhiteSpace($net2)) { $Options.Add('net2', $net2) }
	if ($net3 -and -not [String]::IsNullOrEmpty($net3) -and -not [String]::IsNullOrWhiteSpace($net3)) { $Options.Add('net3', $net3) }
	if ($net4 -and -not [String]::IsNullOrEmpty($net4) -and -not [String]::IsNullOrWhiteSpace($net4)) { $Options.Add('net4', $net4) }
	if ($net5 -and -not [String]::IsNullOrEmpty($net5) -and -not [String]::IsNullOrWhiteSpace($net5)) { $Options.Add('net5', $net5) }
	if ($net6 -and -not [String]::IsNullOrEmpty($net6) -and -not [String]::IsNullOrWhiteSpace($net6)) { $Options.Add('net6', $net6) }
	if ($net7 -and -not [String]::IsNullOrEmpty($net7) -and -not [String]::IsNullOrWhiteSpace($net7)) { $Options.Add('net7', $net7) }
	if ($net8 -and -not [String]::IsNullOrEmpty($net8) -and -not [String]::IsNullOrWhiteSpace($net8)) { $Options.Add('net8', $net8) }
	if ($net9 -and -not [String]::IsNullOrEmpty($net9) -and -not [String]::IsNullOrWhiteSpace($net9)) { $Options.Add('net9', $net9) }
	if ($net10 -and -not [String]::IsNullOrEmpty($net10) -and -not [String]::IsNullOrWhiteSpace($net10)) { $Options.Add('net10', $net10) }
	if ($numa) { $Options.Add('numa', $numa) }
	if ($numa0 -and -not [String]::IsNullOrEmpty($numa0) -and -not [String]::IsNullOrWhiteSpace($numa0)) { $Options.Add('numa0', $numa0) }
	if ($numa1 -and -not [String]::IsNullOrEmpty($numa1) -and -not [String]::IsNullOrWhiteSpace($numa1)) { $Options.Add('numa1', $numa1) }
	if ($numa2 -and -not [String]::IsNullOrEmpty($numa2) -and -not [String]::IsNullOrWhiteSpace($numa2)) { $Options.Add('numa2', $numa2) }
	if ($numa3 -and -not [String]::IsNullOrEmpty($numa3) -and -not [String]::IsNullOrWhiteSpace($numa3)) { $Options.Add('numa3', $numa3) }
	if ($numa4 -and -not [String]::IsNullOrEmpty($numa4) -and -not [String]::IsNullOrWhiteSpace($numa4)) { $Options.Add('numa4', $numa4) }
	if ($numa5 -and -not [String]::IsNullOrEmpty($numa5) -and -not [String]::IsNullOrWhiteSpace($numa5)) { $Options.Add('numa5', $numa5) }
	if ($numa6 -and -not [String]::IsNullOrEmpty($numa6) -and -not [String]::IsNullOrWhiteSpace($numa6)) { $Options.Add('numa6', $numa6) }
	if ($numa7 -and -not [String]::IsNullOrEmpty($numa7) -and -not [String]::IsNullOrWhiteSpace($numa7)) { $Options.Add('numa7', $numa7) }
	if ($numa8 -and -not [String]::IsNullOrEmpty($numa8) -and -not [String]::IsNullOrWhiteSpace($numa8)) { $Options.Add('numa8', $numa8) }
	if ($numa9 -and -not [String]::IsNullOrEmpty($numa9) -and -not [String]::IsNullOrWhiteSpace($numa9)) { $Options.Add('numa9', $numa9) }
	if ($numa10 -and -not [String]::IsNullOrEmpty($numa10) -and -not [String]::IsNullOrWhiteSpace($numa10)) { $Options.Add('numa10', $numa10) }
	if ($onboot) { $Options.Add('onboot', $onboot) }
	if ($ostype -and -not [String]::IsNullOrEmpty($ostype) -and -not [String]::IsNullOrWhiteSpace($ostype)) { $Options.Add('ostype', $ostype) }
	if ($parallel0 -and -not [String]::IsNullOrEmpty($parallel0) -and -not [String]::IsNullOrWhiteSpace($parallel0)) { $Options.Add('parallel0', $parallel0) }
	if ($parallel1 -and -not [String]::IsNullOrEmpty($parallel1) -and -not [String]::IsNullOrWhiteSpace($parallel1)) { $Options.Add('parallel1', $parallel1) }
	if ($parallel2 -and -not [String]::IsNullOrEmpty($parallel2) -and -not [String]::IsNullOrWhiteSpace($parallel2)) { $Options.Add('parallel2', $parallel2) }
	if ($protection) { $Options.Add('protection', $protection) }
	if ($reboot) { $Options.Add('reboot', $reboot) }
	if ($revert -and -not [String]::IsNullOrEmpty($revert) -and -not [String]::IsNullOrWhiteSpace($revert)) { $Options.Add('revert', $revert) }
	if ($rng0 -and -not [String]::IsNullOrEmpty($rng0) -and -not [String]::IsNullOrWhiteSpace($rng0)) { $Options.Add('rng0', $rng0) }
	if ($sata0 -and -not [String]::IsNullOrEmpty($sata0) -and -not [String]::IsNullOrWhiteSpace($sata0)) { $Options.Add('sata0', $sata0) }
	if ($sata1 -and -not [String]::IsNullOrEmpty($sata1) -and -not [String]::IsNullOrWhiteSpace($sata1)) { $Options.Add('sata1', $sata1) }
	if ($sata2 -and -not [String]::IsNullOrEmpty($sata2) -and -not [String]::IsNullOrWhiteSpace($sata2)) { $Options.Add('sata2', $sata2) }
	if ($sata3 -and -not [String]::IsNullOrEmpty($sata3) -and -not [String]::IsNullOrWhiteSpace($sata3)) { $Options.Add('sata3', $sata3) }
	if ($sata4 -and -not [String]::IsNullOrEmpty($sata4) -and -not [String]::IsNullOrWhiteSpace($sata4)) { $Options.Add('sata4', $sata4) }
	if ($sata5 -and -not [String]::IsNullOrEmpty($sata5) -and -not [String]::IsNullOrWhiteSpace($sata5)) { $Options.Add('sata5', $sata5) }
	if ($scsihw -and -not [String]::IsNullOrEmpty($scsihw) -and -not [String]::IsNullOrWhiteSpace($scsihw)) { $Options.Add('scsihw', $scsihw) }
	if ($scsi0 -and -not [String]::IsNullOrEmpty($scsi0) -and -not [String]::IsNullOrWhiteSpace($scsi0)) { $Options.Add('scsi0', $scsi0) }
	if ($scsi1 -and -not [String]::IsNullOrEmpty($scsi1) -and -not [String]::IsNullOrWhiteSpace($scsi1)) { $Options.Add('scsi1', $scsi1) }
	if ($scsi2 -and -not [String]::IsNullOrEmpty($scsi2) -and -not [String]::IsNullOrWhiteSpace($scsi2)) { $Options.Add('scsi2', $scsi2) }
	if ($scsi3 -and -not [String]::IsNullOrEmpty($scsi3) -and -not [String]::IsNullOrWhiteSpace($scsi3)) { $Options.Add('scsi3', $scsi3) }
	if ($scsi4 -and -not [String]::IsNullOrEmpty($scsi4) -and -not [String]::IsNullOrWhiteSpace($scsi4)) { $Options.Add('scsi4', $scsi4) }
	if ($scsi5 -and -not [String]::IsNullOrEmpty($scsi5) -and -not [String]::IsNullOrWhiteSpace($scsi5)) { $Options.Add('scsi5', $scsi5) }
	if ($scsi6 -and -not [String]::IsNullOrEmpty($scsi6) -and -not [String]::IsNullOrWhiteSpace($scsi6)) { $Options.Add('scsi6', $scsi6) }
	if ($scsi7 -and -not [String]::IsNullOrEmpty($scsi7) -and -not [String]::IsNullOrWhiteSpace($scsi7)) { $Options.Add('scsi7', $scsi7) }
	if ($scsi8 -and -not [String]::IsNullOrEmpty($scsi8) -and -not [String]::IsNullOrWhiteSpace($scsi8)) { $Options.Add('scsi8', $scsi8) }
	if ($scsi9 -and -not [String]::IsNullOrEmpty($scsi9) -and -not [String]::IsNullOrWhiteSpace($scsi9)) { $Options.Add('scsi9', $scsi9) }
	if ($scsi10 -and -not [String]::IsNullOrEmpty($scsi10) -and -not [String]::IsNullOrWhiteSpace($scsi10)) { $Options.Add('scsi10', $scsi10) }
	if ($scsi11 -and -not [String]::IsNullOrEmpty($scsi11) -and -not [String]::IsNullOrWhiteSpace($scsi11)) { $Options.Add('scsi11', $scsi11) }
	if ($scsi12 -and -not [String]::IsNullOrEmpty($scsi12) -and -not [String]::IsNullOrWhiteSpace($scsi12)) { $Options.Add('scsi12', $scsi12) }
	if ($scsi13 -and -not [String]::IsNullOrEmpty($scsi13) -and -not [String]::IsNullOrWhiteSpace($scsi13)) { $Options.Add('scsi13', $scsi13) }
	if ($scsi14 -and -not [String]::IsNullOrEmpty($scsi14) -and -not [String]::IsNullOrWhiteSpace($scsi14)) { $Options.Add('scsi14', $scsi14) }
	if ($scsi15 -and -not [String]::IsNullOrEmpty($scsi15) -and -not [String]::IsNullOrWhiteSpace($scsi15)) { $Options.Add('scsi15', $scsi15) }
	if ($scsi16 -and -not [String]::IsNullOrEmpty($scsi16) -and -not [String]::IsNullOrWhiteSpace($scsi16)) { $Options.Add('scsi16', $scsi16) }
	if ($scsi17 -and -not [String]::IsNullOrEmpty($scsi17) -and -not [String]::IsNullOrWhiteSpace($scsi17)) { $Options.Add('scsi17', $scsi17) }
	if ($scsi18 -and -not [String]::IsNullOrEmpty($scsi18) -and -not [String]::IsNullOrWhiteSpace($scsi18)) { $Options.Add('scsi18', $scsi18) }
	if ($scsi19 -and -not [String]::IsNullOrEmpty($scsi19) -and -not [String]::IsNullOrWhiteSpace($scsi19)) { $Options.Add('scsi19', $scsi19) }
	if ($scsi20 -and -not [String]::IsNullOrEmpty($scsi20) -and -not [String]::IsNullOrWhiteSpace($scsi20)) { $Options.Add('scsi20', $scsi20) }
	if ($scsi21 -and -not [String]::IsNullOrEmpty($scsi21) -and -not [String]::IsNullOrWhiteSpace($scsi21)) { $Options.Add('scsi21', $scsi21) }
	if ($scsi22 -and -not [String]::IsNullOrEmpty($scsi22) -and -not [String]::IsNullOrWhiteSpace($scsi22)) { $Options.Add('scsi22', $scsi22) }
	if ($scsi23 -and -not [String]::IsNullOrEmpty($scsi23) -and -not [String]::IsNullOrWhiteSpace($scsi23)) { $Options.Add('scsi23', $scsi23) }
	if ($scsi24 -and -not [String]::IsNullOrEmpty($scsi24) -and -not [String]::IsNullOrWhiteSpace($scsi24)) { $Options.Add('scsi24', $scsi24) }
	if ($scsi25 -and -not [String]::IsNullOrEmpty($scsi25) -and -not [String]::IsNullOrWhiteSpace($scsi25)) { $Options.Add('scsi25', $scsi25) }
	if ($scsi26 -and -not [String]::IsNullOrEmpty($scsi26) -and -not [String]::IsNullOrWhiteSpace($scsi26)) { $Options.Add('scsi26', $scsi26) }
	if ($scsi27 -and -not [String]::IsNullOrEmpty($scsi27) -and -not [String]::IsNullOrWhiteSpace($scsi27)) { $Options.Add('scsi27', $scsi27) }
	if ($scsi28 -and -not [String]::IsNullOrEmpty($scsi28) -and -not [String]::IsNullOrWhiteSpace($scsi28)) { $Options.Add('scsi28', $scsi28) }
	if ($scsi29 -and -not [String]::IsNullOrEmpty($scsi29) -and -not [String]::IsNullOrWhiteSpace($scsi29)) { $Options.Add('scsi29', $scsi29) }
	if ($scsi30 -and -not [String]::IsNullOrEmpty($scsi30) -and -not [String]::IsNullOrWhiteSpace($scsi30)) { $Options.Add('scsi30', $scsi30) }
	if ($searchdomain -and -not [String]::IsNullOrEmpty($searchdomain) -and -not [String]::IsNullOrWhiteSpace($searchdomain)) { $Options.Add('searchdomain', $searchdomain) }
	if ($serial0 -and -not [String]::IsNullOrEmpty($serial0) -and -not [String]::IsNullOrWhiteSpace($serial0)) { $Options.Add('serial0', $serial0) }
	if ($serial1 -and -not [String]::IsNullOrEmpty($serial1) -and -not [String]::IsNullOrWhiteSpace($serial1)) { $Options.Add('serial1', $serial1) }
	if ($serial2 -and -not [String]::IsNullOrEmpty($serial2) -and -not [String]::IsNullOrWhiteSpace($serial2)) { $Options.Add('serial2', $serial2) }
	if ($serial3 -and -not [String]::IsNullOrEmpty($serial3) -and -not [String]::IsNullOrWhiteSpace($serial3)) { $Options.Add('serial3', $serial3) }
	if ($shares -and -not [String]::IsNullOrEmpty($shares) -and -not [String]::IsNullOrWhiteSpace($shares)) { $Options.Add('shares', $shares) }
	if ($skiplock) { $Options.Add('skiplock', $skiplock) }
	if ($smbios1 -and -not [String]::IsNullOrEmpty($smbios1) -and -not [String]::IsNullOrWhiteSpace($smbios1)) { $Options.Add('smbios1', $smbios1) }
	if ($smp -and -not [String]::IsNullOrEmpty($smp) -and -not [String]::IsNullOrWhiteSpace($smp)) { $Options.Add('smp', $smp) }
	if ($sockets -and -not [String]::IsNullOrEmpty($sockets) -and -not [String]::IsNullOrWhiteSpace($sockets)) { $Options.Add('sockets', $sockets) }
	if ($spice_enhancements -and -not [String]::IsNullOrEmpty($spice_enhancements) -and -not [String]::IsNullOrWhiteSpace($spice_enhancements)) { $Options.Add('spice_enhancements', $spice_enhancements) }
	if ($sshkeys -and -not [String]::IsNullOrEmpty($sshkeys) -and -not [String]::IsNullOrWhiteSpace($sshkeys)) { $Options.Add('sshkeys', $sshkeys) }
	if ($startdate -and -not [String]::IsNullOrEmpty($startdate) -and -not [String]::IsNullOrWhiteSpace($startdate)) { $Options.Add('startdate', $startdate) }
	if ($startup -and -not [String]::IsNullOrEmpty($startup) -and -not [String]::IsNullOrWhiteSpace($startup)) { $Options.Add('startup', $startup) }
	if ($tablet) { $Options.Add('tablet', $tablet) }
	if ($tags -and -not [String]::IsNullOrEmpty($tags) -and -not [String]::IsNullOrWhiteSpace($tags)) { $Options.Add('tags', $tags) }
	if ($tdf) { $Options.Add('tdf', $tdf) }
	if ($template) { $Options.Add('template', $template) }
	if ($tpmstate0 -and -not [String]::IsNullOrEmpty($tpmstate0) -and -not [String]::IsNullOrWhiteSpace($tpmstate0)) { $Options.Add('tpmstate0', $tpmstate0) }
	if ($usb0 -and -not [String]::IsNullOrEmpty($usb0) -and -not [String]::IsNullOrWhiteSpace($usb0)) { $Options.Add('usb0', $usb0) }
	if ($usb1 -and -not [String]::IsNullOrEmpty($usb1) -and -not [String]::IsNullOrWhiteSpace($usb1)) { $Options.Add('usb1', $usb1) }
	if ($usb2 -and -not [String]::IsNullOrEmpty($usb2) -and -not [String]::IsNullOrWhiteSpace($usb2)) { $Options.Add('usb2', $usb2) }
	if ($usb3 -and -not [String]::IsNullOrEmpty($usb3) -and -not [String]::IsNullOrWhiteSpace($usb3)) { $Options.Add('usb3', $usb3) }
	if ($usb4 -and -not [String]::IsNullOrEmpty($usb4) -and -not [String]::IsNullOrWhiteSpace($usb4)) { $Options.Add('usb4', $usb4) }
	if ($vcpus -and -not [String]::IsNullOrEmpty($vcpus) -and -not [String]::IsNullOrWhiteSpace($vcpus)) { $Options.Add('vcpus', $vcpus) }
	if ($vga -and -not [String]::IsNullOrEmpty($vga) -and -not [String]::IsNullOrWhiteSpace($vga)) { $Options.Add('vga', $vga) }
	if ($virtio0 -and -not [String]::IsNullOrEmpty($virtio0) -and -not [String]::IsNullOrWhiteSpace($virtio0)) { $Options.Add('virtio0', $virtio0) }
	if ($virtio1 -and -not [String]::IsNullOrEmpty($virtio1) -and -not [String]::IsNullOrWhiteSpace($virtio1)) { $Options.Add('virtio1', $virtio1) }
	if ($virtio2 -and -not [String]::IsNullOrEmpty($virtio2) -and -not [String]::IsNullOrWhiteSpace($virtio2)) { $Options.Add('virtio2', $virtio2) }
	if ($virtio3 -and -not [String]::IsNullOrEmpty($virtio3) -and -not [String]::IsNullOrWhiteSpace($virtio3)) { $Options.Add('virtio3', $virtio3) }
	if ($virtio4 -and -not [String]::IsNullOrEmpty($virtio4) -and -not [String]::IsNullOrWhiteSpace($virtio4)) { $Options.Add('virtio4', $virtio4) }
	if ($virtio5 -and -not [String]::IsNullOrEmpty($virtio5) -and -not [String]::IsNullOrWhiteSpace($virtio5)) { $Options.Add('virtio5', $virtio5) }
	if ($virtio6 -and -not [String]::IsNullOrEmpty($virtio6) -and -not [String]::IsNullOrWhiteSpace($virtio6)) { $Options.Add('virtio6', $virtio6) }
	if ($virtio7 -and -not [String]::IsNullOrEmpty($virtio7) -and -not [String]::IsNullOrWhiteSpace($virtio7)) { $Options.Add('virtio7', $virtio7) }
	if ($virtio8 -and -not [String]::IsNullOrEmpty($virtio8) -and -not [String]::IsNullOrWhiteSpace($virtio8)) { $Options.Add('virtio8', $virtio8) }
	if ($virtio9 -and -not [String]::IsNullOrEmpty($virtio9) -and -not [String]::IsNullOrWhiteSpace($virtio9)) { $Options.Add('virtio9', $virtio9) }
	if ($virtio10 -and -not [String]::IsNullOrEmpty($virtio10) -and -not [String]::IsNullOrWhiteSpace($virtio10)) { $Options.Add('virtio10', $virtio10) }
	if ($virtio11 -and -not [String]::IsNullOrEmpty($virtio11) -and -not [String]::IsNullOrWhiteSpace($virtio11)) { $Options.Add('virtio11', $virtio11) }
	if ($virtio12 -and -not [String]::IsNullOrEmpty($virtio12) -and -not [String]::IsNullOrWhiteSpace($virtio12)) { $Options.Add('virtio12', $virtio12) }
	if ($virtio13 -and -not [String]::IsNullOrEmpty($virtio13) -and -not [String]::IsNullOrWhiteSpace($virtio13)) { $Options.Add('virtio13', $virtio13) }
	if ($virtio14 -and -not [String]::IsNullOrEmpty($virtio14) -and -not [String]::IsNullOrWhiteSpace($virtio14)) { $Options.Add('virtio14', $virtio14) }
	if ($virtio15 -and -not [String]::IsNullOrEmpty($virtio15) -and -not [String]::IsNullOrWhiteSpace($virtio15)) { $Options.Add('virtio15', $virtio15) }
	if ($vmgenid -and -not [String]::IsNullOrEmpty($vmgenid) -and -not [String]::IsNullOrWhiteSpace($vmgenid)) { $Options.Add('vmgenid', $vmgenid) }
	if ($vmstatestorage -and -not [String]::IsNullOrEmpty($vmstatestorage) -and -not [String]::IsNullOrWhiteSpace($vmstatestorage)) { $Options.Add('vmstatestorage', $vmstatestorage) }
	if ($watchdog -and -not [String]::IsNullOrEmpty($watchdog) -and -not [String]::IsNullOrWhiteSpace($watchdog)) { $Options.Add('watchdog', $watchdog) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/qemu/{vmid}/config" -Options $Options
}
function Get-NodeQemuFirewallLog {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# 
		[integer]
		$limit,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# 
		[integer]
		$start,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($limit -and -not [String]::IsNullOrEmpty($limit) -and -not [String]::IsNullOrWhiteSpace($limit)) { $Options.Add('limit', $limit) }
	if ($start -and -not [String]::IsNullOrEmpty($start) -and -not [String]::IsNullOrWhiteSpace($start)) { $Options.Add('start', $start) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/firewall/log" -Options $Options
}
function Get-NodeQemuPending {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/pending" -Options $Options
}
function Get-NodeQemuFirewallRefs {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Only list references of specified type.
		[string]
		$type,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($type -and -not [String]::IsNullOrEmpty($type) -and -not [String]::IsNullOrWhiteSpace($type)) { $Options.Add('type', $type) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/firewall/refs" -Options $Options
}
function Set-NodeQemuUnlink {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# A list of disk IDs you want to delete.
		[string]
		$idlist,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('idlist', $idlist)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($force) { $Options.Add('force', $force) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/qemu/{vmid}/unlink" -Options $Options
}
function New-NodeQemuAgentFsfreezeFreeze {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/agent/fsfreeze-freeze" -Options $Options
}
function New-NodeQemuVncproxy {
	[CmdletBinding()]
	param(
		# Generates a random password to be used as ticket instead of the API ticket.
		[switch]
		$generatepassword,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid,
		# starts websockify instead of vncproxy
		[switch]
		$websocket
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($generatepassword) { $Options.Add('generate-password', $generatepassword) }
	if ($websocket) { $Options.Add('websocket', $websocket) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/vncproxy" -Options $Options
}
function New-NodeQemuAgentFsfreezeStatus {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/agent/fsfreeze-status" -Options $Options
}
function New-NodeQemuTermproxy {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# opens a serial terminal (defaults to display)
		[string]
		$serial,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($serial -and -not [String]::IsNullOrEmpty($serial) -and -not [String]::IsNullOrWhiteSpace($serial)) { $Options.Add('serial', $serial) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/termproxy" -Options $Options
}
function New-NodeQemuAgentFsfreezeThaw {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/agent/fsfreeze-thaw" -Options $Options
}
function Get-NodeQemuVncwebsocket {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Port number returned by previous vncproxy call.
		[integer]
		$port,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid,
		[Parameter(Mandatory)]
		# Ticket from previous call to vncproxy.
		[string]
		$vncticket
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('port', $port)
	$Options.Add('vmid', $vmid)
	$Options.Add('vncticket', $vncticket)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/vncwebsocket" -Options $Options
}
function New-NodeQemuAgentFstrim {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/agent/fstrim" -Options $Options
}
function New-NodeQemuSpiceproxy {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# SPICE proxy server. This can be used by the client to specify the proxy server. All nodes in a cluster runs 'spiceproxy', so it is up to the client to choose one. By default, we return the node where the VM is currently running. As reasonable setting is to use same node you use to connect to the API (This is window.location.hostname for the JS GUI).
		[string]
		$proxy,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($proxy -and -not [String]::IsNullOrEmpty($proxy) -and -not [String]::IsNullOrWhiteSpace($proxy)) { $Options.Add('proxy', $proxy) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/spiceproxy" -Options $Options
}
function Get-NodeQemuAgentGetFsinfo {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/agent/get-fsinfo" -Options $Options
}
function Get-NodeQemuStatus {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/status" -Options $Options
}
function Get-NodeQemuAgentGetHostName {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/agent/get-host-name" -Options $Options
}
function Set-NodeQemuSendkey {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# The key (qemu monitor encoding).
		[string]
		$key,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Ignore locks - only root is allowed to use this option.
		[switch]
		$skiplock,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('key', $key)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($skiplock) { $Options.Add('skiplock', $skiplock) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/qemu/{vmid}/sendkey" -Options $Options
}
function Get-NodeQemuAgentGetMemoryBlockInfo {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/agent/get-memory-block-info" -Options $Options
}
function Get-NodeQemuFeature {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# Feature to check.
		[string]
		$feature,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# The name of the snapshot.
		[string]
		$snapname,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('feature', $feature)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($snapname -and -not [String]::IsNullOrEmpty($snapname) -and -not [String]::IsNullOrWhiteSpace($snapname)) { $Options.Add('snapname', $snapname) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/feature" -Options $Options
}
function Get-NodeQemuAgentGetMemoryBlocks {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/agent/get-memory-blocks" -Options $Options
}
function New-NodeQemuClone {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Override I/O bandwidth limit (in KiB/s).
		[integer]
		$bwlimit,
		# Description for the new VM.
		[string]
		$description,
		# Target format for file storage. Only valid for full clone.
		[string]
		$format,
		# Create a full copy of all disks. This is always done when you clone a normal VM. For VM templates, we try to create a linked clone by default.
		[switch]
		$full,
		# Set a name for the new VM.
		[string]
		$name,
		[Parameter(Mandatory)]
		# VMID for the clone.
		[integer]
		$newid,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Add the new VM to the specified pool.
		[string]
		$pool,
		# The name of the snapshot.
		[string]
		$snapname,
		# Target storage for full clone.
		[string]
		$storage,
		# Target node. Only allowed if the original VM is on shared storage.
		[string]
		$target,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('newid', $newid)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($bwlimit -and -not [String]::IsNullOrEmpty($bwlimit) -and -not [String]::IsNullOrWhiteSpace($bwlimit)) { $Options.Add('bwlimit', $bwlimit) }
	if ($description -and -not [String]::IsNullOrEmpty($description) -and -not [String]::IsNullOrWhiteSpace($description)) { $Options.Add('description', $description) }
	if ($format -and -not [String]::IsNullOrEmpty($format) -and -not [String]::IsNullOrWhiteSpace($format)) { $Options.Add('format', $format) }
	if ($full) { $Options.Add('full', $full) }
	if ($name -and -not [String]::IsNullOrEmpty($name) -and -not [String]::IsNullOrWhiteSpace($name)) { $Options.Add('name', $name) }
	if ($pool -and -not [String]::IsNullOrEmpty($pool) -and -not [String]::IsNullOrWhiteSpace($pool)) { $Options.Add('pool', $pool) }
	if ($snapname -and -not [String]::IsNullOrEmpty($snapname) -and -not [String]::IsNullOrWhiteSpace($snapname)) { $Options.Add('snapname', $snapname) }
	if ($storage -and -not [String]::IsNullOrEmpty($storage) -and -not [String]::IsNullOrWhiteSpace($storage)) { $Options.Add('storage', $storage) }
	if ($target -and -not [String]::IsNullOrEmpty($target) -and -not [String]::IsNullOrWhiteSpace($target)) { $Options.Add('target', $target) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/clone" -Options $Options
}
function Get-NodeQemuAgentGetOsinfo {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/agent/get-osinfo" -Options $Options
}
function New-NodeQemuMoveDisk {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Override I/O bandwidth limit (in KiB/s).
		[integer]
		$bwlimit,
		# Delete the original disk after successful copy. By default the original disk is kept as unused disk.
		[switch]
		$delete,
		# Prevent changes if current configuration file has different SHA1"
		[string]
		$digest,
		[Parameter(Mandatory)]
		# The disk you want to move.
		[string]
		$disk,
		# Target Format.
		[string]
		$format,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Target storage.
		[string]
		$storage,
		# Prevent changes if the current config file of the target VM has a"
		[string]
		$targetdigest,
		# The config key the disk will be moved to on the target VM (for example, ide0 or scsi1). Default is the source disk key.
		[string]
		$targetdisk,
		# The (unique) ID of the VM.
		[integer]
		$targetvmid,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('disk', $disk)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($bwlimit -and -not [String]::IsNullOrEmpty($bwlimit) -and -not [String]::IsNullOrWhiteSpace($bwlimit)) { $Options.Add('bwlimit', $bwlimit) }
	if ($delete) { $Options.Add('delete', $delete) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($format -and -not [String]::IsNullOrEmpty($format) -and -not [String]::IsNullOrWhiteSpace($format)) { $Options.Add('format', $format) }
	if ($storage -and -not [String]::IsNullOrEmpty($storage) -and -not [String]::IsNullOrWhiteSpace($storage)) { $Options.Add('storage', $storage) }
	if ($targetdigest -and -not [String]::IsNullOrEmpty($targetdigest) -and -not [String]::IsNullOrWhiteSpace($targetdigest)) { $Options.Add('target-digest', $targetdigest) }
	if ($targetdisk -and -not [String]::IsNullOrEmpty($targetdisk) -and -not [String]::IsNullOrWhiteSpace($targetdisk)) { $Options.Add('target-disk', $targetdisk) }
	if ($targetvmid -and -not [String]::IsNullOrEmpty($targetvmid) -and -not [String]::IsNullOrWhiteSpace($targetvmid)) { $Options.Add('target-vmid', $targetvmid) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/move_disk" -Options $Options
}
function Get-NodeQemuAgentGetTime {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/agent/get-time" -Options $Options
}
function Get-NodeQemuMigrate {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Target node.
		[string]
		$target,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($target -and -not [String]::IsNullOrEmpty($target) -and -not [String]::IsNullOrWhiteSpace($target)) { $Options.Add('target', $target) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/migrate" -Options $Options
}
function New-NodeQemuMigrate {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Override I/O bandwidth limit (in KiB/s).
		[integer]
		$bwlimit,
		# CIDR of the (sub) network that is used for migration.
		[string]
		$migration_network,
		# Migration traffic is encrypted using an SSH tunnel by default. On secure, completely private networks this can be disabled to increase performance.
		[string]
		$migration_type,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Use online/live migration if VM is running. Ignored if VM is stopped.
		[switch]
		$online,
		[Parameter(Mandatory)]
		# Target node.
		[string]
		$target,
		# Mapping from source to target storages. Providing only a single storage ID maps all source storages to that storage. Providing the special value '1' will map each source storage to itself.
		[string]
		$targetstorage,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid,
		# Enable live storage migration for local disk
		[switch]
		$withlocaldisks
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('target', $target)
	$Options.Add('vmid', $vmid)
	if ($bwlimit -and -not [String]::IsNullOrEmpty($bwlimit) -and -not [String]::IsNullOrWhiteSpace($bwlimit)) { $Options.Add('bwlimit', $bwlimit) }
	if ($force) { $Options.Add('force', $force) }
	if ($migration_network -and -not [String]::IsNullOrEmpty($migration_network) -and -not [String]::IsNullOrWhiteSpace($migration_network)) { $Options.Add('migration_network', $migration_network) }
	if ($migration_type -and -not [String]::IsNullOrEmpty($migration_type) -and -not [String]::IsNullOrWhiteSpace($migration_type)) { $Options.Add('migration_type', $migration_type) }
	if ($online) { $Options.Add('online', $online) }
	if ($targetstorage -and -not [String]::IsNullOrEmpty($targetstorage) -and -not [String]::IsNullOrWhiteSpace($targetstorage)) { $Options.Add('targetstorage', $targetstorage) }
	if ($withlocaldisks) { $Options.Add('with-local-disks', $withlocaldisks) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/migrate" -Options $Options
}
function Get-NodeQemuAgentGetTimezone {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/agent/get-timezone" -Options $Options
}
function New-NodeQemuMonitor {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The monitor command.
		[string]
		$command,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('command', $command)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/monitor" -Options $Options
}
function Get-NodeQemuAgentGetUsers {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/agent/get-users" -Options $Options
}
function Set-NodeQemuResize {
	[CmdletBinding()]
	param(
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# The disk you want to resize.
		[string]
		$disk,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The new size. With the `+` sign the value is added to the actual size of the volume and without it, the value is taken as an absolute one. Shrinking disk size is not supported.
		[string]
		$size,
		# Ignore locks - only root is allowed to use this option.
		[switch]
		$skiplock,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('disk', $disk)
	$Options.Add('node', $node)
	$Options.Add('size', $size)
	$Options.Add('vmid', $vmid)
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($skiplock) { $Options.Add('skiplock', $skiplock) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/qemu/{vmid}/resize" -Options $Options
}
function Get-NodeQemuAgentGetVcpus {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/agent/get-vcpus" -Options $Options
}
function Get-NodeQemuSnapshot {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/snapshot" -Options $Options
}
function New-NodeQemuSnapshot {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# A textual description or comment.
		[string]
		$description,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The name of the snapshot.
		[string]
		$snapname,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid,
		# Save the vmstate
		[switch]
		$vmstate
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('snapname', $snapname)
	$Options.Add('vmid', $vmid)
	if ($description -and -not [String]::IsNullOrEmpty($description) -and -not [String]::IsNullOrWhiteSpace($description)) { $Options.Add('description', $description) }
	if ($vmstate) { $Options.Add('vmstate', $vmstate) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/snapshot" -Options $Options
}
function Get-NodeQemuAgentInfo {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/agent/info" -Options $Options
}
function New-NodeQemuTemplate {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# If you want to convert only 1 disk to base image.
		[string]
		$disk,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($disk -and -not [String]::IsNullOrEmpty($disk) -and -not [String]::IsNullOrWhiteSpace($disk)) { $Options.Add('disk', $disk) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/template" -Options $Options
}
function Get-NodeQemuAgentNetworkGetInterfaces {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces" -Options $Options
}
function New-NodeQemuAgentPing {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/qemu/{vmid}/agent/ping" -Options $Options
}
function Get-NodeLxc {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc" -Options $Options
}
function New-NodeLxc {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# OS architecture type.
		[string]
		$arch,
		# Override I/O bandwidth limit (in KiB/s).
		[number]
		$bwlimit,
		# Console mode. By default, the console command tries to open a connection to one of the available tty devices. By setting cmode to 'console' it tries to attach to /dev/console instead. If you set cmode to 'shell', it simply invokes a shell inside the container (no login).
		[string]
		$cmode,
		# Attach a console device (/dev/console) to the container.
		[switch]
		$console,
		# The number of cores assigned to the container. A container can use all available cores by default.
		[integer]
		$cores,
		# Limit of CPU usage.
		[number]
		$cpulimit,
		# CPU weight for a VM. Argument is used in the kernel fair scheduler. The larger the number is, the more CPU time this VM gets. Number is relative to the weights of all the other running VMs.
		[integer]
		$cpuunits,
		# Description for the Container. Shown in the web-interface CT's summary. This is saved as comment inside the configuration file.
		[string]
		$description,
		# Allow containers access to advanced features.
		[string]
		$features,
		# Script that will be exectued during various steps in the containers lifetime.
		[string]
		$hookscript,
		# Set a host name for the container.
		[string]
		$hostname,
		# Ignore errors when extracting the template.
		[switch]
		$ignoreunpackerrors,
		# Lock/unlock the VM.
		[string]
		$lock,
		# Amount of RAM for the VM in MB.
		[integer]
		$memory,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp0,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp1,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp2,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp3,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp4,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp5,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp6,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp7,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp8,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp9,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp10,
		# Sets DNS server IP address for a container. Create will automatically use the setting from the host if you neither set searchdomain nor nameserver.
		[string]
		$nameserver,
		# Specifies network interfaces for the container.
		[string]
		$net0,
		# Specifies network interfaces for the container.
		[string]
		$net1,
		# Specifies network interfaces for the container.
		[string]
		$net2,
		# Specifies network interfaces for the container.
		[string]
		$net3,
		# Specifies network interfaces for the container.
		[string]
		$net4,
		# Specifies network interfaces for the container.
		[string]
		$net5,
		# Specifies network interfaces for the container.
		[string]
		$net6,
		# Specifies network interfaces for the container.
		[string]
		$net7,
		# Specifies network interfaces for the container.
		[string]
		$net8,
		# Specifies network interfaces for the container.
		[string]
		$net9,
		# Specifies network interfaces for the container.
		[string]
		$net10,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Specifies whether a VM will be started during system bootup.
		[switch]
		$onboot,
		[Parameter(Mandatory)]
		# The OS template or backup file.
		[string]
		$ostemplate,
		# OS type. This is used to setup configuration inside the container, and corresponds to lxc setup scripts in /usr/share/lxc/config/<ostype>.common.conf. Value 'unmanaged' can be used to skip and OS specific setup.
		[string]
		$ostype,
		# Sets root password inside container.
		[securestring]
		$password,
		# Add the VM to the specified pool.
		[string]
		$pool,
		# Sets the protection flag of the container. This will prevent the CT or CT's disk remove/update operation.
		[switch]
		$protection,
		# Mark this as restore task.
		[switch]
		$restore,
		# Use volume as container root.
		[string]
		$rootfs,
		# Sets DNS search domains for a container. Create will automatically use the setting from the host if you neither set searchdomain nor nameserver.
		[string]
		$searchdomain,
		# Setup public SSH keys (one key per line, OpenSSH format).
		[string]
		$sshpublickeys,
		# Start the CT after its creation finished successfully.
		[switch]
		$start,
		# Startup and shutdown behavior. Order is a non-negative number defining the general startup order. Shutdown in done with reverse ordering. Additionally you can set the 'up' or 'down' delay in seconds, which specifies a delay to wait before the next VM is started or stopped.
		[string]
		$startup,
		# Default Storage.
		[string]
		$storage,
		# Amount of SWAP for the VM in MB.
		[integer]
		$swap,
		# Tags of the Container. This is only meta information.
		[string]
		$tags,
		# Enable/disable Template.
		[switch]
		$template,
		# Time zone to use in the container. If option isn't set, then nothing will be done. Can be set to 'host' to match the host time zone, or an arbitrary time zone option from /usr/share/zoneinfo/zone.tab
		[string]
		$timezone,
		# Specify the number of tty available to the container
		[integer]
		$tty,
		# Assign a unique random ethernet address.
		[switch]
		$unique,
		# Makes the container run as unprivileged user. (Should not be modified manually.)
		[switch]
		$unprivileged,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('ostemplate', $ostemplate)
	$Options.Add('vmid', $vmid)
	if ($arch -and -not [String]::IsNullOrEmpty($arch) -and -not [String]::IsNullOrWhiteSpace($arch)) { $Options.Add('arch', $arch) }
	if ($bwlimit -and -not [String]::IsNullOrEmpty($bwlimit) -and -not [String]::IsNullOrWhiteSpace($bwlimit)) { $Options.Add('bwlimit', $bwlimit) }
	if ($cmode -and -not [String]::IsNullOrEmpty($cmode) -and -not [String]::IsNullOrWhiteSpace($cmode)) { $Options.Add('cmode', $cmode) }
	if ($console) { $Options.Add('console', $console) }
	if ($cores -and -not [String]::IsNullOrEmpty($cores) -and -not [String]::IsNullOrWhiteSpace($cores)) { $Options.Add('cores', $cores) }
	if ($cpulimit -and -not [String]::IsNullOrEmpty($cpulimit) -and -not [String]::IsNullOrWhiteSpace($cpulimit)) { $Options.Add('cpulimit', $cpulimit) }
	if ($cpuunits -and -not [String]::IsNullOrEmpty($cpuunits) -and -not [String]::IsNullOrWhiteSpace($cpuunits)) { $Options.Add('cpuunits', $cpuunits) }
	if ($debug) { $Options.Add('debug', $debug) }
	if ($description -and -not [String]::IsNullOrEmpty($description) -and -not [String]::IsNullOrWhiteSpace($description)) { $Options.Add('description', $description) }
	if ($features -and -not [String]::IsNullOrEmpty($features) -and -not [String]::IsNullOrWhiteSpace($features)) { $Options.Add('features', $features) }
	if ($force) { $Options.Add('force', $force) }
	if ($hookscript -and -not [String]::IsNullOrEmpty($hookscript) -and -not [String]::IsNullOrWhiteSpace($hookscript)) { $Options.Add('hookscript', $hookscript) }
	if ($hostname -and -not [String]::IsNullOrEmpty($hostname) -and -not [String]::IsNullOrWhiteSpace($hostname)) { $Options.Add('hostname', $hostname) }
	if ($ignoreunpackerrors) { $Options.Add('ignore-unpack-errors', $ignoreunpackerrors) }
	if ($lock -and -not [String]::IsNullOrEmpty($lock) -and -not [String]::IsNullOrWhiteSpace($lock)) { $Options.Add('lock', $lock) }
	if ($memory -and -not [String]::IsNullOrEmpty($memory) -and -not [String]::IsNullOrWhiteSpace($memory)) { $Options.Add('memory', $memory) }
	if ($mp0 -and -not [String]::IsNullOrEmpty($mp0) -and -not [String]::IsNullOrWhiteSpace($mp0)) { $Options.Add('mp0', $mp0) }
	if ($mp1 -and -not [String]::IsNullOrEmpty($mp1) -and -not [String]::IsNullOrWhiteSpace($mp1)) { $Options.Add('mp1', $mp1) }
	if ($mp2 -and -not [String]::IsNullOrEmpty($mp2) -and -not [String]::IsNullOrWhiteSpace($mp2)) { $Options.Add('mp2', $mp2) }
	if ($mp3 -and -not [String]::IsNullOrEmpty($mp3) -and -not [String]::IsNullOrWhiteSpace($mp3)) { $Options.Add('mp3', $mp3) }
	if ($mp4 -and -not [String]::IsNullOrEmpty($mp4) -and -not [String]::IsNullOrWhiteSpace($mp4)) { $Options.Add('mp4', $mp4) }
	if ($mp5 -and -not [String]::IsNullOrEmpty($mp5) -and -not [String]::IsNullOrWhiteSpace($mp5)) { $Options.Add('mp5', $mp5) }
	if ($mp6 -and -not [String]::IsNullOrEmpty($mp6) -and -not [String]::IsNullOrWhiteSpace($mp6)) { $Options.Add('mp6', $mp6) }
	if ($mp7 -and -not [String]::IsNullOrEmpty($mp7) -and -not [String]::IsNullOrWhiteSpace($mp7)) { $Options.Add('mp7', $mp7) }
	if ($mp8 -and -not [String]::IsNullOrEmpty($mp8) -and -not [String]::IsNullOrWhiteSpace($mp8)) { $Options.Add('mp8', $mp8) }
	if ($mp9 -and -not [String]::IsNullOrEmpty($mp9) -and -not [String]::IsNullOrWhiteSpace($mp9)) { $Options.Add('mp9', $mp9) }
	if ($mp10 -and -not [String]::IsNullOrEmpty($mp10) -and -not [String]::IsNullOrWhiteSpace($mp10)) { $Options.Add('mp10', $mp10) }
	if ($nameserver -and -not [String]::IsNullOrEmpty($nameserver) -and -not [String]::IsNullOrWhiteSpace($nameserver)) { $Options.Add('nameserver', $nameserver) }
	if ($net0 -and -not [String]::IsNullOrEmpty($net0) -and -not [String]::IsNullOrWhiteSpace($net0)) { $Options.Add('net0', $net0) }
	if ($net1 -and -not [String]::IsNullOrEmpty($net1) -and -not [String]::IsNullOrWhiteSpace($net1)) { $Options.Add('net1', $net1) }
	if ($net2 -and -not [String]::IsNullOrEmpty($net2) -and -not [String]::IsNullOrWhiteSpace($net2)) { $Options.Add('net2', $net2) }
	if ($net3 -and -not [String]::IsNullOrEmpty($net3) -and -not [String]::IsNullOrWhiteSpace($net3)) { $Options.Add('net3', $net3) }
	if ($net4 -and -not [String]::IsNullOrEmpty($net4) -and -not [String]::IsNullOrWhiteSpace($net4)) { $Options.Add('net4', $net4) }
	if ($net5 -and -not [String]::IsNullOrEmpty($net5) -and -not [String]::IsNullOrWhiteSpace($net5)) { $Options.Add('net5', $net5) }
	if ($net6 -and -not [String]::IsNullOrEmpty($net6) -and -not [String]::IsNullOrWhiteSpace($net6)) { $Options.Add('net6', $net6) }
	if ($net7 -and -not [String]::IsNullOrEmpty($net7) -and -not [String]::IsNullOrWhiteSpace($net7)) { $Options.Add('net7', $net7) }
	if ($net8 -and -not [String]::IsNullOrEmpty($net8) -and -not [String]::IsNullOrWhiteSpace($net8)) { $Options.Add('net8', $net8) }
	if ($net9 -and -not [String]::IsNullOrEmpty($net9) -and -not [String]::IsNullOrWhiteSpace($net9)) { $Options.Add('net9', $net9) }
	if ($net10 -and -not [String]::IsNullOrEmpty($net10) -and -not [String]::IsNullOrWhiteSpace($net10)) { $Options.Add('net10', $net10) }
	if ($onboot) { $Options.Add('onboot', $onboot) }
	if ($ostype -and -not [String]::IsNullOrEmpty($ostype) -and -not [String]::IsNullOrWhiteSpace($ostype)) { $Options.Add('ostype', $ostype) }
	if ($password) { $Options.Add('password', $($password | ConvertFrom-SecureString -AsPlainText)) }
	if ($pool -and -not [String]::IsNullOrEmpty($pool) -and -not [String]::IsNullOrWhiteSpace($pool)) { $Options.Add('pool', $pool) }
	if ($protection) { $Options.Add('protection', $protection) }
	if ($restore) { $Options.Add('restore', $restore) }
	if ($rootfs -and -not [String]::IsNullOrEmpty($rootfs) -and -not [String]::IsNullOrWhiteSpace($rootfs)) { $Options.Add('rootfs', $rootfs) }
	if ($searchdomain -and -not [String]::IsNullOrEmpty($searchdomain) -and -not [String]::IsNullOrWhiteSpace($searchdomain)) { $Options.Add('searchdomain', $searchdomain) }
	if ($sshpublickeys -and -not [String]::IsNullOrEmpty($sshpublickeys) -and -not [String]::IsNullOrWhiteSpace($sshpublickeys)) { $Options.Add('ssh-public-keys', $sshpublickeys) }
	if ($start) { $Options.Add('start', $start) }
	if ($startup -and -not [String]::IsNullOrEmpty($startup) -and -not [String]::IsNullOrWhiteSpace($startup)) { $Options.Add('startup', $startup) }
	if ($storage -and -not [String]::IsNullOrEmpty($storage) -and -not [String]::IsNullOrWhiteSpace($storage)) { $Options.Add('storage', $storage) }
	if ($swap -and -not [String]::IsNullOrEmpty($swap) -and -not [String]::IsNullOrWhiteSpace($swap)) { $Options.Add('swap', $swap) }
	if ($tags -and -not [String]::IsNullOrEmpty($tags) -and -not [String]::IsNullOrWhiteSpace($tags)) { $Options.Add('tags', $tags) }
	if ($template) { $Options.Add('template', $template) }
	if ($timezone -and -not [String]::IsNullOrEmpty($timezone) -and -not [String]::IsNullOrWhiteSpace($timezone)) { $Options.Add('timezone', $timezone) }
	if ($tty -and -not [String]::IsNullOrEmpty($tty) -and -not [String]::IsNullOrWhiteSpace($tty)) { $Options.Add('tty', $tty) }
	if ($unique) { $Options.Add('unique', $unique) }
	if ($unprivileged) { $Options.Add('unprivileged', $unprivileged) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc" -Options $Options
}
function Get-NodeLxcVmid {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}" -Options $Options
}
function Remove-NodeLxcVmid {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# If set, destroy additionally all disks with the VMID from all enabled storages which are not referenced in the config.
		[switch]
		$destroyunreferenceddisks,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Remove container from all related configurations. For example, backup jobs, replication jobs or HA. Related ACLs and Firewall entries will *always* be removed.
		[switch]
		$purge,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($destroyunreferenceddisks) { $Options.Add('destroy-unreferenced-disks', $destroyunreferenceddisks) }
	if ($force) { $Options.Add('force', $force) }
	if ($purge) { $Options.Add('purge', $purge) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/lxc/{vmid}" -Options $Options
}
function Get-NodeLxcConfig {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		# Get current values (instead of pending values).
		[switch]
		$current,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Fetch config values from given snapshot.
		[string]
		$snapshot,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($current) { $Options.Add('current', $current) }
	if ($snapshot -and -not [String]::IsNullOrEmpty($snapshot) -and -not [String]::IsNullOrWhiteSpace($snapshot)) { $Options.Add('snapshot', $snapshot) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/config" -Options $Options
}
function Set-NodeLxcConfig {
	[CmdletBinding()]
	param(
		# OS architecture type.
		[string]
		$arch,
		# Console mode. By default, the console command tries to open a connection to one of the available tty devices. By setting cmode to 'console' it tries to attach to /dev/console instead. If you set cmode to 'shell', it simply invokes a shell inside the container (no login).
		[string]
		$cmode,
		# Attach a console device (/dev/console) to the container.
		[switch]
		$console,
		# The number of cores assigned to the container. A container can use all available cores by default.
		[integer]
		$cores,
		# Limit of CPU usage.
		[number]
		$cpulimit,
		# CPU weight for a VM. Argument is used in the kernel fair scheduler. The larger the number is, the more CPU time this VM gets. Number is relative to the weights of all the other running VMs.
		[integer]
		$cpuunits,
		# A list of settings you want to delete.
		[string]
		$delete,
		# Description for the Container. Shown in the web-interface CT's summary. This is saved as comment inside the configuration file.
		[string]
		$description,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# Allow containers access to advanced features.
		[string]
		$features,
		# Script that will be exectued during various steps in the containers lifetime.
		[string]
		$hookscript,
		# Set a host name for the container.
		[string]
		$hostname,
		# Lock/unlock the VM.
		[string]
		$lock,
		# Amount of RAM for the VM in MB.
		[integer]
		$memory,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp0,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp1,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp2,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp3,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp4,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp5,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp6,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp7,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp8,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp9,
		# Use volume as container mount point. Use the special syntax STORAGE_ID:SIZE_IN_GiB to allocate a new volume.
		[string]
		$mp10,
		# Sets DNS server IP address for a container. Create will automatically use the setting from the host if you neither set searchdomain nor nameserver.
		[string]
		$nameserver,
		# Specifies network interfaces for the container.
		[string]
		$net0,
		# Specifies network interfaces for the container.
		[string]
		$net1,
		# Specifies network interfaces for the container.
		[string]
		$net2,
		# Specifies network interfaces for the container.
		[string]
		$net3,
		# Specifies network interfaces for the container.
		[string]
		$net4,
		# Specifies network interfaces for the container.
		[string]
		$net5,
		# Specifies network interfaces for the container.
		[string]
		$net6,
		# Specifies network interfaces for the container.
		[string]
		$net7,
		# Specifies network interfaces for the container.
		[string]
		$net8,
		# Specifies network interfaces for the container.
		[string]
		$net9,
		# Specifies network interfaces for the container.
		[string]
		$net10,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Specifies whether a VM will be started during system bootup.
		[switch]
		$onboot,
		# OS type. This is used to setup configuration inside the container, and corresponds to lxc setup scripts in /usr/share/lxc/config/<ostype>.common.conf. Value 'unmanaged' can be used to skip and OS specific setup.
		[string]
		$ostype,
		# Sets the protection flag of the container. This will prevent the CT or CT's disk remove/update operation.
		[switch]
		$protection,
		# Revert a pending change.
		[string]
		$revert,
		# Use volume as container root.
		[string]
		$rootfs,
		# Sets DNS search domains for a container. Create will automatically use the setting from the host if you neither set searchdomain nor nameserver.
		[string]
		$searchdomain,
		# Startup and shutdown behavior. Order is a non-negative number defining the general startup order. Shutdown in done with reverse ordering. Additionally you can set the 'up' or 'down' delay in seconds, which specifies a delay to wait before the next VM is started or stopped.
		[string]
		$startup,
		# Amount of SWAP for the VM in MB.
		[integer]
		$swap,
		# Tags of the Container. This is only meta information.
		[string]
		$tags,
		# Enable/disable Template.
		[switch]
		$template,
		# Time zone to use in the container. If option isn't set, then nothing will be done. Can be set to 'host' to match the host time zone, or an arbitrary time zone option from /usr/share/zoneinfo/zone.tab
		[string]
		$timezone,
		# Specify the number of tty available to the container
		[integer]
		$tty,
		# Makes the container run as unprivileged user. (Should not be modified manually.)
		[switch]
		$unprivileged,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($arch -and -not [String]::IsNullOrEmpty($arch) -and -not [String]::IsNullOrWhiteSpace($arch)) { $Options.Add('arch', $arch) }
	if ($cmode -and -not [String]::IsNullOrEmpty($cmode) -and -not [String]::IsNullOrWhiteSpace($cmode)) { $Options.Add('cmode', $cmode) }
	if ($console) { $Options.Add('console', $console) }
	if ($cores -and -not [String]::IsNullOrEmpty($cores) -and -not [String]::IsNullOrWhiteSpace($cores)) { $Options.Add('cores', $cores) }
	if ($cpulimit -and -not [String]::IsNullOrEmpty($cpulimit) -and -not [String]::IsNullOrWhiteSpace($cpulimit)) { $Options.Add('cpulimit', $cpulimit) }
	if ($cpuunits -and -not [String]::IsNullOrEmpty($cpuunits) -and -not [String]::IsNullOrWhiteSpace($cpuunits)) { $Options.Add('cpuunits', $cpuunits) }
	if ($debug) { $Options.Add('debug', $debug) }
	if ($delete -and -not [String]::IsNullOrEmpty($delete) -and -not [String]::IsNullOrWhiteSpace($delete)) { $Options.Add('delete', $delete) }
	if ($description -and -not [String]::IsNullOrEmpty($description) -and -not [String]::IsNullOrWhiteSpace($description)) { $Options.Add('description', $description) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($features -and -not [String]::IsNullOrEmpty($features) -and -not [String]::IsNullOrWhiteSpace($features)) { $Options.Add('features', $features) }
	if ($hookscript -and -not [String]::IsNullOrEmpty($hookscript) -and -not [String]::IsNullOrWhiteSpace($hookscript)) { $Options.Add('hookscript', $hookscript) }
	if ($hostname -and -not [String]::IsNullOrEmpty($hostname) -and -not [String]::IsNullOrWhiteSpace($hostname)) { $Options.Add('hostname', $hostname) }
	if ($lock -and -not [String]::IsNullOrEmpty($lock) -and -not [String]::IsNullOrWhiteSpace($lock)) { $Options.Add('lock', $lock) }
	if ($memory -and -not [String]::IsNullOrEmpty($memory) -and -not [String]::IsNullOrWhiteSpace($memory)) { $Options.Add('memory', $memory) }
	if ($mp0 -and -not [String]::IsNullOrEmpty($mp0) -and -not [String]::IsNullOrWhiteSpace($mp0)) { $Options.Add('mp0', $mp0) }
	if ($mp1 -and -not [String]::IsNullOrEmpty($mp1) -and -not [String]::IsNullOrWhiteSpace($mp1)) { $Options.Add('mp1', $mp1) }
	if ($mp2 -and -not [String]::IsNullOrEmpty($mp2) -and -not [String]::IsNullOrWhiteSpace($mp2)) { $Options.Add('mp2', $mp2) }
	if ($mp3 -and -not [String]::IsNullOrEmpty($mp3) -and -not [String]::IsNullOrWhiteSpace($mp3)) { $Options.Add('mp3', $mp3) }
	if ($mp4 -and -not [String]::IsNullOrEmpty($mp4) -and -not [String]::IsNullOrWhiteSpace($mp4)) { $Options.Add('mp4', $mp4) }
	if ($mp5 -and -not [String]::IsNullOrEmpty($mp5) -and -not [String]::IsNullOrWhiteSpace($mp5)) { $Options.Add('mp5', $mp5) }
	if ($mp6 -and -not [String]::IsNullOrEmpty($mp6) -and -not [String]::IsNullOrWhiteSpace($mp6)) { $Options.Add('mp6', $mp6) }
	if ($mp7 -and -not [String]::IsNullOrEmpty($mp7) -and -not [String]::IsNullOrWhiteSpace($mp7)) { $Options.Add('mp7', $mp7) }
	if ($mp8 -and -not [String]::IsNullOrEmpty($mp8) -and -not [String]::IsNullOrWhiteSpace($mp8)) { $Options.Add('mp8', $mp8) }
	if ($mp9 -and -not [String]::IsNullOrEmpty($mp9) -and -not [String]::IsNullOrWhiteSpace($mp9)) { $Options.Add('mp9', $mp9) }
	if ($mp10 -and -not [String]::IsNullOrEmpty($mp10) -and -not [String]::IsNullOrWhiteSpace($mp10)) { $Options.Add('mp10', $mp10) }
	if ($nameserver -and -not [String]::IsNullOrEmpty($nameserver) -and -not [String]::IsNullOrWhiteSpace($nameserver)) { $Options.Add('nameserver', $nameserver) }
	if ($net0 -and -not [String]::IsNullOrEmpty($net0) -and -not [String]::IsNullOrWhiteSpace($net0)) { $Options.Add('net0', $net0) }
	if ($net1 -and -not [String]::IsNullOrEmpty($net1) -and -not [String]::IsNullOrWhiteSpace($net1)) { $Options.Add('net1', $net1) }
	if ($net2 -and -not [String]::IsNullOrEmpty($net2) -and -not [String]::IsNullOrWhiteSpace($net2)) { $Options.Add('net2', $net2) }
	if ($net3 -and -not [String]::IsNullOrEmpty($net3) -and -not [String]::IsNullOrWhiteSpace($net3)) { $Options.Add('net3', $net3) }
	if ($net4 -and -not [String]::IsNullOrEmpty($net4) -and -not [String]::IsNullOrWhiteSpace($net4)) { $Options.Add('net4', $net4) }
	if ($net5 -and -not [String]::IsNullOrEmpty($net5) -and -not [String]::IsNullOrWhiteSpace($net5)) { $Options.Add('net5', $net5) }
	if ($net6 -and -not [String]::IsNullOrEmpty($net6) -and -not [String]::IsNullOrWhiteSpace($net6)) { $Options.Add('net6', $net6) }
	if ($net7 -and -not [String]::IsNullOrEmpty($net7) -and -not [String]::IsNullOrWhiteSpace($net7)) { $Options.Add('net7', $net7) }
	if ($net8 -and -not [String]::IsNullOrEmpty($net8) -and -not [String]::IsNullOrWhiteSpace($net8)) { $Options.Add('net8', $net8) }
	if ($net9 -and -not [String]::IsNullOrEmpty($net9) -and -not [String]::IsNullOrWhiteSpace($net9)) { $Options.Add('net9', $net9) }
	if ($net10 -and -not [String]::IsNullOrEmpty($net10) -and -not [String]::IsNullOrWhiteSpace($net10)) { $Options.Add('net10', $net10) }
	if ($onboot) { $Options.Add('onboot', $onboot) }
	if ($ostype -and -not [String]::IsNullOrEmpty($ostype) -and -not [String]::IsNullOrWhiteSpace($ostype)) { $Options.Add('ostype', $ostype) }
	if ($protection) { $Options.Add('protection', $protection) }
	if ($revert -and -not [String]::IsNullOrEmpty($revert) -and -not [String]::IsNullOrWhiteSpace($revert)) { $Options.Add('revert', $revert) }
	if ($rootfs -and -not [String]::IsNullOrEmpty($rootfs) -and -not [String]::IsNullOrWhiteSpace($rootfs)) { $Options.Add('rootfs', $rootfs) }
	if ($searchdomain -and -not [String]::IsNullOrEmpty($searchdomain) -and -not [String]::IsNullOrWhiteSpace($searchdomain)) { $Options.Add('searchdomain', $searchdomain) }
	if ($startup -and -not [String]::IsNullOrEmpty($startup) -and -not [String]::IsNullOrWhiteSpace($startup)) { $Options.Add('startup', $startup) }
	if ($swap -and -not [String]::IsNullOrEmpty($swap) -and -not [String]::IsNullOrWhiteSpace($swap)) { $Options.Add('swap', $swap) }
	if ($tags -and -not [String]::IsNullOrEmpty($tags) -and -not [String]::IsNullOrWhiteSpace($tags)) { $Options.Add('tags', $tags) }
	if ($template) { $Options.Add('template', $template) }
	if ($timezone -and -not [String]::IsNullOrEmpty($timezone) -and -not [String]::IsNullOrWhiteSpace($timezone)) { $Options.Add('timezone', $timezone) }
	if ($tty -and -not [String]::IsNullOrEmpty($tty) -and -not [String]::IsNullOrWhiteSpace($tty)) { $Options.Add('tty', $tty) }
	if ($unprivileged) { $Options.Add('unprivileged', $unprivileged) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/lxc/{vmid}/config" -Options $Options
}
function Get-NodeLxcStatus {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/status" -Options $Options
}
function Get-NodeLxcStatusCurrent {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/status/current" -Options $Options
}
function Get-NodeLxcSnapshot {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/snapshot" -Options $Options
}
function New-NodeLxcSnapshot {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# A textual description or comment.
		[string]
		$description,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The name of the snapshot.
		[string]
		$snapname,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('snapname', $snapname)
	$Options.Add('vmid', $vmid)
	if ($description -and -not [String]::IsNullOrEmpty($description) -and -not [String]::IsNullOrWhiteSpace($description)) { $Options.Add('description', $description) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc/{vmid}/snapshot" -Options $Options
}
function New-NodeLxcStatusStart {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Ignore locks - only root is allowed to use this option.
		[switch]
		$skiplock,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($debug) { $Options.Add('debug', $debug) }
	if ($skiplock) { $Options.Add('skiplock', $skiplock) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc/{vmid}/status/start" -Options $Options
}
function Get-NodeLxcFirewall {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/firewall" -Options $Options
}
function New-NodeLxcStatusStop {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Ignore locks - only root is allowed to use this option.
		[switch]
		$skiplock,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($skiplock) { $Options.Add('skiplock', $skiplock) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc/{vmid}/status/stop" -Options $Options
}
function Get-NodeLxcRrd {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		# The RRD consolidation function
		[string]
		$cf,
		[Parameter(Mandatory)]
		# The list of datasources you want to display.
		[string]
		$ds,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Specify the time frame you are interested in.
		[string]
		$timeframe,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('ds', $ds)
	$Options.Add('node', $node)
	$Options.Add('timeframe', $timeframe)
	$Options.Add('vmid', $vmid)
	if ($cf -and -not [String]::IsNullOrEmpty($cf) -and -not [String]::IsNullOrWhiteSpace($cf)) { $Options.Add('cf', $cf) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/rrd" -Options $Options
}
function New-NodeLxcStatusShutdown {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Make sure the Container stops.
		[switch]
		$forceStop,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Wait maximal timeout seconds.
		[integer]
		$timeout,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($forceStop) { $Options.Add('forceStop', $forceStop) }
	if ($timeout -and -not [String]::IsNullOrEmpty($timeout) -and -not [String]::IsNullOrWhiteSpace($timeout)) { $Options.Add('timeout', $timeout) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc/{vmid}/status/shutdown" -Options $Options
}
function Get-NodeLxcRrddata {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# The RRD consolidation function
		[string]
		$cf,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Specify the time frame you are interested in.
		[string]
		$timeframe,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('timeframe', $timeframe)
	$Options.Add('vmid', $vmid)
	if ($cf -and -not [String]::IsNullOrEmpty($cf) -and -not [String]::IsNullOrWhiteSpace($cf)) { $Options.Add('cf', $cf) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/rrddata" -Options $Options
}
function New-NodeLxcStatusSuspend {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc/{vmid}/status/suspend" -Options $Options
}
function New-NodeLxcVncproxy {
	[CmdletBinding()]
	param(
		# sets the height of the console in pixels.
		[integer]
		$height,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid,
		# use websocket instead of standard VNC.
		[switch]
		$websocket,
		# sets the width of the console in pixels.
		[integer]
		$width
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($height -and -not [String]::IsNullOrEmpty($height) -and -not [String]::IsNullOrWhiteSpace($height)) { $Options.Add('height', $height) }
	if ($websocket) { $Options.Add('websocket', $websocket) }
	if ($width -and -not [String]::IsNullOrEmpty($width) -and -not [String]::IsNullOrWhiteSpace($width)) { $Options.Add('width', $width) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc/{vmid}/vncproxy" -Options $Options
}
function New-NodeLxcStatusResume {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc/{vmid}/status/resume" -Options $Options
}
function New-NodeLxcTermproxy {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc/{vmid}/termproxy" -Options $Options
}
function New-NodeLxcStatusReboot {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Wait maximal timeout seconds for the shutdown.
		[integer]
		$timeout,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($timeout -and -not [String]::IsNullOrEmpty($timeout) -and -not [String]::IsNullOrWhiteSpace($timeout)) { $Options.Add('timeout', $timeout) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc/{vmid}/status/reboot" -Options $Options
}
function Get-NodeLxcVncwebsocket {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Port number returned by previous vncproxy call.
		[integer]
		$port,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid,
		[Parameter(Mandatory)]
		# Ticket from previous call to vncproxy.
		[string]
		$vncticket
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('port', $port)
	$Options.Add('vmid', $vmid)
	$Options.Add('vncticket', $vncticket)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/vncwebsocket" -Options $Options
}
function Get-NodeLxcSnapshotSnapname {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The name of the snapshot.
		[string]
		$snapname,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('snapname', $snapname)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/snapshot/{snapname}" -Options $Options
}
function Remove-NodeLxcSnapshotSnapname {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The name of the snapshot.
		[string]
		$snapname,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('snapname', $snapname)
	$Options.Add('vmid', $vmid)
	if ($force) { $Options.Add('force', $force) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/lxc/{vmid}/snapshot/{snapname}" -Options $Options
}
function New-NodeLxcSnapshotSnapnameRollback {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The name of the snapshot.
		[string]
		$snapname,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('snapname', $snapname)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc/{vmid}/snapshot/{snapname}/rollback" -Options $Options
}
function Get-NodeLxcSnapshotSnapnameConfig {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The name of the snapshot.
		[string]
		$snapname,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('snapname', $snapname)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/snapshot/{snapname}/config" -Options $Options
}
function Set-NodeLxcSnapshotSnapnameConfig {
	[CmdletBinding()]
	param(
		# A textual description or comment.
		[string]
		$description,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The name of the snapshot.
		[string]
		$snapname,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('snapname', $snapname)
	$Options.Add('vmid', $vmid)
	if ($description -and -not [String]::IsNullOrEmpty($description) -and -not [String]::IsNullOrWhiteSpace($description)) { $Options.Add('description', $description) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/lxc/{vmid}/snapshot/{snapname}/config" -Options $Options
}
function New-NodeLxcSpiceproxy {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# SPICE proxy server. This can be used by the client to specify the proxy server. All nodes in a cluster runs 'spiceproxy', so it is up to the client to choose one. By default, we return the node where the VM is currently running. As reasonable setting is to use same node you use to connect to the API (This is window.location.hostname for the JS GUI).
		[string]
		$proxy,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($proxy -and -not [String]::IsNullOrEmpty($proxy) -and -not [String]::IsNullOrWhiteSpace($proxy)) { $Options.Add('proxy', $proxy) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc/{vmid}/spiceproxy" -Options $Options
}
function Get-NodeLxcFirewallRules {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/firewall/rules" -Options $Options
}
function New-NodeLxcFirewallRules {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.
		[string]
		$action,
		# Descriptive comment.
		[string]
		$comment,
		# Restrict packet destination address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
		[string]
		$dest,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# Restrict TCP/UDP destination port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
		[string]
		$dport,
		# Flag to enable/disable a rule.
		[integer]
		$enable,
		# Specify icmp-type. Only valid if proto equals 'icmp'.
		[string]
		$icmptype,
		# Network interface name. You have to use network configuration key names for VMs and containers ('net\d+'). Host related rules can use arbitrary strings.
		[string]
		$iface,
		# Log level for firewall rule.
		[string]
		$log,
		# Use predefined standard macro.
		[string]
		$macro,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Update rule at position <pos>.
		[integer]
		$pos,
		# IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.
		[string]
		$proto,
		# Restrict packet source address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
		[string]
		$source,
		# Restrict TCP/UDP source port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
		[string]
		$sport,
		[Parameter(Mandatory)]
		# Rule type.
		[string]
		$type,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('action', $action)
	$Options.Add('node', $node)
	$Options.Add('type', $type)
	$Options.Add('vmid', $vmid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($dest -and -not [String]::IsNullOrEmpty($dest) -and -not [String]::IsNullOrWhiteSpace($dest)) { $Options.Add('dest', $dest) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($dport -and -not [String]::IsNullOrEmpty($dport) -and -not [String]::IsNullOrWhiteSpace($dport)) { $Options.Add('dport', $dport) }
	if ($enable -and -not [String]::IsNullOrEmpty($enable) -and -not [String]::IsNullOrWhiteSpace($enable)) { $Options.Add('enable', $enable) }
	if ($icmptype -and -not [String]::IsNullOrEmpty($icmptype) -and -not [String]::IsNullOrWhiteSpace($icmptype)) { $Options.Add('icmp-type', $icmptype) }
	if ($iface -and -not [String]::IsNullOrEmpty($iface) -and -not [String]::IsNullOrWhiteSpace($iface)) { $Options.Add('iface', $iface) }
	if ($log -and -not [String]::IsNullOrEmpty($log) -and -not [String]::IsNullOrWhiteSpace($log)) { $Options.Add('log', $log) }
	if ($macro -and -not [String]::IsNullOrEmpty($macro) -and -not [String]::IsNullOrWhiteSpace($macro)) { $Options.Add('macro', $macro) }
	if ($pos -and -not [String]::IsNullOrEmpty($pos) -and -not [String]::IsNullOrWhiteSpace($pos)) { $Options.Add('pos', $pos) }
	if ($proto -and -not [String]::IsNullOrEmpty($proto) -and -not [String]::IsNullOrWhiteSpace($proto)) { $Options.Add('proto', $proto) }
	if ($source -and -not [String]::IsNullOrEmpty($source) -and -not [String]::IsNullOrWhiteSpace($source)) { $Options.Add('source', $source) }
	if ($sport -and -not [String]::IsNullOrEmpty($sport) -and -not [String]::IsNullOrWhiteSpace($sport)) { $Options.Add('sport', $sport) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc/{vmid}/firewall/rules" -Options $Options
}
function Get-NodeLxcFirewallRulesPos {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Update rule at position <pos>.
		[integer]
		$pos,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($pos -and -not [String]::IsNullOrEmpty($pos) -and -not [String]::IsNullOrWhiteSpace($pos)) { $Options.Add('pos', $pos) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/firewall/rules/{pos}" -Options $Options
}
function Set-NodeLxcFirewallRulesPos {
	[CmdletBinding()]
	param(
		# Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.
		[string]
		$action,
		# Descriptive comment.
		[string]
		$comment,
		# A list of settings you want to delete.
		[string]
		$delete,
		# Restrict packet destination address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
		[string]
		$dest,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# Restrict TCP/UDP destination port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
		[string]
		$dport,
		# Flag to enable/disable a rule.
		[integer]
		$enable,
		# Specify icmp-type. Only valid if proto equals 'icmp'.
		[string]
		$icmptype,
		# Network interface name. You have to use network configuration key names for VMs and containers ('net\d+'). Host related rules can use arbitrary strings.
		[string]
		$iface,
		# Log level for firewall rule.
		[string]
		$log,
		# Use predefined standard macro.
		[string]
		$macro,
		# Move rule to new position <moveto>. Other arguments are ignored.
		[integer]
		$moveto,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Update rule at position <pos>.
		[integer]
		$pos,
		# IP protocol. You can use protocol names ('tcp'/'udp') or simple numbers, as defined in '/etc/protocols'.
		[string]
		$proto,
		# Restrict packet source address. This can refer to a single IP address, an IP set ('+ipsetname') or an IP alias definition. You can also specify an address range like '20.34.101.207-201.3.9.99', or a list of IP addresses and networks (entries are separated by comma). Please do not mix IPv4 and IPv6 addresses inside such lists.
		[string]
		$source,
		# Restrict TCP/UDP source port. You can use service names or simple numbers (0-65535), as defined in '/etc/services'. Port ranges can be specified with '\d+:\d+', for example '80:85', and you can use comma separated list to match several ports or ranges.
		[string]
		$sport,
		# Rule type.
		[string]
		$type,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($action -and -not [String]::IsNullOrEmpty($action) -and -not [String]::IsNullOrWhiteSpace($action)) { $Options.Add('action', $action) }
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($delete -and -not [String]::IsNullOrEmpty($delete) -and -not [String]::IsNullOrWhiteSpace($delete)) { $Options.Add('delete', $delete) }
	if ($dest -and -not [String]::IsNullOrEmpty($dest) -and -not [String]::IsNullOrWhiteSpace($dest)) { $Options.Add('dest', $dest) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($dport -and -not [String]::IsNullOrEmpty($dport) -and -not [String]::IsNullOrWhiteSpace($dport)) { $Options.Add('dport', $dport) }
	if ($enable -and -not [String]::IsNullOrEmpty($enable) -and -not [String]::IsNullOrWhiteSpace($enable)) { $Options.Add('enable', $enable) }
	if ($icmptype -and -not [String]::IsNullOrEmpty($icmptype) -and -not [String]::IsNullOrWhiteSpace($icmptype)) { $Options.Add('icmp-type', $icmptype) }
	if ($iface -and -not [String]::IsNullOrEmpty($iface) -and -not [String]::IsNullOrWhiteSpace($iface)) { $Options.Add('iface', $iface) }
	if ($log -and -not [String]::IsNullOrEmpty($log) -and -not [String]::IsNullOrWhiteSpace($log)) { $Options.Add('log', $log) }
	if ($macro -and -not [String]::IsNullOrEmpty($macro) -and -not [String]::IsNullOrWhiteSpace($macro)) { $Options.Add('macro', $macro) }
	if ($moveto -and -not [String]::IsNullOrEmpty($moveto) -and -not [String]::IsNullOrWhiteSpace($moveto)) { $Options.Add('moveto', $moveto) }
	if ($pos -and -not [String]::IsNullOrEmpty($pos) -and -not [String]::IsNullOrWhiteSpace($pos)) { $Options.Add('pos', $pos) }
	if ($proto -and -not [String]::IsNullOrEmpty($proto) -and -not [String]::IsNullOrWhiteSpace($proto)) { $Options.Add('proto', $proto) }
	if ($source -and -not [String]::IsNullOrEmpty($source) -and -not [String]::IsNullOrWhiteSpace($source)) { $Options.Add('source', $source) }
	if ($sport -and -not [String]::IsNullOrEmpty($sport) -and -not [String]::IsNullOrWhiteSpace($sport)) { $Options.Add('sport', $sport) }
	if ($type -and -not [String]::IsNullOrEmpty($type) -and -not [String]::IsNullOrWhiteSpace($type)) { $Options.Add('type', $type) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/lxc/{vmid}/firewall/rules/{pos}" -Options $Options
}
function Remove-NodeLxcFirewallRulesPos {
	[CmdletBinding()]
	param(
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Update rule at position <pos>.
		[integer]
		$pos,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($pos -and -not [String]::IsNullOrEmpty($pos) -and -not [String]::IsNullOrWhiteSpace($pos)) { $Options.Add('pos', $pos) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/lxc/{vmid}/firewall/rules/{pos}" -Options $Options
}
function New-NodeLxcMigrate {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Override I/O bandwidth limit (in KiB/s).
		[number]
		$bwlimit,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Use online/live migration.
		[switch]
		$online,
		# Use restart migration
		[switch]
		$restart,
		[Parameter(Mandatory)]
		# Target node.
		[string]
		$target,
		# Timeout in seconds for shutdown for restart migration
		[integer]
		$timeout,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('target', $target)
	$Options.Add('vmid', $vmid)
	if ($bwlimit -and -not [String]::IsNullOrEmpty($bwlimit) -and -not [String]::IsNullOrWhiteSpace($bwlimit)) { $Options.Add('bwlimit', $bwlimit) }
	if ($online) { $Options.Add('online', $online) }
	if ($restart) { $Options.Add('restart', $restart) }
	if ($timeout -and -not [String]::IsNullOrEmpty($timeout) -and -not [String]::IsNullOrWhiteSpace($timeout)) { $Options.Add('timeout', $timeout) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc/{vmid}/migrate" -Options $Options
}
function Get-NodeLxcFirewallAliases {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/firewall/aliases" -Options $Options
}
function New-NodeLxcFirewallAliases {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Network/IP specification in CIDR format.
		[string]
		$cidr,
		# 
		[string]
		$comment,
		[Parameter(Mandatory)]
		# Alias name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('cidr', $cidr)
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc/{vmid}/firewall/aliases" -Options $Options
}
function Get-NodeLxcFirewallAliasesName {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# Alias name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/firewall/aliases/{name}" -Options $Options
}
function Set-NodeLxcFirewallAliasesName {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Network/IP specification in CIDR format.
		[string]
		$cidr,
		# 
		[string]
		$comment,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# Alias name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Rename an existing alias.
		[string]
		$rename,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('cidr', $cidr)
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($rename -and -not [String]::IsNullOrEmpty($rename) -and -not [String]::IsNullOrWhiteSpace($rename)) { $Options.Add('rename', $rename) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/lxc/{vmid}/firewall/aliases/{name}" -Options $Options
}
function Remove-NodeLxcFirewallAliasesName {
	[CmdletBinding()]
	param(
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# Alias name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/lxc/{vmid}/firewall/aliases/{name}" -Options $Options
}
function Get-NodeLxcFeature {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# Feature to check.
		[string]
		$feature,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# The name of the snapshot.
		[string]
		$snapname,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('feature', $feature)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($snapname -and -not [String]::IsNullOrEmpty($snapname) -and -not [String]::IsNullOrWhiteSpace($snapname)) { $Options.Add('snapname', $snapname) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/feature" -Options $Options
}
function Get-NodeLxcFirewallIpset {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/firewall/ipset" -Options $Options
}
function New-NodeLxcFirewallIpset {
	[CmdletBinding()]
	param(
		# 
		[string]
		$comment,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Rename an existing IPSet. You can set 'rename' to the same value as 'name' to update the 'comment' of an existing IPSet.
		[string]
		$rename,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($rename -and -not [String]::IsNullOrEmpty($rename) -and -not [String]::IsNullOrWhiteSpace($rename)) { $Options.Add('rename', $rename) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc/{vmid}/firewall/ipset" -Options $Options
}
function Get-NodeLxcFirewallIpsetName {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/firewall/ipset/{name}" -Options $Options
}
function New-NodeLxcFirewallIpsetName {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Network/IP specification in CIDR format.
		[string]
		$cidr,
		# 
		[string]
		$comment,
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# 
		[switch]
		$nomatch,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('cidr', $cidr)
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($nomatch) { $Options.Add('nomatch', $nomatch) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc/{vmid}/firewall/ipset/{name}" -Options $Options
}
function Remove-NodeLxcFirewallIpsetName {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/lxc/{vmid}/firewall/ipset/{name}" -Options $Options
}
function Get-NodeLxcFirewallIpsetNameCidr {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# Network/IP specification in CIDR format.
		[string]
		$cidr,
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('cidr', $cidr)
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/firewall/ipset/{name}/{cidr}" -Options $Options
}
function Set-NodeLxcFirewallIpsetNameCidr {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Network/IP specification in CIDR format.
		[string]
		$cidr,
		# 
		[string]
		$comment,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# 
		[switch]
		$nomatch,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('cidr', $cidr)
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($nomatch) { $Options.Add('nomatch', $nomatch) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/lxc/{vmid}/firewall/ipset/{name}/{cidr}" -Options $Options
}
function Remove-NodeLxcFirewallIpsetNameCidr {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Network/IP specification in CIDR format.
		[string]
		$cidr,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# IP set name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('cidr', $cidr)
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/lxc/{vmid}/firewall/ipset/{name}/{cidr}" -Options $Options
}
function New-NodeLxcTemplate {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc/{vmid}/template" -Options $Options
}
function Get-NodeLxcFirewallOptions {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/firewall/options" -Options $Options
}
function Set-NodeLxcFirewallOptions {
	[CmdletBinding()]
	param(
		# A list of settings you want to delete.
		[string]
		$delete,
		# Enable DHCP.
		[switch]
		$dhcp,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# Enable/disable firewall rules.
		[switch]
		$enable,
		# Enable default IP filters. This is equivalent to adding an empty ipfilter-net<id> ipset for every interface. Such ipsets implicitly contain sane default restrictions such as restricting IPv6 link local addresses to the one derived from the interface's MAC address. For containers the configured IP addresses will be implicitly added.
		[switch]
		$ipfilter,
		# Log level for incoming traffic.
		[string]
		$log_level_in,
		# Log level for outgoing traffic.
		[string]
		$log_level_out,
		# Enable/disable MAC address filter.
		[switch]
		$macfilter,
		# Enable NDP (Neighbor Discovery Protocol).
		[switch]
		$ndp,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Input policy.
		[string]
		$policy_in,
		# Output policy.
		[string]
		$policy_out,
		# Allow sending Router Advertisement.
		[switch]
		$radv,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($delete -and -not [String]::IsNullOrEmpty($delete) -and -not [String]::IsNullOrWhiteSpace($delete)) { $Options.Add('delete', $delete) }
	if ($dhcp) { $Options.Add('dhcp', $dhcp) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($enable) { $Options.Add('enable', $enable) }
	if ($ipfilter) { $Options.Add('ipfilter', $ipfilter) }
	if ($log_level_in -and -not [String]::IsNullOrEmpty($log_level_in) -and -not [String]::IsNullOrWhiteSpace($log_level_in)) { $Options.Add('log_level_in', $log_level_in) }
	if ($log_level_out -and -not [String]::IsNullOrEmpty($log_level_out) -and -not [String]::IsNullOrWhiteSpace($log_level_out)) { $Options.Add('log_level_out', $log_level_out) }
	if ($macfilter) { $Options.Add('macfilter', $macfilter) }
	if ($ndp) { $Options.Add('ndp', $ndp) }
	if ($policy_in -and -not [String]::IsNullOrEmpty($policy_in) -and -not [String]::IsNullOrWhiteSpace($policy_in)) { $Options.Add('policy_in', $policy_in) }
	if ($policy_out -and -not [String]::IsNullOrEmpty($policy_out) -and -not [String]::IsNullOrWhiteSpace($policy_out)) { $Options.Add('policy_out', $policy_out) }
	if ($radv) { $Options.Add('radv', $radv) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/lxc/{vmid}/firewall/options" -Options $Options
}
function New-NodeLxcClone {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Override I/O bandwidth limit (in KiB/s).
		[number]
		$bwlimit,
		# Description for the new CT.
		[string]
		$description,
		# Create a full copy of all disks. This is always done when you clone a normal CT. For CT templates, we try to create a linked clone by default.
		[switch]
		$full,
		# Set a hostname for the new CT.
		[string]
		$hostname,
		[Parameter(Mandatory)]
		# VMID for the clone.
		[integer]
		$newid,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Add the new CT to the specified pool.
		[string]
		$pool,
		# The name of the snapshot.
		[string]
		$snapname,
		# Target storage for full clone.
		[string]
		$storage,
		# Target node. Only allowed if the original VM is on shared storage.
		[string]
		$target,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('newid', $newid)
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($bwlimit -and -not [String]::IsNullOrEmpty($bwlimit) -and -not [String]::IsNullOrWhiteSpace($bwlimit)) { $Options.Add('bwlimit', $bwlimit) }
	if ($description -and -not [String]::IsNullOrEmpty($description) -and -not [String]::IsNullOrWhiteSpace($description)) { $Options.Add('description', $description) }
	if ($full) { $Options.Add('full', $full) }
	if ($hostname -and -not [String]::IsNullOrEmpty($hostname) -and -not [String]::IsNullOrWhiteSpace($hostname)) { $Options.Add('hostname', $hostname) }
	if ($pool -and -not [String]::IsNullOrEmpty($pool) -and -not [String]::IsNullOrWhiteSpace($pool)) { $Options.Add('pool', $pool) }
	if ($snapname -and -not [String]::IsNullOrEmpty($snapname) -and -not [String]::IsNullOrWhiteSpace($snapname)) { $Options.Add('snapname', $snapname) }
	if ($storage -and -not [String]::IsNullOrEmpty($storage) -and -not [String]::IsNullOrWhiteSpace($storage)) { $Options.Add('storage', $storage) }
	if ($target -and -not [String]::IsNullOrEmpty($target) -and -not [String]::IsNullOrWhiteSpace($target)) { $Options.Add('target', $target) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc/{vmid}/clone" -Options $Options
}
function Get-NodeLxcFirewallLog {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# 
		[integer]
		$limit,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# 
		[integer]
		$start,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($limit -and -not [String]::IsNullOrEmpty($limit) -and -not [String]::IsNullOrWhiteSpace($limit)) { $Options.Add('limit', $limit) }
	if ($start -and -not [String]::IsNullOrEmpty($start) -and -not [String]::IsNullOrWhiteSpace($start)) { $Options.Add('start', $start) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/firewall/log" -Options $Options
}
function Set-NodeLxcResize {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# The disk you want to resize.
		[string]
		$disk,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The new size. With the '+' sign the value is added to the actual size of the volume and without it, the value is taken as an absolute one. Shrinking disk size is not supported.
		[string]
		$size,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('disk', $disk)
	$Options.Add('node', $node)
	$Options.Add('size', $size)
	$Options.Add('vmid', $vmid)
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/lxc/{vmid}/resize" -Options $Options
}
function Get-NodeLxcFirewallRefs {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Only list references of specified type.
		[string]
		$type,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	if ($type -and -not [String]::IsNullOrEmpty($type) -and -not [String]::IsNullOrWhiteSpace($type)) { $Options.Add('type', $type) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/firewall/refs" -Options $Options
}
function New-NodeLxcMoveVolume {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Override I/O bandwidth limit (in KiB/s).
		[number]
		$bwlimit,
		# Delete the original volume after successful copy. By default the original is kept as an unused volume entry.
		[switch]
		$delete,
		# Prevent changes if current configuration file has different SHA1 " .
		[string]
		$digest,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Target Storage.
		[string]
		$storage,
		# Prevent changes if current configuration file of the target " .
		[string]
		$targetdigest,
		# The (unique) ID of the VM.
		[integer]
		$targetvmid,
		# The config key the volume will be moved to. Default is the source volume key.
		[string]
		$targetvolume,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid,
		[Parameter(Mandatory)]
		# Volume which will be moved.
		[string]
		$volume
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	$Options.Add('volume', $volume)
	if ($bwlimit -and -not [String]::IsNullOrEmpty($bwlimit) -and -not [String]::IsNullOrWhiteSpace($bwlimit)) { $Options.Add('bwlimit', $bwlimit) }
	if ($delete) { $Options.Add('delete', $delete) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($storage -and -not [String]::IsNullOrEmpty($storage) -and -not [String]::IsNullOrWhiteSpace($storage)) { $Options.Add('storage', $storage) }
	if ($targetdigest -and -not [String]::IsNullOrEmpty($targetdigest) -and -not [String]::IsNullOrWhiteSpace($targetdigest)) { $Options.Add('target-digest', $targetdigest) }
	if ($targetvmid -and -not [String]::IsNullOrEmpty($targetvmid) -and -not [String]::IsNullOrWhiteSpace($targetvmid)) { $Options.Add('target-vmid', $targetvmid) }
	if ($targetvolume -and -not [String]::IsNullOrEmpty($targetvolume) -and -not [String]::IsNullOrWhiteSpace($targetvolume)) { $Options.Add('target-volume', $targetvolume) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/lxc/{vmid}/move_volume" -Options $Options
}
function Get-NodeLxcPending {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The (unique) ID of the VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vmid', $vmid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/lxc/{vmid}/pending" -Options $Options
}
function Get-NodeCeph {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/ceph" -Options $Options
}
function Get-NodeCephOsd {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/ceph/osd" -Options $Options
}
function New-NodeCephOsd {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Set the device class of the OSD in crush.
		[string]
		$crushdeviceclass,
		# Block device name for block.db.
		[string]
		$db_dev,
		# Size in GiB for block.db.
		[number]
		$db_dev_size,
		[Parameter(Mandatory)]
		# Block device name.
		[string]
		$dev,
		# Enables encryption of the OSD.
		[switch]
		$encrypted,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Block device name for block.wal.
		[string]
		$wal_dev,
		# Size in GiB for block.wal.
		[number]
		$wal_dev_size
	)
	$Options = @()
	$Options.Add('dev', $dev)
	$Options.Add('node', $node)
	if ($crushdeviceclass -and -not [String]::IsNullOrEmpty($crushdeviceclass) -and -not [String]::IsNullOrWhiteSpace($crushdeviceclass)) { $Options.Add('crush-device-class', $crushdeviceclass) }
	if ($db_dev -and -not [String]::IsNullOrEmpty($db_dev) -and -not [String]::IsNullOrWhiteSpace($db_dev)) { $Options.Add('db_dev', $db_dev) }
	if ($db_dev_size -and -not [String]::IsNullOrEmpty($db_dev_size) -and -not [String]::IsNullOrWhiteSpace($db_dev_size)) { $Options.Add('db_dev_size', $db_dev_size) }
	if ($encrypted) { $Options.Add('encrypted', $encrypted) }
	if ($wal_dev -and -not [String]::IsNullOrEmpty($wal_dev) -and -not [String]::IsNullOrWhiteSpace($wal_dev)) { $Options.Add('wal_dev', $wal_dev) }
	if ($wal_dev_size -and -not [String]::IsNullOrEmpty($wal_dev_size) -and -not [String]::IsNullOrWhiteSpace($wal_dev_size)) { $Options.Add('wal_dev_size', $wal_dev_size) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/ceph/osd" -Options $Options
}
function Remove-NodeCephOsdOsdid {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# If set, we remove partition table entries.
		[switch]
		$cleanup,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# OSD ID
		[integer]
		$osdid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('osdid', $osdid)
	if ($cleanup) { $Options.Add('cleanup', $cleanup) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/ceph/osd/{osdid}" -Options $Options
}
function New-NodeCephOsdIn {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# OSD ID
		[integer]
		$osdid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('osdid', $osdid)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/ceph/osd/{osdid}/in" -Options $Options
}
function New-NodeCephOsdOut {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# OSD ID
		[integer]
		$osdid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('osdid', $osdid)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/ceph/osd/{osdid}/out" -Options $Options
}
function New-NodeCephOsdScrub {
	[CmdletBinding()]
	param(
		# If set, instructs a deep scrub instead of a normal one.
		[switch]
		$deep,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# OSD ID
		[integer]
		$osdid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('osdid', $osdid)
	if ($deep) { $Options.Add('deep', $deep) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/ceph/osd/{osdid}/scrub" -Options $Options
}
function New-NodeVzdump {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Backup all known guest systems on this host.
		[switch]
		$all,
		# Limit I/O bandwidth (KBytes per second).
		[integer]
		$bwlimit,
		# Compress dump file.
		[string]
		$compress,
		# Store resulting files to specified directory.
		[string]
		$dumpdir,
		# Exclude specified guest systems (assumes --all)
		[string]
		$exclude,
		# Exclude certain files/directories (shell globs). Paths starting with '/' are anchored to the container's root,  other paths match relative to each subdirectory.
		[string]
		$excludepath,
		# Set CFQ ionice priority.
		[integer]
		$ionice,
		# Maximal time to wait for the global lock (minutes).
		[integer]
		$lockwait,
		# Specify when to send an email
		[string]
		$mailnotification,
		# Comma-separated list of email addresses or users that should receive email notifications.
		[string]
		$mailto,
		# Deprecated: use 'prune-backups' instead. Maximal number of backup files per guest system.
		[integer]
		$maxfiles,
		# Backup mode.
		[string]
		$mode,
		# Only run if executed on this node.
		[string]
		$node,
		# Use pigz instead of gzip when N>0. N=1 uses half of cores, N>1 uses N as thread count.
		[integer]
		$pigz,
		# Backup all known guest systems included in the specified pool.
		[string]
		$pool,
		# Use these retention options instead of those from the storage configuration.
		[string]
		$prunebackups,
		# Be quiet.
		[switch]
		$quiet,
		# Prune older backups according to 'prune-backups'.
		[switch]
		$remove,
		# Use specified hook script.
		[string]
		$script,
		# Exclude temporary files and logs.
		[switch]
		$stdexcludes,
		# Write tar to stdout, not to a file.
		[switch]
		$stdout,
		# Stop running backup jobs on this host.
		[switch]
		$stop,
		# Maximal time to wait until a guest system is stopped (minutes).
		[integer]
		$stopwait,
		# Store resulting file to this storage.
		[string]
		$storage,
		# Store temporary files to specified directory.
		[string]
		$tmpdir,
		# The ID of the guest system you want to backup.
		[string]
		$vmid,
		# Zstd threads. N=0 uses half of the available cores, N>0 uses N as thread count.
		[integer]
		$zstd
	)
	$Options = @()
	if ($all) { $Options.Add('all', $all) }
	if ($bwlimit -and -not [String]::IsNullOrEmpty($bwlimit) -and -not [String]::IsNullOrWhiteSpace($bwlimit)) { $Options.Add('bwlimit', $bwlimit) }
	if ($compress -and -not [String]::IsNullOrEmpty($compress) -and -not [String]::IsNullOrWhiteSpace($compress)) { $Options.Add('compress', $compress) }
	if ($dumpdir -and -not [String]::IsNullOrEmpty($dumpdir) -and -not [String]::IsNullOrWhiteSpace($dumpdir)) { $Options.Add('dumpdir', $dumpdir) }
	if ($exclude -and -not [String]::IsNullOrEmpty($exclude) -and -not [String]::IsNullOrWhiteSpace($exclude)) { $Options.Add('exclude', $exclude) }
	if ($excludepath -and -not [String]::IsNullOrEmpty($excludepath) -and -not [String]::IsNullOrWhiteSpace($excludepath)) { $Options.Add('exclude-path', $excludepath) }
	if ($ionice -and -not [String]::IsNullOrEmpty($ionice) -and -not [String]::IsNullOrWhiteSpace($ionice)) { $Options.Add('ionice', $ionice) }
	if ($lockwait -and -not [String]::IsNullOrEmpty($lockwait) -and -not [String]::IsNullOrWhiteSpace($lockwait)) { $Options.Add('lockwait', $lockwait) }
	if ($mailnotification -and -not [String]::IsNullOrEmpty($mailnotification) -and -not [String]::IsNullOrWhiteSpace($mailnotification)) { $Options.Add('mailnotification', $mailnotification) }
	if ($mailto -and -not [String]::IsNullOrEmpty($mailto) -and -not [String]::IsNullOrWhiteSpace($mailto)) { $Options.Add('mailto', $mailto) }
	if ($maxfiles -and -not [String]::IsNullOrEmpty($maxfiles) -and -not [String]::IsNullOrWhiteSpace($maxfiles)) { $Options.Add('maxfiles', $maxfiles) }
	if ($mode -and -not [String]::IsNullOrEmpty($mode) -and -not [String]::IsNullOrWhiteSpace($mode)) { $Options.Add('mode', $mode) }
	if ($node -and -not [String]::IsNullOrEmpty($node) -and -not [String]::IsNullOrWhiteSpace($node)) { $Options.Add('node', $node) }
	if ($pigz -and -not [String]::IsNullOrEmpty($pigz) -and -not [String]::IsNullOrWhiteSpace($pigz)) { $Options.Add('pigz', $pigz) }
	if ($pool -and -not [String]::IsNullOrEmpty($pool) -and -not [String]::IsNullOrWhiteSpace($pool)) { $Options.Add('pool', $pool) }
	if ($prunebackups -and -not [String]::IsNullOrEmpty($prunebackups) -and -not [String]::IsNullOrWhiteSpace($prunebackups)) { $Options.Add('prune-backups', $prunebackups) }
	if ($quiet) { $Options.Add('quiet', $quiet) }
	if ($remove) { $Options.Add('remove', $remove) }
	if ($script -and -not [String]::IsNullOrEmpty($script) -and -not [String]::IsNullOrWhiteSpace($script)) { $Options.Add('script', $script) }
	if ($stdexcludes) { $Options.Add('stdexcludes', $stdexcludes) }
	if ($stdout) { $Options.Add('stdout', $stdout) }
	if ($stop) { $Options.Add('stop', $stop) }
	if ($stopwait -and -not [String]::IsNullOrEmpty($stopwait) -and -not [String]::IsNullOrWhiteSpace($stopwait)) { $Options.Add('stopwait', $stopwait) }
	if ($storage -and -not [String]::IsNullOrEmpty($storage) -and -not [String]::IsNullOrWhiteSpace($storage)) { $Options.Add('storage', $storage) }
	if ($tmpdir -and -not [String]::IsNullOrEmpty($tmpdir) -and -not [String]::IsNullOrWhiteSpace($tmpdir)) { $Options.Add('tmpdir', $tmpdir) }
	if ($vmid -and -not [String]::IsNullOrEmpty($vmid) -and -not [String]::IsNullOrWhiteSpace($vmid)) { $Options.Add('vmid', $vmid) }
	if ($zstd -and -not [String]::IsNullOrEmpty($zstd) -and -not [String]::IsNullOrWhiteSpace($zstd)) { $Options.Add('zstd', $zstd) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/vzdump" -Options $Options
}
function Get-NodeCephMds {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/ceph/mds" -Options $Options
}
function New-NodeCephMdsName {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Determines whether a ceph-mds daemon should poll and replay the log of an active MDS. Faster switch on MDS failure, but needs more idle resources.
		[switch]
		$hotstandby,
		# The ID for the mds, when omitted the same as the nodename
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($hotstandby) { $Options.Add('hotstandby', $hotstandby) }
	if ($name -and -not [String]::IsNullOrEmpty($name) -and -not [String]::IsNullOrWhiteSpace($name)) { $Options.Add('name', $name) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/ceph/mds/{name}" -Options $Options
}
function Remove-NodeCephMdsName {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The name (ID) of the mds
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/ceph/mds/{name}" -Options $Options
}
function Get-NodeServices {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/services" -Options $Options
}
function Get-NodeCephMgr {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/ceph/mgr" -Options $Options
}
function New-NodeCephMgrId {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# The ID for the manager, when omitted the same as the nodename
		[string]
		$id,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($id -and -not [String]::IsNullOrEmpty($id) -and -not [String]::IsNullOrWhiteSpace($id)) { $Options.Add('id', $id) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/ceph/mgr/{id}" -Options $Options
}
function Remove-NodeCephMgrId {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The ID of the manager
		[string]
		$id,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('id', $id)
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/ceph/mgr/{id}" -Options $Options
}
function Get-NodeSubscription {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/subscription" -Options $Options
}
function New-NodeSubscription {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($force) { $Options.Add('force', $force) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/subscription" -Options $Options
}
function Set-NodeSubscription {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Proxmox VE subscription key
		[string]
		$key,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('key', $key)
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/subscription" -Options $Options
}
function Remove-NodeSubscription {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/subscription" -Options $Options
}
function Get-NodeCephMon {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/ceph/mon" -Options $Options
}
function New-NodeCephMonMonid {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Overwrites autodetected monitor IP address(es). Must be in the public network(s) of Ceph.
		[string]
		$monaddress,
		# The ID for the monitor, when omitted the same as the nodename
		[string]
		$monid,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($monaddress -and -not [String]::IsNullOrEmpty($monaddress) -and -not [String]::IsNullOrWhiteSpace($monaddress)) { $Options.Add('mon-address', $monaddress) }
	if ($monid -and -not [String]::IsNullOrEmpty($monid) -and -not [String]::IsNullOrWhiteSpace($monid)) { $Options.Add('monid', $monid) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/ceph/mon/{monid}" -Options $Options
}
function Remove-NodeCephMonMonid {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# Monitor ID
		[string]
		$monid,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('monid', $monid)
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/ceph/mon/{monid}" -Options $Options
}
function Get-NodeNetwork {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Only list specific interface types.
		[string]
		$type
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($type -and -not [String]::IsNullOrEmpty($type) -and -not [String]::IsNullOrWhiteSpace($type)) { $Options.Add('type', $type) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/network" -Options $Options
}
function New-NodeNetwork {
	[CmdletBinding()]
	param(
		# IP address.
		[string]
		$address,
		# IP address.
		[string]
		$address6,
		# Automatically start interface on boot.
		[switch]
		$autostart,
		# Specify the primary interface for active-backup bond.
		[string]
		$bondprimary,
		# Bonding mode.
		[string]
		$bond_mode,
		# Selects the transmit hash policy to use for slave selection in balance-xor and 802.3ad modes.
		[string]
		$bond_xmit_hash_policy,
		# Specify the interfaces you want to add to your bridge.
		[string]
		$bridge_ports,
		# Enable bridge vlan support.
		[switch]
		$bridge_vlan_aware,
		# IPv4 CIDR.
		[string]
		$cidr,
		# IPv6 CIDR.
		[string]
		$cidr6,
		# Comments
		[string]
		$comments,
		# Comments
		[string]
		$comments6,
		# Default gateway address.
		[string]
		$gateway,
		# Default ipv6 gateway address.
		[string]
		$gateway6,
		[Parameter(Mandatory)]
		# Network interface name.
		[string]
		$iface,
		# MTU.
		[integer]
		$mtu,
		# Network mask.
		[string]
		$netmask,
		# Network mask.
		[integer]
		$netmask6,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Specify the interfaces used by the bonding device.
		[string]
		$ovs_bonds,
		# The OVS bridge associated with a OVS port. This is required when you create an OVS port.
		[string]
		$ovs_bridge,
		# OVS interface options.
		[string]
		$ovs_options,
		# Specify the interfaces you want to add to your bridge.
		[string]
		$ovs_ports,
		# Specify a VLan tag (used by OVSPort, OVSIntPort, OVSBond)
		[integer]
		$ovs_tag,
		# Specify the interfaces used by the bonding device.
		[string]
		$slaves,
		[Parameter(Mandatory)]
		# Network interface type
		[string]
		$type,
		# vlan-id for a custom named vlan interface (ifupdown2 only).
		[integer]
		$vlanid,
		# Specify the raw interface for the vlan interface.
		[string]
		$vlanrawdevice
	)
	$Options = @()
	$Options.Add('iface', $iface)
	$Options.Add('node', $node)
	$Options.Add('type', $type)
	if ($address -and -not [String]::IsNullOrEmpty($address) -and -not [String]::IsNullOrWhiteSpace($address)) { $Options.Add('address', $address) }
	if ($address6 -and -not [String]::IsNullOrEmpty($address6) -and -not [String]::IsNullOrWhiteSpace($address6)) { $Options.Add('address6', $address6) }
	if ($autostart) { $Options.Add('autostart', $autostart) }
	if ($bondprimary -and -not [String]::IsNullOrEmpty($bondprimary) -and -not [String]::IsNullOrWhiteSpace($bondprimary)) { $Options.Add('bond-primary', $bondprimary) }
	if ($bond_mode -and -not [String]::IsNullOrEmpty($bond_mode) -and -not [String]::IsNullOrWhiteSpace($bond_mode)) { $Options.Add('bond_mode', $bond_mode) }
	if ($bond_xmit_hash_policy -and -not [String]::IsNullOrEmpty($bond_xmit_hash_policy) -and -not [String]::IsNullOrWhiteSpace($bond_xmit_hash_policy)) { $Options.Add('bond_xmit_hash_policy', $bond_xmit_hash_policy) }
	if ($bridge_ports -and -not [String]::IsNullOrEmpty($bridge_ports) -and -not [String]::IsNullOrWhiteSpace($bridge_ports)) { $Options.Add('bridge_ports', $bridge_ports) }
	if ($bridge_vlan_aware) { $Options.Add('bridge_vlan_aware', $bridge_vlan_aware) }
	if ($cidr -and -not [String]::IsNullOrEmpty($cidr) -and -not [String]::IsNullOrWhiteSpace($cidr)) { $Options.Add('cidr', $cidr) }
	if ($cidr6 -and -not [String]::IsNullOrEmpty($cidr6) -and -not [String]::IsNullOrWhiteSpace($cidr6)) { $Options.Add('cidr6', $cidr6) }
	if ($comments -and -not [String]::IsNullOrEmpty($comments) -and -not [String]::IsNullOrWhiteSpace($comments)) { $Options.Add('comments', $comments) }
	if ($comments6 -and -not [String]::IsNullOrEmpty($comments6) -and -not [String]::IsNullOrWhiteSpace($comments6)) { $Options.Add('comments6', $comments6) }
	if ($gateway -and -not [String]::IsNullOrEmpty($gateway) -and -not [String]::IsNullOrWhiteSpace($gateway)) { $Options.Add('gateway', $gateway) }
	if ($gateway6 -and -not [String]::IsNullOrEmpty($gateway6) -and -not [String]::IsNullOrWhiteSpace($gateway6)) { $Options.Add('gateway6', $gateway6) }
	if ($mtu -and -not [String]::IsNullOrEmpty($mtu) -and -not [String]::IsNullOrWhiteSpace($mtu)) { $Options.Add('mtu', $mtu) }
	if ($netmask -and -not [String]::IsNullOrEmpty($netmask) -and -not [String]::IsNullOrWhiteSpace($netmask)) { $Options.Add('netmask', $netmask) }
	if ($netmask6 -and -not [String]::IsNullOrEmpty($netmask6) -and -not [String]::IsNullOrWhiteSpace($netmask6)) { $Options.Add('netmask6', $netmask6) }
	if ($ovs_bonds -and -not [String]::IsNullOrEmpty($ovs_bonds) -and -not [String]::IsNullOrWhiteSpace($ovs_bonds)) { $Options.Add('ovs_bonds', $ovs_bonds) }
	if ($ovs_bridge -and -not [String]::IsNullOrEmpty($ovs_bridge) -and -not [String]::IsNullOrWhiteSpace($ovs_bridge)) { $Options.Add('ovs_bridge', $ovs_bridge) }
	if ($ovs_options -and -not [String]::IsNullOrEmpty($ovs_options) -and -not [String]::IsNullOrWhiteSpace($ovs_options)) { $Options.Add('ovs_options', $ovs_options) }
	if ($ovs_ports -and -not [String]::IsNullOrEmpty($ovs_ports) -and -not [String]::IsNullOrWhiteSpace($ovs_ports)) { $Options.Add('ovs_ports', $ovs_ports) }
	if ($ovs_tag -and -not [String]::IsNullOrEmpty($ovs_tag) -and -not [String]::IsNullOrWhiteSpace($ovs_tag)) { $Options.Add('ovs_tag', $ovs_tag) }
	if ($slaves -and -not [String]::IsNullOrEmpty($slaves) -and -not [String]::IsNullOrWhiteSpace($slaves)) { $Options.Add('slaves', $slaves) }
	if ($vlanid -and -not [String]::IsNullOrEmpty($vlanid) -and -not [String]::IsNullOrWhiteSpace($vlanid)) { $Options.Add('vlan-id', $vlanid) }
	if ($vlanrawdevice -and -not [String]::IsNullOrEmpty($vlanrawdevice) -and -not [String]::IsNullOrWhiteSpace($vlanrawdevice)) { $Options.Add('vlan-raw-device', $vlanrawdevice) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/network" -Options $Options
}
function Set-NodeNetwork {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/network" -Options $Options
}
function Remove-NodeNetwork {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/network" -Options $Options
}
function Get-NodeCephFs {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/ceph/fs" -Options $Options
}
function New-NodeCephFsName {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Configure the created CephFS as storage for this cluster.
		[switch]
		$addstorage,
		# The ceph filesystem name.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Number of placement groups for the backing data pool. The metadata pool will use a quarter of this.
		[integer]
		$pg_num
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($addstorage) { $Options.Add('add-storage', $addstorage) }
	if ($name -and -not [String]::IsNullOrEmpty($name) -and -not [String]::IsNullOrWhiteSpace($name)) { $Options.Add('name', $name) }
	if ($pg_num -and -not [String]::IsNullOrEmpty($pg_num) -and -not [String]::IsNullOrWhiteSpace($pg_num)) { $Options.Add('pg_num', $pg_num) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/ceph/fs/{name}" -Options $Options
}
function Get-NodeTasks {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# Only list tasks with a status of ERROR.
		[switch]
		$errors,
		# Only list this amount of tasks.
		[integer]
		$limit,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Only list tasks since this UNIX epoch.
		[integer]
		$since,
		# List archived, active or all tasks.
		[string]
		$source,
		# List tasks beginning from this offset.
		[integer]
		$start,
		# List of Task States that should be returned.
		[string]
		$statusfilter,
		# Only list tasks of this type (e.g., vzstart, vzdump).
		[string]
		$typefilter,
		# Only list tasks until this UNIX epoch.
		[integer]
		$until,
		# Only list tasks from this user.
		[string]
		$userfilter,
		# Only list tasks for this VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($errors) { $Options.Add('errors', $errors) }
	if ($limit -and -not [String]::IsNullOrEmpty($limit) -and -not [String]::IsNullOrWhiteSpace($limit)) { $Options.Add('limit', $limit) }
	if ($since -and -not [String]::IsNullOrEmpty($since) -and -not [String]::IsNullOrWhiteSpace($since)) { $Options.Add('since', $since) }
	if ($source -and -not [String]::IsNullOrEmpty($source) -and -not [String]::IsNullOrWhiteSpace($source)) { $Options.Add('source', $source) }
	if ($start -and -not [String]::IsNullOrEmpty($start) -and -not [String]::IsNullOrWhiteSpace($start)) { $Options.Add('start', $start) }
	if ($statusfilter -and -not [String]::IsNullOrEmpty($statusfilter) -and -not [String]::IsNullOrWhiteSpace($statusfilter)) { $Options.Add('statusfilter', $statusfilter) }
	if ($typefilter -and -not [String]::IsNullOrEmpty($typefilter) -and -not [String]::IsNullOrWhiteSpace($typefilter)) { $Options.Add('typefilter', $typefilter) }
	if ($until -and -not [String]::IsNullOrEmpty($until) -and -not [String]::IsNullOrWhiteSpace($until)) { $Options.Add('until', $until) }
	if ($userfilter -and -not [String]::IsNullOrEmpty($userfilter) -and -not [String]::IsNullOrWhiteSpace($userfilter)) { $Options.Add('userfilter', $userfilter) }
	if ($vmid -and -not [String]::IsNullOrEmpty($vmid) -and -not [String]::IsNullOrWhiteSpace($vmid)) { $Options.Add('vmid', $vmid) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/tasks" -Options $Options
}
function Get-NodeCephPools {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/ceph/pools" -Options $Options
}
function New-NodeCephPools {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Configure VM and CT storage using the new pool.
		[switch]
		$add_storages,
		# The application of the pool.
		[string]
		$application,
		# The rule to use for mapping object placement in the cluster.
		[string]
		$crush_rule,
		# Minimum number of replicas per object
		[integer]
		$min_size,
		[Parameter(Mandatory)]
		# The name of the pool. It must be unique.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# The automatic PG scaling mode of the pool.
		[string]
		$pg_autoscale_mode,
		# Number of placement groups.
		[integer]
		$pg_num,
		# Minimal number of placement groups.
		[integer]
		$pg_num_min,
		# Number of replicas per object
		[integer]
		$size,
		# The estimated target size of the pool for the PG autoscaler.
		[string]
		$target_size,
		# The estimated target ratio of the pool for the PG autoscaler.
		[number]
		$target_size_ratio
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	if ($add_storages) { $Options.Add('add_storages', $add_storages) }
	if ($application -and -not [String]::IsNullOrEmpty($application) -and -not [String]::IsNullOrWhiteSpace($application)) { $Options.Add('application', $application) }
	if ($crush_rule -and -not [String]::IsNullOrEmpty($crush_rule) -and -not [String]::IsNullOrWhiteSpace($crush_rule)) { $Options.Add('crush_rule', $crush_rule) }
	if ($min_size -and -not [String]::IsNullOrEmpty($min_size) -and -not [String]::IsNullOrWhiteSpace($min_size)) { $Options.Add('min_size', $min_size) }
	if ($pg_autoscale_mode -and -not [String]::IsNullOrEmpty($pg_autoscale_mode) -and -not [String]::IsNullOrWhiteSpace($pg_autoscale_mode)) { $Options.Add('pg_autoscale_mode', $pg_autoscale_mode) }
	if ($pg_num -and -not [String]::IsNullOrEmpty($pg_num) -and -not [String]::IsNullOrWhiteSpace($pg_num)) { $Options.Add('pg_num', $pg_num) }
	if ($pg_num_min -and -not [String]::IsNullOrEmpty($pg_num_min) -and -not [String]::IsNullOrWhiteSpace($pg_num_min)) { $Options.Add('pg_num_min', $pg_num_min) }
	if ($size -and -not [String]::IsNullOrEmpty($size) -and -not [String]::IsNullOrWhiteSpace($size)) { $Options.Add('size', $size) }
	if ($target_size -and -not [String]::IsNullOrEmpty($target_size) -and -not [String]::IsNullOrWhiteSpace($target_size)) { $Options.Add('target_size', $target_size) }
	if ($target_size_ratio -and -not [String]::IsNullOrEmpty($target_size_ratio) -and -not [String]::IsNullOrWhiteSpace($target_size_ratio)) { $Options.Add('target_size_ratio', $target_size_ratio) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/ceph/pools" -Options $Options
}
function Get-NodeCephPoolsName {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The name of the pool. It must be unique.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	if ($verbose) { $Options.Add('verbose', $verbose) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/ceph/pools/{name}" -Options $Options
}
function Set-NodeCephPoolsName {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# The application of the pool.
		[string]
		$application,
		# The rule to use for mapping object placement in the cluster.
		[string]
		$crush_rule,
		# Minimum number of replicas per object
		[integer]
		$min_size,
		[Parameter(Mandatory)]
		# The name of the pool. It must be unique.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# The automatic PG scaling mode of the pool.
		[string]
		$pg_autoscale_mode,
		# Number of placement groups.
		[integer]
		$pg_num,
		# Minimal number of placement groups.
		[integer]
		$pg_num_min,
		# Number of replicas per object
		[integer]
		$size,
		# The estimated target size of the pool for the PG autoscaler.
		[string]
		$target_size,
		# The estimated target ratio of the pool for the PG autoscaler.
		[number]
		$target_size_ratio
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	if ($application -and -not [String]::IsNullOrEmpty($application) -and -not [String]::IsNullOrWhiteSpace($application)) { $Options.Add('application', $application) }
	if ($crush_rule -and -not [String]::IsNullOrEmpty($crush_rule) -and -not [String]::IsNullOrWhiteSpace($crush_rule)) { $Options.Add('crush_rule', $crush_rule) }
	if ($min_size -and -not [String]::IsNullOrEmpty($min_size) -and -not [String]::IsNullOrWhiteSpace($min_size)) { $Options.Add('min_size', $min_size) }
	if ($pg_autoscale_mode -and -not [String]::IsNullOrEmpty($pg_autoscale_mode) -and -not [String]::IsNullOrWhiteSpace($pg_autoscale_mode)) { $Options.Add('pg_autoscale_mode', $pg_autoscale_mode) }
	if ($pg_num -and -not [String]::IsNullOrEmpty($pg_num) -and -not [String]::IsNullOrWhiteSpace($pg_num)) { $Options.Add('pg_num', $pg_num) }
	if ($pg_num_min -and -not [String]::IsNullOrEmpty($pg_num_min) -and -not [String]::IsNullOrWhiteSpace($pg_num_min)) { $Options.Add('pg_num_min', $pg_num_min) }
	if ($size -and -not [String]::IsNullOrEmpty($size) -and -not [String]::IsNullOrWhiteSpace($size)) { $Options.Add('size', $size) }
	if ($target_size -and -not [String]::IsNullOrEmpty($target_size) -and -not [String]::IsNullOrWhiteSpace($target_size)) { $Options.Add('target_size', $target_size) }
	if ($target_size_ratio -and -not [String]::IsNullOrEmpty($target_size_ratio) -and -not [String]::IsNullOrWhiteSpace($target_size_ratio)) { $Options.Add('target_size_ratio', $target_size_ratio) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/ceph/pools/{name}" -Options $Options
}
function Remove-NodeCephPoolsName {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The name of the pool. It must be unique.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Remove all pveceph-managed storages configured for this pool
		[switch]
		$remove_storages
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	if ($force) { $Options.Add('force', $force) }
	if ($remove_storages) { $Options.Add('remove_storages', $remove_storages) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/ceph/pools/{name}" -Options $Options
}
function Get-NodeScan {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/scan" -Options $Options
}
function Get-NodeCephConfig {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/ceph/config" -Options $Options
}
function Get-NodeHardware {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/hardware" -Options $Options
}
function Get-NodeCephConfigdb {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/ceph/configdb" -Options $Options
}
function Get-NodeCapabilities {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/capabilities" -Options $Options
}
function New-NodeCephInit {
	[CmdletBinding()]
	param(
		# Declare a separate cluster network, OSDs will routeheartbeat, object replication and recovery traffic over it
		[string]
		$clusternetwork,
		# Disable cephx authentication.
		[switch]
		$disable_cephx,
		# Minimum number of available replicas per object to allow I/O
		[integer]
		$min_size,
		# Use specific network for all ceph related traffic
		[string]
		$network,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Placement group bits, used to specify the default number of placement groups.
		[integer]
		$pg_bits,
		# Targeted number of replicas per object
		[integer]
		$size
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($clusternetwork -and -not [String]::IsNullOrEmpty($clusternetwork) -and -not [String]::IsNullOrWhiteSpace($clusternetwork)) { $Options.Add('cluster-network', $clusternetwork) }
	if ($disable_cephx) { $Options.Add('disable_cephx', $disable_cephx) }
	if ($min_size -and -not [String]::IsNullOrEmpty($min_size) -and -not [String]::IsNullOrWhiteSpace($min_size)) { $Options.Add('min_size', $min_size) }
	if ($network -and -not [String]::IsNullOrEmpty($network) -and -not [String]::IsNullOrWhiteSpace($network)) { $Options.Add('network', $network) }
	if ($pg_bits -and -not [String]::IsNullOrEmpty($pg_bits) -and -not [String]::IsNullOrWhiteSpace($pg_bits)) { $Options.Add('pg_bits', $pg_bits) }
	if ($size -and -not [String]::IsNullOrEmpty($size) -and -not [String]::IsNullOrWhiteSpace($size)) { $Options.Add('size', $size) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/ceph/init" -Options $Options
}
function Get-NodeStorage {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# Only list stores which support this content type.
		[string]
		$content,
		# Only list stores which are enabled (not disabled in config).
		[switch]
		$enabled,
		# Include information about formats
		[switch]
		$format,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Only list status for  specified storage
		[string]
		$storage,
		# If target is different to 'node', we only lists shared storages which content is accessible on this 'node' and the specified 'target' node.
		[string]
		$target
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($content -and -not [String]::IsNullOrEmpty($content) -and -not [String]::IsNullOrWhiteSpace($content)) { $Options.Add('content', $content) }
	if ($enabled) { $Options.Add('enabled', $enabled) }
	if ($format) { $Options.Add('format', $format) }
	if ($storage -and -not [String]::IsNullOrEmpty($storage) -and -not [String]::IsNullOrWhiteSpace($storage)) { $Options.Add('storage', $storage) }
	if ($target -and -not [String]::IsNullOrEmpty($target) -and -not [String]::IsNullOrWhiteSpace($target)) { $Options.Add('target', $target) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/storage" -Options $Options
}
function New-NodeCephStop {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Ceph service name.
		[string]
		$service
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($service -and -not [String]::IsNullOrEmpty($service) -and -not [String]::IsNullOrWhiteSpace($service)) { $Options.Add('service', $service) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/ceph/stop" -Options $Options
}
function Get-NodeDisks {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/disks" -Options $Options
}
function New-NodeCephStart {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Ceph service name.
		[string]
		$service
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($service -and -not [String]::IsNullOrEmpty($service) -and -not [String]::IsNullOrWhiteSpace($service)) { $Options.Add('service', $service) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/ceph/start" -Options $Options
}
function Get-NodeApt {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/apt" -Options $Options
}
function New-NodeCephRestart {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Ceph service name.
		[string]
		$service
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($service -and -not [String]::IsNullOrEmpty($service) -and -not [String]::IsNullOrWhiteSpace($service)) { $Options.Add('service', $service) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/ceph/restart" -Options $Options
}
function Get-NodeFirewall {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/firewall" -Options $Options
}
function Get-NodeCephStatus {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/ceph/status" -Options $Options
}
function Get-NodeReplication {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# Only list replication jobs for this guest.
		[integer]
		$guest,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($guest -and -not [String]::IsNullOrEmpty($guest) -and -not [String]::IsNullOrWhiteSpace($guest)) { $Options.Add('guest', $guest) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/replication" -Options $Options
}
function Get-NodeCephCrush {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/ceph/crush" -Options $Options
}
function Get-NodeCertificates {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/certificates" -Options $Options
}
function Get-NodeCephLog {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# 
		[integer]
		$limit,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# 
		[integer]
		$start
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($limit -and -not [String]::IsNullOrEmpty($limit) -and -not [String]::IsNullOrWhiteSpace($limit)) { $Options.Add('limit', $limit) }
	if ($start -and -not [String]::IsNullOrEmpty($start) -and -not [String]::IsNullOrWhiteSpace($start)) { $Options.Add('start', $start) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/ceph/log" -Options $Options
}
function Get-NodeConfig {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Return only a specific property from the node configuration.
		[string]
		$property
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($property -and -not [String]::IsNullOrEmpty($property) -and -not [String]::IsNullOrWhiteSpace($property)) { $Options.Add('property', $property) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/config" -Options $Options
}
function Set-NodeConfig {
	[CmdletBinding()]
	param(
		# Node specific ACME settings.
		[string]
		$acme,
		# ACME domain and validation plugin
		[string]
		$acmedomain0,
		# ACME domain and validation plugin
		[string]
		$acmedomain1,
		# ACME domain and validation plugin
		[string]
		$acmedomain2,
		# ACME domain and validation plugin
		[string]
		$acmedomain3,
		# ACME domain and validation plugin
		[string]
		$acmedomain4,
		# ACME domain and validation plugin
		[string]
		$acmedomain5,
		# ACME domain and validation plugin
		[string]
		$acmedomain6,
		# ACME domain and validation plugin
		[string]
		$acmedomain7,
		# ACME domain and validation plugin
		[string]
		$acmedomain8,
		# ACME domain and validation plugin
		[string]
		$acmedomain9,
		# ACME domain and validation plugin
		[string]
		$acmedomain10,
		# A list of settings you want to delete.
		[string]
		$delete,
		# Description for the Node. Shown in the web-interface node notes panel. This is saved as comment inside the configuration file.
		[string]
		$description,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Initial delay in seconds, before starting all the Virtual Guests with on-boot enabled.
		[integer]
		$startallonbootdelay,
		# MAC address for wake on LAN
		[string]
		$wakeonlan
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($acme -and -not [String]::IsNullOrEmpty($acme) -and -not [String]::IsNullOrWhiteSpace($acme)) { $Options.Add('acme', $acme) }
	if ($acmedomain0 -and -not [String]::IsNullOrEmpty($acmedomain0) -and -not [String]::IsNullOrWhiteSpace($acmedomain0)) { $Options.Add('acmedomain0', $acmedomain0) }
	if ($acmedomain1 -and -not [String]::IsNullOrEmpty($acmedomain1) -and -not [String]::IsNullOrWhiteSpace($acmedomain1)) { $Options.Add('acmedomain1', $acmedomain1) }
	if ($acmedomain2 -and -not [String]::IsNullOrEmpty($acmedomain2) -and -not [String]::IsNullOrWhiteSpace($acmedomain2)) { $Options.Add('acmedomain2', $acmedomain2) }
	if ($acmedomain3 -and -not [String]::IsNullOrEmpty($acmedomain3) -and -not [String]::IsNullOrWhiteSpace($acmedomain3)) { $Options.Add('acmedomain3', $acmedomain3) }
	if ($acmedomain4 -and -not [String]::IsNullOrEmpty($acmedomain4) -and -not [String]::IsNullOrWhiteSpace($acmedomain4)) { $Options.Add('acmedomain4', $acmedomain4) }
	if ($acmedomain5 -and -not [String]::IsNullOrEmpty($acmedomain5) -and -not [String]::IsNullOrWhiteSpace($acmedomain5)) { $Options.Add('acmedomain5', $acmedomain5) }
	if ($acmedomain6 -and -not [String]::IsNullOrEmpty($acmedomain6) -and -not [String]::IsNullOrWhiteSpace($acmedomain6)) { $Options.Add('acmedomain6', $acmedomain6) }
	if ($acmedomain7 -and -not [String]::IsNullOrEmpty($acmedomain7) -and -not [String]::IsNullOrWhiteSpace($acmedomain7)) { $Options.Add('acmedomain7', $acmedomain7) }
	if ($acmedomain8 -and -not [String]::IsNullOrEmpty($acmedomain8) -and -not [String]::IsNullOrWhiteSpace($acmedomain8)) { $Options.Add('acmedomain8', $acmedomain8) }
	if ($acmedomain9 -and -not [String]::IsNullOrEmpty($acmedomain9) -and -not [String]::IsNullOrWhiteSpace($acmedomain9)) { $Options.Add('acmedomain9', $acmedomain9) }
	if ($acmedomain10 -and -not [String]::IsNullOrEmpty($acmedomain10) -and -not [String]::IsNullOrWhiteSpace($acmedomain10)) { $Options.Add('acmedomain10', $acmedomain10) }
	if ($delete -and -not [String]::IsNullOrEmpty($delete) -and -not [String]::IsNullOrWhiteSpace($delete)) { $Options.Add('delete', $delete) }
	if ($description -and -not [String]::IsNullOrEmpty($description) -and -not [String]::IsNullOrWhiteSpace($description)) { $Options.Add('description', $description) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($startallonbootdelay -and -not [String]::IsNullOrEmpty($startallonbootdelay) -and -not [String]::IsNullOrWhiteSpace($startallonbootdelay)) { $Options.Add('startall-onboot-delay', $startallonbootdelay) }
	if ($wakeonlan -and -not [String]::IsNullOrEmpty($wakeonlan) -and -not [String]::IsNullOrWhiteSpace($wakeonlan)) { $Options.Add('wakeonlan', $wakeonlan) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/config" -Options $Options
}
function Get-NodeCephRules {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/ceph/rules" -Options $Options
}
function Get-NodeSdn {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/sdn" -Options $Options
}
function Get-NodeVzdumpDefaults {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# The storage identifier.
		[string]
		$storage
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($storage -and -not [String]::IsNullOrEmpty($storage) -and -not [String]::IsNullOrWhiteSpace($storage)) { $Options.Add('storage', $storage) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/vzdump/defaults" -Options $Options
}
function Get-NodeVersion {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/version" -Options $Options
}
function Get-NodeVzdumpExtractconfig {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Volume identifier
		[string]
		$volume
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('volume', $volume)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/vzdump/extractconfig" -Options $Options
}
function Get-NodeStatus {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/status" -Options $Options
}
function New-NodeStatus {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Specify the command.
		[string]
		$command,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('command', $command)
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/status" -Options $Options
}
function Get-NodeServicesService {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Service ID
		[string]
		$service
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('service', $service)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/services/{service}" -Options $Options
}
function Get-NodeServicesServiceState {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Service ID
		[string]
		$service
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('service', $service)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/services/{service}/state" -Options $Options
}
function New-NodeServicesServiceStart {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Service ID
		[string]
		$service
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('service', $service)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/services/{service}/start" -Options $Options
}
function New-NodeServicesServiceStop {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Service ID
		[string]
		$service
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('service', $service)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/services/{service}/stop" -Options $Options
}
function New-NodeServicesServiceRestart {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Service ID
		[string]
		$service
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('service', $service)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/services/{service}/restart" -Options $Options
}
function New-NodeServicesServiceReload {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Service ID
		[string]
		$service
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('service', $service)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/services/{service}/reload" -Options $Options
}
function Get-NodeNetstat {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/netstat" -Options $Options
}
function New-NodeExecute {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# JSON encoded array of commands.
		[string]
		$commands,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('commands', $commands)
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/execute" -Options $Options
}
function Get-NodeNetworkIface {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# Network interface name.
		[string]
		$iface,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('iface', $iface)
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/network/{iface}" -Options $Options
}
function Set-NodeNetworkIface {
	[CmdletBinding()]
	param(
		# IP address.
		[string]
		$address,
		# IP address.
		[string]
		$address6,
		# Automatically start interface on boot.
		[switch]
		$autostart,
		# Specify the primary interface for active-backup bond.
		[string]
		$bondprimary,
		# Bonding mode.
		[string]
		$bond_mode,
		# Selects the transmit hash policy to use for slave selection in balance-xor and 802.3ad modes.
		[string]
		$bond_xmit_hash_policy,
		# Specify the interfaces you want to add to your bridge.
		[string]
		$bridge_ports,
		# Enable bridge vlan support.
		[switch]
		$bridge_vlan_aware,
		# IPv4 CIDR.
		[string]
		$cidr,
		# IPv6 CIDR.
		[string]
		$cidr6,
		# Comments
		[string]
		$comments,
		# Comments
		[string]
		$comments6,
		# A list of settings you want to delete.
		[string]
		$delete,
		# Default gateway address.
		[string]
		$gateway,
		# Default ipv6 gateway address.
		[string]
		$gateway6,
		[Parameter(Mandatory)]
		# Network interface name.
		[string]
		$iface,
		# MTU.
		[integer]
		$mtu,
		# Network mask.
		[string]
		$netmask,
		# Network mask.
		[integer]
		$netmask6,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Specify the interfaces used by the bonding device.
		[string]
		$ovs_bonds,
		# The OVS bridge associated with a OVS port. This is required when you create an OVS port.
		[string]
		$ovs_bridge,
		# OVS interface options.
		[string]
		$ovs_options,
		# Specify the interfaces you want to add to your bridge.
		[string]
		$ovs_ports,
		# Specify a VLan tag (used by OVSPort, OVSIntPort, OVSBond)
		[integer]
		$ovs_tag,
		# Specify the interfaces used by the bonding device.
		[string]
		$slaves,
		[Parameter(Mandatory)]
		# Network interface type
		[string]
		$type,
		# vlan-id for a custom named vlan interface (ifupdown2 only).
		[integer]
		$vlanid,
		# Specify the raw interface for the vlan interface.
		[string]
		$vlanrawdevice
	)
	$Options = @()
	$Options.Add('iface', $iface)
	$Options.Add('node', $node)
	$Options.Add('type', $type)
	if ($address -and -not [String]::IsNullOrEmpty($address) -and -not [String]::IsNullOrWhiteSpace($address)) { $Options.Add('address', $address) }
	if ($address6 -and -not [String]::IsNullOrEmpty($address6) -and -not [String]::IsNullOrWhiteSpace($address6)) { $Options.Add('address6', $address6) }
	if ($autostart) { $Options.Add('autostart', $autostart) }
	if ($bondprimary -and -not [String]::IsNullOrEmpty($bondprimary) -and -not [String]::IsNullOrWhiteSpace($bondprimary)) { $Options.Add('bond-primary', $bondprimary) }
	if ($bond_mode -and -not [String]::IsNullOrEmpty($bond_mode) -and -not [String]::IsNullOrWhiteSpace($bond_mode)) { $Options.Add('bond_mode', $bond_mode) }
	if ($bond_xmit_hash_policy -and -not [String]::IsNullOrEmpty($bond_xmit_hash_policy) -and -not [String]::IsNullOrWhiteSpace($bond_xmit_hash_policy)) { $Options.Add('bond_xmit_hash_policy', $bond_xmit_hash_policy) }
	if ($bridge_ports -and -not [String]::IsNullOrEmpty($bridge_ports) -and -not [String]::IsNullOrWhiteSpace($bridge_ports)) { $Options.Add('bridge_ports', $bridge_ports) }
	if ($bridge_vlan_aware) { $Options.Add('bridge_vlan_aware', $bridge_vlan_aware) }
	if ($cidr -and -not [String]::IsNullOrEmpty($cidr) -and -not [String]::IsNullOrWhiteSpace($cidr)) { $Options.Add('cidr', $cidr) }
	if ($cidr6 -and -not [String]::IsNullOrEmpty($cidr6) -and -not [String]::IsNullOrWhiteSpace($cidr6)) { $Options.Add('cidr6', $cidr6) }
	if ($comments -and -not [String]::IsNullOrEmpty($comments) -and -not [String]::IsNullOrWhiteSpace($comments)) { $Options.Add('comments', $comments) }
	if ($comments6 -and -not [String]::IsNullOrEmpty($comments6) -and -not [String]::IsNullOrWhiteSpace($comments6)) { $Options.Add('comments6', $comments6) }
	if ($delete -and -not [String]::IsNullOrEmpty($delete) -and -not [String]::IsNullOrWhiteSpace($delete)) { $Options.Add('delete', $delete) }
	if ($gateway -and -not [String]::IsNullOrEmpty($gateway) -and -not [String]::IsNullOrWhiteSpace($gateway)) { $Options.Add('gateway', $gateway) }
	if ($gateway6 -and -not [String]::IsNullOrEmpty($gateway6) -and -not [String]::IsNullOrWhiteSpace($gateway6)) { $Options.Add('gateway6', $gateway6) }
	if ($mtu -and -not [String]::IsNullOrEmpty($mtu) -and -not [String]::IsNullOrWhiteSpace($mtu)) { $Options.Add('mtu', $mtu) }
	if ($netmask -and -not [String]::IsNullOrEmpty($netmask) -and -not [String]::IsNullOrWhiteSpace($netmask)) { $Options.Add('netmask', $netmask) }
	if ($netmask6 -and -not [String]::IsNullOrEmpty($netmask6) -and -not [String]::IsNullOrWhiteSpace($netmask6)) { $Options.Add('netmask6', $netmask6) }
	if ($ovs_bonds -and -not [String]::IsNullOrEmpty($ovs_bonds) -and -not [String]::IsNullOrWhiteSpace($ovs_bonds)) { $Options.Add('ovs_bonds', $ovs_bonds) }
	if ($ovs_bridge -and -not [String]::IsNullOrEmpty($ovs_bridge) -and -not [String]::IsNullOrWhiteSpace($ovs_bridge)) { $Options.Add('ovs_bridge', $ovs_bridge) }
	if ($ovs_options -and -not [String]::IsNullOrEmpty($ovs_options) -and -not [String]::IsNullOrWhiteSpace($ovs_options)) { $Options.Add('ovs_options', $ovs_options) }
	if ($ovs_ports -and -not [String]::IsNullOrEmpty($ovs_ports) -and -not [String]::IsNullOrWhiteSpace($ovs_ports)) { $Options.Add('ovs_ports', $ovs_ports) }
	if ($ovs_tag -and -not [String]::IsNullOrEmpty($ovs_tag) -and -not [String]::IsNullOrWhiteSpace($ovs_tag)) { $Options.Add('ovs_tag', $ovs_tag) }
	if ($slaves -and -not [String]::IsNullOrEmpty($slaves) -and -not [String]::IsNullOrWhiteSpace($slaves)) { $Options.Add('slaves', $slaves) }
	if ($vlanid -and -not [String]::IsNullOrEmpty($vlanid) -and -not [String]::IsNullOrWhiteSpace($vlanid)) { $Options.Add('vlan-id', $vlanid) }
	if ($vlanrawdevice -and -not [String]::IsNullOrEmpty($vlanrawdevice) -and -not [String]::IsNullOrWhiteSpace($vlanrawdevice)) { $Options.Add('vlan-raw-device', $vlanrawdevice) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/network/{iface}" -Options $Options
}
function Remove-NodeNetworkIface {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Network interface name.
		[string]
		$iface,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('iface', $iface)
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/network/{iface}" -Options $Options
}
function New-NodeWakeonlan {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# target node for wake on LAN packet
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/wakeonlan" -Options $Options
}
function Get-NodeTasksUpid {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# 
		[string]
		$upid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('upid', $upid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/tasks/{upid}" -Options $Options
}
function Remove-NodeTasksUpid {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# 
		[string]
		$upid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('upid', $upid)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/tasks/{upid}" -Options $Options
}
function Get-NodeTasksLog {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# The maximum amount of lines that should be printed.
		[integer]
		$limit,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# The line number to start printing at.
		[integer]
		$start,
		[Parameter(Mandatory)]
		# The task's unique ID.
		[string]
		$upid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('upid', $upid)
	if ($limit -and -not [String]::IsNullOrEmpty($limit) -and -not [String]::IsNullOrWhiteSpace($limit)) { $Options.Add('limit', $limit) }
	if ($start -and -not [String]::IsNullOrEmpty($start) -and -not [String]::IsNullOrWhiteSpace($start)) { $Options.Add('start', $start) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/tasks/{upid}/log" -Options $Options
}
function Get-NodeTasksStatus {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The task's unique ID.
		[string]
		$upid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('upid', $upid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/tasks/{upid}/status" -Options $Options
}
function Get-NodeRrd {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		# The RRD consolidation function
		[string]
		$cf,
		[Parameter(Mandatory)]
		# The list of datasources you want to display.
		[string]
		$ds,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Specify the time frame you are interested in.
		[string]
		$timeframe
	)
	$Options = @()
	$Options.Add('ds', $ds)
	$Options.Add('node', $node)
	$Options.Add('timeframe', $timeframe)
	if ($cf -and -not [String]::IsNullOrEmpty($cf) -and -not [String]::IsNullOrWhiteSpace($cf)) { $Options.Add('cf', $cf) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/rrd" -Options $Options
}
function Get-NodeScanNfs {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The server address (name or IP).
		[string]
		$server
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('server', $server)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/scan/nfs" -Options $Options
}
function Get-NodeRrddata {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# The RRD consolidation function
		[string]
		$cf,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Specify the time frame you are interested in.
		[string]
		$timeframe
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('timeframe', $timeframe)
	if ($cf -and -not [String]::IsNullOrEmpty($cf) -and -not [String]::IsNullOrWhiteSpace($cf)) { $Options.Add('cf', $cf) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/rrddata" -Options $Options
}
function Get-NodeScanCifs {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# SMB domain (Workgroup).
		[string]
		$domain,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# User password.
		[securestring]
		$password,
		[Parameter(Mandatory)]
		# The server address (name or IP).
		[string]
		$server,
		# User name.
		[string]
		$username
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('server', $server)
	if ($domain -and -not [String]::IsNullOrEmpty($domain) -and -not [String]::IsNullOrWhiteSpace($domain)) { $Options.Add('domain', $domain) }
	if ($password) { $Options.Add('password', $($password | ConvertFrom-SecureString -AsPlainText)) }
	if ($username -and -not [String]::IsNullOrEmpty($username) -and -not [String]::IsNullOrWhiteSpace($username)) { $Options.Add('username', $username) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/scan/cifs" -Options $Options
}
function Get-NodeSyslog {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# 
		[integer]
		$limit,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Service ID
		[string]
		$service,
		# Display all log since this date-time string.
		[string]
		$since,
		# 
		[integer]
		$start,
		# Display all log until this date-time string.
		[string]
		$until
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($limit -and -not [String]::IsNullOrEmpty($limit) -and -not [String]::IsNullOrWhiteSpace($limit)) { $Options.Add('limit', $limit) }
	if ($service -and -not [String]::IsNullOrEmpty($service) -and -not [String]::IsNullOrWhiteSpace($service)) { $Options.Add('service', $service) }
	if ($since -and -not [String]::IsNullOrEmpty($since) -and -not [String]::IsNullOrWhiteSpace($since)) { $Options.Add('since', $since) }
	if ($start -and -not [String]::IsNullOrEmpty($start) -and -not [String]::IsNullOrWhiteSpace($start)) { $Options.Add('start', $start) }
	if ($until -and -not [String]::IsNullOrEmpty($until) -and -not [String]::IsNullOrWhiteSpace($until)) { $Options.Add('until', $until) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/syslog" -Options $Options
}
function Get-NodeScanPbs {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# Certificate SHA 256 fingerprint.
		[string]
		$fingerprint,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# User password or API token secret.
		[securestring]
		$password,
		# Optional port.
		[integer]
		$port,
		[Parameter(Mandatory)]
		# The server address (name or IP).
		[string]
		$server,
		[Parameter(Mandatory)]
		# User-name or API token-ID.
		[string]
		$username
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('password', $password)
	$Options.Add('server', $server)
	$Options.Add('username', $username)
	if ($fingerprint -and -not [String]::IsNullOrEmpty($fingerprint) -and -not [String]::IsNullOrWhiteSpace($fingerprint)) { $Options.Add('fingerprint', $fingerprint) }
	if ($port -and -not [String]::IsNullOrEmpty($port) -and -not [String]::IsNullOrWhiteSpace($port)) { $Options.Add('port', $port) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/scan/pbs" -Options $Options
}
function Get-NodeJournal {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# End before the given Cursor. Conflicts with 'until'
		[string]
		$endcursor,
		# Limit to the last X lines. Conflicts with a range.
		[integer]
		$lastentries,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Display all log since this UNIX epoch. Conflicts with 'startcursor'.
		[integer]
		$since,
		# Start after the given Cursor. Conflicts with 'since'
		[string]
		$startcursor,
		# Display all log until this UNIX epoch. Conflicts with 'endcursor'.
		[integer]
		$until
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($endcursor -and -not [String]::IsNullOrEmpty($endcursor) -and -not [String]::IsNullOrWhiteSpace($endcursor)) { $Options.Add('endcursor', $endcursor) }
	if ($lastentries -and -not [String]::IsNullOrEmpty($lastentries) -and -not [String]::IsNullOrWhiteSpace($lastentries)) { $Options.Add('lastentries', $lastentries) }
	if ($since -and -not [String]::IsNullOrEmpty($since) -and -not [String]::IsNullOrWhiteSpace($since)) { $Options.Add('since', $since) }
	if ($startcursor -and -not [String]::IsNullOrEmpty($startcursor) -and -not [String]::IsNullOrWhiteSpace($startcursor)) { $Options.Add('startcursor', $startcursor) }
	if ($until -and -not [String]::IsNullOrEmpty($until) -and -not [String]::IsNullOrWhiteSpace($until)) { $Options.Add('until', $until) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/journal" -Options $Options
}
function Get-NodeScanGlusterfs {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The server address (name or IP).
		[string]
		$server
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('server', $server)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/scan/glusterfs" -Options $Options
}
function New-NodeVncshell {
	[CmdletBinding()]
	param(
		# Run specific command or default to login.
		[string]
		$cmd,
		# Add parameters to a command. Encoded as null terminated strings.
		[string]
		$cmdopts,
		# sets the height of the console in pixels.
		[integer]
		$height,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# use websocket instead of standard vnc.
		[switch]
		$websocket,
		# sets the width of the console in pixels.
		[integer]
		$width
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($cmd -and -not [String]::IsNullOrEmpty($cmd) -and -not [String]::IsNullOrWhiteSpace($cmd)) { $Options.Add('cmd', $cmd) }
	if ($cmdopts -and -not [String]::IsNullOrEmpty($cmdopts) -and -not [String]::IsNullOrWhiteSpace($cmdopts)) { $Options.Add('cmd-opts', $cmdopts) }
	if ($height -and -not [String]::IsNullOrEmpty($height) -and -not [String]::IsNullOrWhiteSpace($height)) { $Options.Add('height', $height) }
	if ($websocket) { $Options.Add('websocket', $websocket) }
	if ($width -and -not [String]::IsNullOrEmpty($width) -and -not [String]::IsNullOrWhiteSpace($width)) { $Options.Add('width', $width) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/vncshell" -Options $Options
}
function Get-NodeScanIscsi {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The iSCSI portal (IP or DNS name with optional port).
		[string]
		$portal
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('portal', $portal)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/scan/iscsi" -Options $Options
}
function New-NodeTermproxy {
	[CmdletBinding()]
	param(
		# Run specific command or default to login.
		[string]
		$cmd,
		# Add parameters to a command. Encoded as null terminated strings.
		[string]
		$cmdopts,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($cmd -and -not [String]::IsNullOrEmpty($cmd) -and -not [String]::IsNullOrWhiteSpace($cmd)) { $Options.Add('cmd', $cmd) }
	if ($cmdopts -and -not [String]::IsNullOrEmpty($cmdopts) -and -not [String]::IsNullOrWhiteSpace($cmdopts)) { $Options.Add('cmd-opts', $cmdopts) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/termproxy" -Options $Options
}
function Get-NodeScanLvm {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/scan/lvm" -Options $Options
}
function Get-NodeVncwebsocket {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Port number returned by previous vncproxy call.
		[integer]
		$port,
		[Parameter(Mandatory)]
		# Ticket from previous call to vncproxy.
		[string]
		$vncticket
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('port', $port)
	$Options.Add('vncticket', $vncticket)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/vncwebsocket" -Options $Options
}
function Get-NodeScanLvmthin {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# 
		[string]
		$vg
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('vg', $vg)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/scan/lvmthin" -Options $Options
}
function New-NodeSpiceshell {
	[CmdletBinding()]
	param(
		# Run specific command or default to login.
		[string]
		$cmd,
		# Add parameters to a command. Encoded as null terminated strings.
		[string]
		$cmdopts,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# SPICE proxy server. This can be used by the client to specify the proxy server. All nodes in a cluster runs 'spiceproxy', so it is up to the client to choose one. By default, we return the node where the VM is currently running. As reasonable setting is to use same node you use to connect to the API (This is window.location.hostname for the JS GUI).
		[string]
		$proxy
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($cmd -and -not [String]::IsNullOrEmpty($cmd) -and -not [String]::IsNullOrWhiteSpace($cmd)) { $Options.Add('cmd', $cmd) }
	if ($cmdopts -and -not [String]::IsNullOrEmpty($cmdopts) -and -not [String]::IsNullOrWhiteSpace($cmdopts)) { $Options.Add('cmd-opts', $cmdopts) }
	if ($proxy -and -not [String]::IsNullOrEmpty($proxy) -and -not [String]::IsNullOrWhiteSpace($proxy)) { $Options.Add('proxy', $proxy) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/spiceshell" -Options $Options
}
function Get-NodeScanZfs {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/scan/zfs" -Options $Options
}
function Get-NodeDns {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/dns" -Options $Options
}
function Set-NodeDns {
	[CmdletBinding()]
	param(
		# First name server IP address.
		[string]
		$dns1,
		# Second name server IP address.
		[string]
		$dns2,
		# Third name server IP address.
		[string]
		$dns3,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Search domain for host-name lookup.
		[string]
		$search
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('search', $search)
	if ($dns1 -and -not [String]::IsNullOrEmpty($dns1) -and -not [String]::IsNullOrWhiteSpace($dns1)) { $Options.Add('dns1', $dns1) }
	if ($dns2 -and -not [String]::IsNullOrEmpty($dns2) -and -not [String]::IsNullOrWhiteSpace($dns2)) { $Options.Add('dns2', $dns2) }
	if ($dns3 -and -not [String]::IsNullOrEmpty($dns3) -and -not [String]::IsNullOrWhiteSpace($dns3)) { $Options.Add('dns3', $dns3) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/dns" -Options $Options
}
function Get-NodeHardwarePci {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# A list of blacklisted PCI classes, which will not be returned. Following are filtered by default: Memory Controller (05), Bridge (06) and Processor (0b).
		[string]
		$pciclassblacklist
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($pciclassblacklist -and -not [String]::IsNullOrEmpty($pciclassblacklist) -and -not [String]::IsNullOrWhiteSpace($pciclassblacklist)) { $Options.Add('pci-class-blacklist', $pciclassblacklist) }
	if ($verbose) { $Options.Add('verbose', $verbose) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/hardware/pci" -Options $Options
}
function Get-NodeHardwarePciPciid {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# 
		[string]
		$pciid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('pciid', $pciid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/hardware/pci/{pciid}" -Options $Options
}
function Get-NodeHardwarePciMdev {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The PCI ID to list the mdev types for.
		[string]
		$pciid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('pciid', $pciid)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/hardware/pci/{pciid}/mdev" -Options $Options
}
function Get-NodeTime {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/time" -Options $Options
}
function Set-NodeTime {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Time zone. The file '/usr/share/zoneinfo/zone.tab' contains the list of valid names.
		[string]
		$timezone
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('timezone', $timezone)
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/time" -Options $Options
}
function Get-NodeHardwareUsb {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/hardware/usb" -Options $Options
}
function Get-NodeAplinfo {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/aplinfo" -Options $Options
}
function New-NodeAplinfo {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The storage where the template will be stored
		[string]
		$storage,
		[Parameter(Mandatory)]
		# The template which will downloaded
		[string]
		$template
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('storage', $storage)
	$Options.Add('template', $template)
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/aplinfo" -Options $Options
}
function Get-NodeCapabilitiesQemu {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/capabilities/qemu" -Options $Options
}
function Get-NodeCapabilitiesQemuCpu {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/capabilities/qemu/cpu" -Options $Options
}
function Get-NodeCapabilitiesQemuMachines {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/capabilities/qemu/machines" -Options $Options
}
function Get-NodeQueryUrlMetadata {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The URL to query the metadata from.
		[string]
		$url,
		# If false, no SSL/TLS certificates will be verified.
		[switch]
		$verifycertificates
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('url', $url)
	if ($verifycertificates) { $Options.Add('verify-certificates', $verifycertificates) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/query-url-metadata" -Options $Options
}
function Get-NodeStorage {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$storage
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('storage', $storage)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/storage/{storage}" -Options $Options
}
function Get-NodeStoragePrunebackups {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Use these retention options instead of those from the storage configuration.
		[string]
		$prunebackups,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$storage,
		# Either 'qemu' or 'lxc'. Only consider backups for guests of this type.
		[string]
		$type,
		# Only consider backups for this guest.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('storage', $storage)
	if ($prunebackups -and -not [String]::IsNullOrEmpty($prunebackups) -and -not [String]::IsNullOrWhiteSpace($prunebackups)) { $Options.Add('prune-backups', $prunebackups) }
	if ($type -and -not [String]::IsNullOrEmpty($type) -and -not [String]::IsNullOrWhiteSpace($type)) { $Options.Add('type', $type) }
	if ($vmid -and -not [String]::IsNullOrEmpty($vmid) -and -not [String]::IsNullOrWhiteSpace($vmid)) { $Options.Add('vmid', $vmid) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/storage/{storage}/prunebackups" -Options $Options
}
function Remove-NodeStoragePrunebackups {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Use these retention options instead of those from the storage configuration.
		[string]
		$prunebackups,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$storage,
		# Either 'qemu' or 'lxc'. Only consider backups for guests of this type.
		[string]
		$type,
		# Only prune backups for this VM.
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('storage', $storage)
	if ($prunebackups -and -not [String]::IsNullOrEmpty($prunebackups) -and -not [String]::IsNullOrWhiteSpace($prunebackups)) { $Options.Add('prune-backups', $prunebackups) }
	if ($type -and -not [String]::IsNullOrEmpty($type) -and -not [String]::IsNullOrWhiteSpace($type)) { $Options.Add('type', $type) }
	if ($vmid -and -not [String]::IsNullOrEmpty($vmid) -and -not [String]::IsNullOrWhiteSpace($vmid)) { $Options.Add('vmid', $vmid) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/storage/{storage}/prunebackups" -Options $Options
}
function Get-NodeStorageContent {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# Only list content of this type.
		[string]
		$content,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$storage,
		# Only list images for this VM
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('storage', $storage)
	if ($content -and -not [String]::IsNullOrEmpty($content) -and -not [String]::IsNullOrWhiteSpace($content)) { $Options.Add('content', $content) }
	if ($vmid -and -not [String]::IsNullOrEmpty($vmid) -and -not [String]::IsNullOrWhiteSpace($vmid)) { $Options.Add('vmid', $vmid) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/storage/{storage}/content" -Options $Options
}
function New-NodeStorageContent {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The name of the file to create.
		[string]
		$filename,
		# 
		[string]
		$format,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Size in kilobyte (1024 bytes). Optional suffixes 'M' (megabyte, 1024K) and 'G' (gigabyte, 1024M)
		[string]
		$size,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$storage,
		[Parameter(Mandatory)]
		# Specify owner VM
		[integer]
		$vmid
	)
	$Options = @()
	$Options.Add('filename', $filename)
	$Options.Add('node', $node)
	$Options.Add('size', $size)
	$Options.Add('storage', $storage)
	$Options.Add('vmid', $vmid)
	if ($format -and -not [String]::IsNullOrEmpty($format) -and -not [String]::IsNullOrWhiteSpace($format)) { $Options.Add('format', $format) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/storage/{storage}/content" -Options $Options
}
function Get-NodeStorageContentVolume {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# The storage identifier.
		[string]
		$storage,
		[Parameter(Mandatory)]
		# Volume identifier
		[string]
		$volume
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('volume', $volume)
	if ($storage -and -not [String]::IsNullOrEmpty($storage) -and -not [String]::IsNullOrWhiteSpace($storage)) { $Options.Add('storage', $storage) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/storage/{storage}/content/{volume}" -Options $Options
}
function New-NodeStorageContentVolume {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# The storage identifier.
		[string]
		$storage,
		[Parameter(Mandatory)]
		# Target volume identifier
		[string]
		$target,
		# Target node. Default is local node.
		[string]
		$target_node,
		[Parameter(Mandatory)]
		# Source volume identifier
		[string]
		$volume
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('target', $target)
	$Options.Add('volume', $volume)
	if ($storage -and -not [String]::IsNullOrEmpty($storage) -and -not [String]::IsNullOrWhiteSpace($storage)) { $Options.Add('storage', $storage) }
	if ($target_node -and -not [String]::IsNullOrEmpty($target_node) -and -not [String]::IsNullOrWhiteSpace($target_node)) { $Options.Add('target_node', $target_node) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/storage/{storage}/content/{volume}" -Options $Options
}
function Set-NodeStorageContentVolume {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# The new notes.
		[string]
		$notes,
		# Protection status. Currently only supported for backups.
		[switch]
		$protected,
		# The storage identifier.
		[string]
		$storage,
		[Parameter(Mandatory)]
		# Volume identifier
		[string]
		$volume
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('volume', $volume)
	if ($notes -and -not [String]::IsNullOrEmpty($notes) -and -not [String]::IsNullOrWhiteSpace($notes)) { $Options.Add('notes', $notes) }
	if ($protected) { $Options.Add('protected', $protected) }
	if ($storage -and -not [String]::IsNullOrEmpty($storage) -and -not [String]::IsNullOrWhiteSpace($storage)) { $Options.Add('storage', $storage) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/nodes/{node}/storage/{storage}/content/{volume}" -Options $Options
}
function Remove-NodeStorageContentVolume {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Time to wait for the task to finish. We return 'null' if the task finish within that time.
		[integer]
		$delay,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# The storage identifier.
		[string]
		$storage,
		[Parameter(Mandatory)]
		# Volume identifier
		[string]
		$volume
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('volume', $volume)
	if ($delay -and -not [String]::IsNullOrEmpty($delay) -and -not [String]::IsNullOrWhiteSpace($delay)) { $Options.Add('delay', $delay) }
	if ($storage -and -not [String]::IsNullOrEmpty($storage) -and -not [String]::IsNullOrWhiteSpace($storage)) { $Options.Add('storage', $storage) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/storage/{storage}/content/{volume}" -Options $Options
}
function Get-NodeStorageFileRestoreList {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# base64-path to the directory or file being listed, or "/".
		[string]
		$filepath,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$storage,
		[Parameter(Mandatory)]
		# Backup volume ID or name. Currently only PBS snapshots are supported.
		[string]
		$volume
	)
	$Options = @()
	$Options.Add('filepath', $filepath)
	$Options.Add('node', $node)
	$Options.Add('storage', $storage)
	$Options.Add('volume', $volume)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/storage/{storage}/file-restore/list" -Options $Options
}
function Get-NodeStorageStatus {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$storage
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('storage', $storage)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/storage/{storage}/status" -Options $Options
}
function Get-NodeStorageFileRestoreDownload {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# base64-path to the directory or file to download.
		[string]
		$filepath,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$storage,
		[Parameter(Mandatory)]
		# Backup volume ID or name. Currently only PBS snapshots are supported.
		[string]
		$volume
	)
	$Options = @()
	$Options.Add('filepath', $filepath)
	$Options.Add('node', $node)
	$Options.Add('storage', $storage)
	$Options.Add('volume', $volume)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/storage/{storage}/file-restore/download" -Options $Options
}
function Get-NodeStorageRrd {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		# The RRD consolidation function
		[string]
		$cf,
		[Parameter(Mandatory)]
		# The list of datasources you want to display.
		[string]
		$ds,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$storage,
		[Parameter(Mandatory)]
		# Specify the time frame you are interested in.
		[string]
		$timeframe
	)
	$Options = @()
	$Options.Add('ds', $ds)
	$Options.Add('node', $node)
	$Options.Add('storage', $storage)
	$Options.Add('timeframe', $timeframe)
	if ($cf -and -not [String]::IsNullOrEmpty($cf) -and -not [String]::IsNullOrWhiteSpace($cf)) { $Options.Add('cf', $cf) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/storage/{storage}/rrd" -Options $Options
}
function Get-NodeStorageRrddata {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# The RRD consolidation function
		[string]
		$cf,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$storage,
		[Parameter(Mandatory)]
		# Specify the time frame you are interested in.
		[string]
		$timeframe
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('storage', $storage)
	$Options.Add('timeframe', $timeframe)
	if ($cf -and -not [String]::IsNullOrEmpty($cf) -and -not [String]::IsNullOrWhiteSpace($cf)) { $Options.Add('cf', $cf) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/storage/{storage}/rrddata" -Options $Options
}
function New-NodeStorageUpload {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# The expected checksum of the file.
		[string]
		$checksum,
		# The algorithm to calculate the checksum of the file.
		[string]
		$checksumalgorithm,
		[Parameter(Mandatory)]
		# Content type.
		[string]
		$content,
		[Parameter(Mandatory)]
		# The name of the file to create. Caution: This will be normalized!
		[string]
		$filename,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$storage,
		# The source file name. This parameter is usually set by the REST handler. You can only overwrite it when connecting to the trusted port on localhost.
		[string]
		$tmpfilename
	)
	$Options = @()
	$Options.Add('content', $content)
	$Options.Add('filename', $filename)
	$Options.Add('node', $node)
	$Options.Add('storage', $storage)
	if ($checksum -and -not [String]::IsNullOrEmpty($checksum) -and -not [String]::IsNullOrWhiteSpace($checksum)) { $Options.Add('checksum', $checksum) }
	if ($checksumalgorithm -and -not [String]::IsNullOrEmpty($checksumalgorithm) -and -not [String]::IsNullOrWhiteSpace($checksumalgorithm)) { $Options.Add('checksum-algorithm', $checksumalgorithm) }
	if ($tmpfilename -and -not [String]::IsNullOrEmpty($tmpfilename) -and -not [String]::IsNullOrWhiteSpace($tmpfilename)) { $Options.Add('tmpfilename', $tmpfilename) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/storage/{storage}/upload" -Options $Options
}
function New-NodeStorageDownloadUrl {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# The expected checksum of the file.
		[string]
		$checksum,
		# The algorithm to calculate the checksum of the file.
		[string]
		$checksumalgorithm,
		[Parameter(Mandatory)]
		# Content type.
		[string]
		$content,
		[Parameter(Mandatory)]
		# The name of the file to create. Caution: This will be normalized!
		[string]
		$filename,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$storage,
		[Parameter(Mandatory)]
		# The URL to download the file from.
		[string]
		$url,
		# If false, no SSL/TLS certificates will be verified.
		[switch]
		$verifycertificates
	)
	$Options = @()
	$Options.Add('content', $content)
	$Options.Add('filename', $filename)
	$Options.Add('node', $node)
	$Options.Add('storage', $storage)
	$Options.Add('url', $url)
	if ($checksum -and -not [String]::IsNullOrEmpty($checksum) -and -not [String]::IsNullOrWhiteSpace($checksum)) { $Options.Add('checksum', $checksum) }
	if ($checksumalgorithm -and -not [String]::IsNullOrEmpty($checksumalgorithm) -and -not [String]::IsNullOrWhiteSpace($checksumalgorithm)) { $Options.Add('checksum-algorithm', $checksumalgorithm) }
	if ($verifycertificates) { $Options.Add('verify-certificates', $verifycertificates) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/storage/{storage}/download-url" -Options $Options
}
function Get-NodeReport {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/report" -Options $Options
}
function Get-NodeDisksLvm {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/disks/lvm" -Options $Options
}
function New-NodeDisksLvm {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Configure storage using the Volume Group
		[switch]
		$add_storage,
		[Parameter(Mandatory)]
		# The block device you want to create the volume group on
		[string]
		$device,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('device', $device)
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	if ($add_storage) { $Options.Add('add_storage', $add_storage) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/disks/lvm" -Options $Options
}
function Remove-NodeDisksLvmName {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Marks associated storage(s) as not available on this node anymore or removes them from the configuration (if configured for this node only).
		[switch]
		$cleanupconfig,
		# Also wipe disks so they can be repurposed afterwards.
		[switch]
		$cleanupdisks,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	if ($cleanupconfig) { $Options.Add('cleanup-config', $cleanupconfig) }
	if ($cleanupdisks) { $Options.Add('cleanup-disks', $cleanupdisks) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/disks/lvm/{name}" -Options $Options
}
function New-NodeStartall {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Only consider guests from this comma separated list of VMIDs.
		[string]
		$vms
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($force) { $Options.Add('force', $force) }
	if ($vms -and -not [String]::IsNullOrEmpty($vms) -and -not [String]::IsNullOrWhiteSpace($vms)) { $Options.Add('vms', $vms) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/startall" -Options $Options
}
function Get-NodeDisksLvmthin {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/disks/lvmthin" -Options $Options
}
function New-NodeDisksLvmthin {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Configure storage using the thinpool.
		[switch]
		$add_storage,
		[Parameter(Mandatory)]
		# The block device you want to create the thinpool on.
		[string]
		$device,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('device', $device)
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	if ($add_storage) { $Options.Add('add_storage', $add_storage) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/disks/lvmthin" -Options $Options
}
function Remove-NodeDisksLvmthinName {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Marks associated storage(s) as not available on this node anymore or removes them from the configuration (if configured for this node only).
		[switch]
		$cleanupconfig,
		# Also wipe disks so they can be repurposed afterwards.
		[switch]
		$cleanupdisks,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$volumegroup
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('volume-group', $volumegroup)
	if ($cleanupconfig) { $Options.Add('cleanup-config', $cleanupconfig) }
	if ($cleanupdisks) { $Options.Add('cleanup-disks', $cleanupdisks) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/disks/lvmthin/{name}" -Options $Options
}
function New-NodeStopall {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Only consider Guests with these IDs.
		[string]
		$vms
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($vms -and -not [String]::IsNullOrEmpty($vms) -and -not [String]::IsNullOrWhiteSpace($vms)) { $Options.Add('vms', $vms) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/stopall" -Options $Options
}
function Get-NodeDisksDirectory {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/disks/directory" -Options $Options
}
function New-NodeDisksDirectory {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Configure storage using the directory.
		[switch]
		$add_storage,
		[Parameter(Mandatory)]
		# The block device you want to create the filesystem on.
		[string]
		$device,
		# The desired filesystem.
		[string]
		$filesystem,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('device', $device)
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	if ($add_storage) { $Options.Add('add_storage', $add_storage) }
	if ($filesystem -and -not [String]::IsNullOrEmpty($filesystem) -and -not [String]::IsNullOrWhiteSpace($filesystem)) { $Options.Add('filesystem', $filesystem) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/disks/directory" -Options $Options
}
function Remove-NodeDisksDirectoryName {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Marks associated storage(s) as not available on this node anymore or removes them from the configuration (if configured for this node only).
		[switch]
		$cleanupconfig,
		# Also wipe disk so it can be repurposed afterwards.
		[switch]
		$cleanupdisks,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	if ($cleanupconfig) { $Options.Add('cleanup-config', $cleanupconfig) }
	if ($cleanupdisks) { $Options.Add('cleanup-disks', $cleanupdisks) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/disks/directory/{name}" -Options $Options
}
function New-NodeMigrateall {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Maximal number of parallel migration job. If not set use 'max_workers' from datacenter.cfg, one of both must be set!
		[integer]
		$maxworkers,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# Target node.
		[string]
		$target,
		# Only consider Guests with these IDs.
		[string]
		$vms,
		# Enable live storage migration for local disk
		[switch]
		$withlocaldisks
	)
	$Options = @()
	$Options.Add('node', $node)
	$Options.Add('target', $target)
	if ($maxworkers -and -not [String]::IsNullOrEmpty($maxworkers) -and -not [String]::IsNullOrWhiteSpace($maxworkers)) { $Options.Add('maxworkers', $maxworkers) }
	if ($vms -and -not [String]::IsNullOrEmpty($vms) -and -not [String]::IsNullOrWhiteSpace($vms)) { $Options.Add('vms', $vms) }
	if ($withlocaldisks) { $Options.Add('with-local-disks', $withlocaldisks) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/migrateall" -Options $Options
}
function Get-NodeDisksZfs {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/disks/zfs" -Options $Options
}
function New-NodeDisksZfs {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Configure storage using the zpool.
		[switch]
		$add_storage,
		# Pool sector size exponent.
		[integer]
		$ashift,
		# The compression algorithm to use.
		[string]
		$compression,
		[Parameter(Mandatory)]
		# The block devices you want to create the zpool on.
		[string]
		$devices,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		[Parameter(Mandatory)]
		# The RAID level to use.
		[string]
		$raidlevel
	)
	$Options = @()
	$Options.Add('devices', $devices)
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	$Options.Add('raidlevel', $raidlevel)
	if ($add_storage) { $Options.Add('add_storage', $add_storage) }
	if ($ashift -and -not [String]::IsNullOrEmpty($ashift) -and -not [String]::IsNullOrWhiteSpace($ashift)) { $Options.Add('ashift', $ashift) }
	if ($compression -and -not [String]::IsNullOrEmpty($compression) -and -not [String]::IsNullOrWhiteSpace($compression)) { $Options.Add('compression', $compression) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/disks/zfs" -Options $Options
}
function Get-NodeDisksZfsName {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/disks/zfs/{name}" -Options $Options
}
function Remove-NodeDisksZfsName {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# Marks associated storage(s) as not available on this node anymore or removes them from the configuration (if configured for this node only).
		[switch]
		$cleanupconfig,
		# Also wipe disks so they can be repurposed afterwards.
		[switch]
		$cleanupdisks,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$name,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('name', $name)
	$Options.Add('node', $node)
	if ($cleanupconfig) { $Options.Add('cleanup-config', $cleanupconfig) }
	if ($cleanupdisks) { $Options.Add('cleanup-disks', $cleanupdisks) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/nodes/{node}/disks/zfs/{name}" -Options $Options
}
function Get-NodeHosts {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('node', $node)
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/hosts" -Options $Options
}
function New-NodeHosts {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# The target content of /etc/hosts.
		[string]
		$data,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node
	)
	$Options = @()
	$Options.Add('data', $data)
	$Options.Add('node', $node)
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	Invoke-ProxmoxAPI -Method POST -Resource "/nodes/{node}/hosts" -Options $Options
}
function Get-NodeDisksList {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# Also include partitions.
		[switch]
		$includepartitions,
		[Parameter(Mandatory)]
		# The cluster node name.
		[string]
		$node,
		# Skip smart checks.
		[switch]
		$skipsmart,
		# Only list specific types of disks.
		[string]
		$type
	)
	$Options = @()
	$Options.Add('node', $node)
	if ($includepartitions) { $Options.Add('include-partitions', $includepartitions) }
	if ($skipsmart) { $Options.Add('skipsmart', $skipsmart) }
	if ($type -and -not [String]::IsNullOrEmpty($type) -and -not [String]::IsNullOrWhiteSpace($type)) { $Options.Add('type', $type) }
	Invoke-ProxmoxAPI -Method GET -Resource "/nodes/{node}/disks/list" -Options $Options
}
function Get-Storage {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# Only list storage of specific type
		[string]
		$type
	)
	$Options = @()
	if ($type -and -not [String]::IsNullOrEmpty($type) -and -not [String]::IsNullOrWhiteSpace($type)) { $Options.Add('type', $type) }
	Invoke-ProxmoxAPI -Method GET -Resource "/storage" -Options $Options
}
function New-Storage {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		# Authsupported.
		[string]
		$authsupported,
		# Base volume. This volume is automatically activated.
		[string]
		$base,
		# block size
		[string]
		$blocksize,
		# Set bandwidth/io limits various operations.
		[string]
		$bwlimit,
		# host group for comstar views
		[string]
		$comstar_hg,
		# target group for comstar views
		[string]
		$comstar_tg,
		# Allowed content types.
		[string]
		$content,
		# Proxmox Backup Server datastore name.
		[string]
		$datastore,
		# Flag to disable the storage.
		[switch]
		$disable,
		# CIFS domain.
		[string]
		$domain,
		# Encryption key. Use 'autogen' to generate one automatically without passphrase.
		[string]
		$encryptionkey,
		# NFS export path.
		[string]
		$export,
		# Certificate SHA 256 fingerprint.
		[string]
		$fingerprint,
		# Default image format.
		[string]
		$format,
		# The Ceph filesystem name.
		[string]
		$fsname,
		# Mount CephFS through FUSE.
		[switch]
		$fuse,
		# iscsi provider
		[string]
		$iscsiprovider,
		# Assume the given path is an externally managed mountpoint and consider the storage offline if it is not mounted. Using a boolean (yes/no) value serves as a shortcut to using the target path in this field.
		[string]
		$is_mountpoint,
		# Client keyring contents (for external clusters).
		[string]
		$keyring,
		# Always access rbd through krbd kernel module.
		[switch]
		$krbd,
		# target portal group for Linux LIO targets
		[string]
		$lio_tpg,
		# Base64-encoded, PEM-formatted public RSA key. Used to encrypt a copy of the encryption-key which will be added to each encrypted backup.
		[string]
		$masterpubkey,
		# Deprecated: use 'prune-backups' instead. Maximal number of backup files per VM. Use '0' for unlimited.
		[integer]
		$maxfiles,
		# Create the directory if it doesn't exist.
		[switch]
		$mkdir,
		# IP addresses of monitors (for external clusters).
		[string]
		$monhost,
		# mount point
		[string]
		$mountpoint,
		# RBD Namespace.
		[string]
		$namespace,
		# Set the NOCOW flag on files. Disables data checksumming and causes data errors to be unrecoverable from while allowing direct I/O. Only use this if data does not need to be any more safe than on a single ext4 formatted disk with no underlying raid system.
		[switch]
		$nocow,
		# List of cluster node names.
		[string]
		$nodes,
		# disable write caching on the target
		[switch]
		$nowritecache,
		# NFS mount options (see 'man nfs')
		[string]
		$options,
		# Password for accessing the share/datastore.
		[securestring]
		$password,
		# File system path.
		[string]
		$path,
		# Pool.
		[string]
		$pool,
		# For non default port.
		[integer]
		$port,
		# iSCSI portal (IP or DNS name with optional port).
		[string]
		$portal,
		# Preallocation mode for raw and qcow2 images. Using 'metadata' on raw images results in preallocation=off.
		[string]
		$preallocation,
		# The retention options with shorter intervals are processed first with --keep-last being the very first one. Each option covers a specific period of time. We say that backups within this period are covered by this option. The next option does not take care of already covered backups and only considers older backups.
		[string]
		$prunebackups,
		# Zero-out data when removing LVs.
		[switch]
		$saferemove,
		# Wipe throughput (cstream -t parameter value).
		[string]
		$saferemove_throughput,
		# Server IP or DNS name.
		[string]
		$server,
		# Backup volfile server IP or DNS name.
		[string]
		$server2,
		# CIFS share.
		[string]
		$share,
		# Mark storage as shared.
		[switch]
		$shared,
		# SMB protocol version. 'default' if not set, negotiates the highest SMB2+ version supported by both the client and server.
		[string]
		$smbversion,
		# use sparse volumes
		[switch]
		$sparse,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$storage,
		# Subdir to mount.
		[string]
		$subdir,
		# Only use logical volumes tagged with 'pve-vm-ID'.
		[switch]
		$tagged_only,
		# iSCSI target.
		[string]
		$target,
		# LVM thin pool LV name.
		[string]
		$thinpool,
		# Gluster transport: tcp or rdma
		[string]
		$transport,
		[Parameter(Mandatory)]
		# Storage type.
		[string]
		$type,
		# RBD Id.
		[string]
		$username,
		# Volume group name.
		[string]
		$vgname,
		# Glusterfs Volume.
		[string]
		$volume
	)
	$Options = @()
	$Options.Add('storage', $storage)
	$Options.Add('type', $type)
	if ($authsupported -and -not [String]::IsNullOrEmpty($authsupported) -and -not [String]::IsNullOrWhiteSpace($authsupported)) { $Options.Add('authsupported', $authsupported) }
	if ($base -and -not [String]::IsNullOrEmpty($base) -and -not [String]::IsNullOrWhiteSpace($base)) { $Options.Add('base', $base) }
	if ($blocksize -and -not [String]::IsNullOrEmpty($blocksize) -and -not [String]::IsNullOrWhiteSpace($blocksize)) { $Options.Add('blocksize', $blocksize) }
	if ($bwlimit -and -not [String]::IsNullOrEmpty($bwlimit) -and -not [String]::IsNullOrWhiteSpace($bwlimit)) { $Options.Add('bwlimit', $bwlimit) }
	if ($comstar_hg -and -not [String]::IsNullOrEmpty($comstar_hg) -and -not [String]::IsNullOrWhiteSpace($comstar_hg)) { $Options.Add('comstar_hg', $comstar_hg) }
	if ($comstar_tg -and -not [String]::IsNullOrEmpty($comstar_tg) -and -not [String]::IsNullOrWhiteSpace($comstar_tg)) { $Options.Add('comstar_tg', $comstar_tg) }
	if ($content -and -not [String]::IsNullOrEmpty($content) -and -not [String]::IsNullOrWhiteSpace($content)) { $Options.Add('content', $content) }
	if ($datastore -and -not [String]::IsNullOrEmpty($datastore) -and -not [String]::IsNullOrWhiteSpace($datastore)) { $Options.Add('datastore', $datastore) }
	if ($disable) { $Options.Add('disable', $disable) }
	if ($domain -and -not [String]::IsNullOrEmpty($domain) -and -not [String]::IsNullOrWhiteSpace($domain)) { $Options.Add('domain', $domain) }
	if ($encryptionkey -and -not [String]::IsNullOrEmpty($encryptionkey) -and -not [String]::IsNullOrWhiteSpace($encryptionkey)) { $Options.Add('encryption-key', $encryptionkey) }
	if ($export -and -not [String]::IsNullOrEmpty($export) -and -not [String]::IsNullOrWhiteSpace($export)) { $Options.Add('export', $export) }
	if ($fingerprint -and -not [String]::IsNullOrEmpty($fingerprint) -and -not [String]::IsNullOrWhiteSpace($fingerprint)) { $Options.Add('fingerprint', $fingerprint) }
	if ($format -and -not [String]::IsNullOrEmpty($format) -and -not [String]::IsNullOrWhiteSpace($format)) { $Options.Add('format', $format) }
	if ($fsname -and -not [String]::IsNullOrEmpty($fsname) -and -not [String]::IsNullOrWhiteSpace($fsname)) { $Options.Add('fs-name', $fsname) }
	if ($fuse) { $Options.Add('fuse', $fuse) }
	if ($iscsiprovider -and -not [String]::IsNullOrEmpty($iscsiprovider) -and -not [String]::IsNullOrWhiteSpace($iscsiprovider)) { $Options.Add('iscsiprovider', $iscsiprovider) }
	if ($is_mountpoint -and -not [String]::IsNullOrEmpty($is_mountpoint) -and -not [String]::IsNullOrWhiteSpace($is_mountpoint)) { $Options.Add('is_mountpoint', $is_mountpoint) }
	if ($keyring -and -not [String]::IsNullOrEmpty($keyring) -and -not [String]::IsNullOrWhiteSpace($keyring)) { $Options.Add('keyring', $keyring) }
	if ($krbd) { $Options.Add('krbd', $krbd) }
	if ($lio_tpg -and -not [String]::IsNullOrEmpty($lio_tpg) -and -not [String]::IsNullOrWhiteSpace($lio_tpg)) { $Options.Add('lio_tpg', $lio_tpg) }
	if ($masterpubkey -and -not [String]::IsNullOrEmpty($masterpubkey) -and -not [String]::IsNullOrWhiteSpace($masterpubkey)) { $Options.Add('master-pubkey', $masterpubkey) }
	if ($maxfiles -and -not [String]::IsNullOrEmpty($maxfiles) -and -not [String]::IsNullOrWhiteSpace($maxfiles)) { $Options.Add('maxfiles', $maxfiles) }
	if ($mkdir) { $Options.Add('mkdir', $mkdir) }
	if ($monhost -and -not [String]::IsNullOrEmpty($monhost) -and -not [String]::IsNullOrWhiteSpace($monhost)) { $Options.Add('monhost', $monhost) }
	if ($mountpoint -and -not [String]::IsNullOrEmpty($mountpoint) -and -not [String]::IsNullOrWhiteSpace($mountpoint)) { $Options.Add('mountpoint', $mountpoint) }
	if ($namespace -and -not [String]::IsNullOrEmpty($namespace) -and -not [String]::IsNullOrWhiteSpace($namespace)) { $Options.Add('namespace', $namespace) }
	if ($nocow) { $Options.Add('nocow', $nocow) }
	if ($nodes -and -not [String]::IsNullOrEmpty($nodes) -and -not [String]::IsNullOrWhiteSpace($nodes)) { $Options.Add('nodes', $nodes) }
	if ($nowritecache) { $Options.Add('nowritecache', $nowritecache) }
	if ($options -and -not [String]::IsNullOrEmpty($options) -and -not [String]::IsNullOrWhiteSpace($options)) { $Options.Add('options', $options) }
	if ($password) { $Options.Add('password', $($password | ConvertFrom-SecureString -AsPlainText)) }
	if ($path -and -not [String]::IsNullOrEmpty($path) -and -not [String]::IsNullOrWhiteSpace($path)) { $Options.Add('path', $path) }
	if ($pool -and -not [String]::IsNullOrEmpty($pool) -and -not [String]::IsNullOrWhiteSpace($pool)) { $Options.Add('pool', $pool) }
	if ($port -and -not [String]::IsNullOrEmpty($port) -and -not [String]::IsNullOrWhiteSpace($port)) { $Options.Add('port', $port) }
	if ($portal -and -not [String]::IsNullOrEmpty($portal) -and -not [String]::IsNullOrWhiteSpace($portal)) { $Options.Add('portal', $portal) }
	if ($preallocation -and -not [String]::IsNullOrEmpty($preallocation) -and -not [String]::IsNullOrWhiteSpace($preallocation)) { $Options.Add('preallocation', $preallocation) }
	if ($prunebackups -and -not [String]::IsNullOrEmpty($prunebackups) -and -not [String]::IsNullOrWhiteSpace($prunebackups)) { $Options.Add('prune-backups', $prunebackups) }
	if ($saferemove) { $Options.Add('saferemove', $saferemove) }
	if ($saferemove_throughput -and -not [String]::IsNullOrEmpty($saferemove_throughput) -and -not [String]::IsNullOrWhiteSpace($saferemove_throughput)) { $Options.Add('saferemove_throughput', $saferemove_throughput) }
	if ($server -and -not [String]::IsNullOrEmpty($server) -and -not [String]::IsNullOrWhiteSpace($server)) { $Options.Add('server', $server) }
	if ($server2 -and -not [String]::IsNullOrEmpty($server2) -and -not [String]::IsNullOrWhiteSpace($server2)) { $Options.Add('server2', $server2) }
	if ($share -and -not [String]::IsNullOrEmpty($share) -and -not [String]::IsNullOrWhiteSpace($share)) { $Options.Add('share', $share) }
	if ($shared) { $Options.Add('shared', $shared) }
	if ($smbversion -and -not [String]::IsNullOrEmpty($smbversion) -and -not [String]::IsNullOrWhiteSpace($smbversion)) { $Options.Add('smbversion', $smbversion) }
	if ($sparse) { $Options.Add('sparse', $sparse) }
	if ($subdir -and -not [String]::IsNullOrEmpty($subdir) -and -not [String]::IsNullOrWhiteSpace($subdir)) { $Options.Add('subdir', $subdir) }
	if ($tagged_only) { $Options.Add('tagged_only', $tagged_only) }
	if ($target -and -not [String]::IsNullOrEmpty($target) -and -not [String]::IsNullOrWhiteSpace($target)) { $Options.Add('target', $target) }
	if ($thinpool -and -not [String]::IsNullOrEmpty($thinpool) -and -not [String]::IsNullOrWhiteSpace($thinpool)) { $Options.Add('thinpool', $thinpool) }
	if ($transport -and -not [String]::IsNullOrEmpty($transport) -and -not [String]::IsNullOrWhiteSpace($transport)) { $Options.Add('transport', $transport) }
	if ($username -and -not [String]::IsNullOrEmpty($username) -and -not [String]::IsNullOrWhiteSpace($username)) { $Options.Add('username', $username) }
	if ($vgname -and -not [String]::IsNullOrEmpty($vgname) -and -not [String]::IsNullOrWhiteSpace($vgname)) { $Options.Add('vgname', $vgname) }
	if ($volume -and -not [String]::IsNullOrEmpty($volume) -and -not [String]::IsNullOrWhiteSpace($volume)) { $Options.Add('volume', $volume) }
	Invoke-ProxmoxAPI -Method POST -Resource "/storage" -Options $Options
}
function Get-Storage {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$storage
	)
	$Options = @()
	$Options.Add('storage', $storage)
	Invoke-ProxmoxAPI -Method GET -Resource "/storage/{storage}" -Options $Options
}
function Set-Storage {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		# block size
		[string]
		$blocksize,
		# Set bandwidth/io limits various operations.
		[string]
		$bwlimit,
		# host group for comstar views
		[string]
		$comstar_hg,
		# target group for comstar views
		[string]
		$comstar_tg,
		# Allowed content types.
		[string]
		$content,
		# A list of settings you want to delete.
		[string]
		$delete,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# Flag to disable the storage.
		[switch]
		$disable,
		# CIFS domain.
		[string]
		$domain,
		# Encryption key. Use 'autogen' to generate one automatically without passphrase.
		[string]
		$encryptionkey,
		# Certificate SHA 256 fingerprint.
		[string]
		$fingerprint,
		# Default image format.
		[string]
		$format,
		# The Ceph filesystem name.
		[string]
		$fsname,
		# Mount CephFS through FUSE.
		[switch]
		$fuse,
		# Assume the given path is an externally managed mountpoint and consider the storage offline if it is not mounted. Using a boolean (yes/no) value serves as a shortcut to using the target path in this field.
		[string]
		$is_mountpoint,
		# Client keyring contents (for external clusters).
		[string]
		$keyring,
		# Always access rbd through krbd kernel module.
		[switch]
		$krbd,
		# target portal group for Linux LIO targets
		[string]
		$lio_tpg,
		# Base64-encoded, PEM-formatted public RSA key. Used to encrypt a copy of the encryption-key which will be added to each encrypted backup.
		[string]
		$masterpubkey,
		# Deprecated: use 'prune-backups' instead. Maximal number of backup files per VM. Use '0' for unlimited.
		[integer]
		$maxfiles,
		# Create the directory if it doesn't exist.
		[switch]
		$mkdir,
		# IP addresses of monitors (for external clusters).
		[string]
		$monhost,
		# mount point
		[string]
		$mountpoint,
		# RBD Namespace.
		[string]
		$namespace,
		# Set the NOCOW flag on files. Disables data checksumming and causes data errors to be unrecoverable from while allowing direct I/O. Only use this if data does not need to be any more safe than on a single ext4 formatted disk with no underlying raid system.
		[switch]
		$nocow,
		# List of cluster node names.
		[string]
		$nodes,
		# disable write caching on the target
		[switch]
		$nowritecache,
		# NFS mount options (see 'man nfs')
		[string]
		$options,
		# Password for accessing the share/datastore.
		[securestring]
		$password,
		# Pool.
		[string]
		$pool,
		# For non default port.
		[integer]
		$port,
		# Preallocation mode for raw and qcow2 images. Using 'metadata' on raw images results in preallocation=off.
		[string]
		$preallocation,
		# The retention options with shorter intervals are processed first with --keep-last being the very first one. Each option covers a specific period of time. We say that backups within this period are covered by this option. The next option does not take care of already covered backups and only considers older backups.
		[string]
		$prunebackups,
		# Zero-out data when removing LVs.
		[switch]
		$saferemove,
		# Wipe throughput (cstream -t parameter value).
		[string]
		$saferemove_throughput,
		# Server IP or DNS name.
		[string]
		$server,
		# Backup volfile server IP or DNS name.
		[string]
		$server2,
		# Mark storage as shared.
		[switch]
		$shared,
		# SMB protocol version. 'default' if not set, negotiates the highest SMB2+ version supported by both the client and server.
		[string]
		$smbversion,
		# use sparse volumes
		[switch]
		$sparse,
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$storage,
		# Subdir to mount.
		[string]
		$subdir,
		# Only use logical volumes tagged with 'pve-vm-ID'.
		[switch]
		$tagged_only,
		# Gluster transport: tcp or rdma
		[string]
		$transport,
		# RBD Id.
		[string]
		$username
	)
	$Options = @()
	$Options.Add('storage', $storage)
	if ($blocksize -and -not [String]::IsNullOrEmpty($blocksize) -and -not [String]::IsNullOrWhiteSpace($blocksize)) { $Options.Add('blocksize', $blocksize) }
	if ($bwlimit -and -not [String]::IsNullOrEmpty($bwlimit) -and -not [String]::IsNullOrWhiteSpace($bwlimit)) { $Options.Add('bwlimit', $bwlimit) }
	if ($comstar_hg -and -not [String]::IsNullOrEmpty($comstar_hg) -and -not [String]::IsNullOrWhiteSpace($comstar_hg)) { $Options.Add('comstar_hg', $comstar_hg) }
	if ($comstar_tg -and -not [String]::IsNullOrEmpty($comstar_tg) -and -not [String]::IsNullOrWhiteSpace($comstar_tg)) { $Options.Add('comstar_tg', $comstar_tg) }
	if ($content -and -not [String]::IsNullOrEmpty($content) -and -not [String]::IsNullOrWhiteSpace($content)) { $Options.Add('content', $content) }
	if ($delete -and -not [String]::IsNullOrEmpty($delete) -and -not [String]::IsNullOrWhiteSpace($delete)) { $Options.Add('delete', $delete) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($disable) { $Options.Add('disable', $disable) }
	if ($domain -and -not [String]::IsNullOrEmpty($domain) -and -not [String]::IsNullOrWhiteSpace($domain)) { $Options.Add('domain', $domain) }
	if ($encryptionkey -and -not [String]::IsNullOrEmpty($encryptionkey) -and -not [String]::IsNullOrWhiteSpace($encryptionkey)) { $Options.Add('encryption-key', $encryptionkey) }
	if ($fingerprint -and -not [String]::IsNullOrEmpty($fingerprint) -and -not [String]::IsNullOrWhiteSpace($fingerprint)) { $Options.Add('fingerprint', $fingerprint) }
	if ($format -and -not [String]::IsNullOrEmpty($format) -and -not [String]::IsNullOrWhiteSpace($format)) { $Options.Add('format', $format) }
	if ($fsname -and -not [String]::IsNullOrEmpty($fsname) -and -not [String]::IsNullOrWhiteSpace($fsname)) { $Options.Add('fs-name', $fsname) }
	if ($fuse) { $Options.Add('fuse', $fuse) }
	if ($is_mountpoint -and -not [String]::IsNullOrEmpty($is_mountpoint) -and -not [String]::IsNullOrWhiteSpace($is_mountpoint)) { $Options.Add('is_mountpoint', $is_mountpoint) }
	if ($keyring -and -not [String]::IsNullOrEmpty($keyring) -and -not [String]::IsNullOrWhiteSpace($keyring)) { $Options.Add('keyring', $keyring) }
	if ($krbd) { $Options.Add('krbd', $krbd) }
	if ($lio_tpg -and -not [String]::IsNullOrEmpty($lio_tpg) -and -not [String]::IsNullOrWhiteSpace($lio_tpg)) { $Options.Add('lio_tpg', $lio_tpg) }
	if ($masterpubkey -and -not [String]::IsNullOrEmpty($masterpubkey) -and -not [String]::IsNullOrWhiteSpace($masterpubkey)) { $Options.Add('master-pubkey', $masterpubkey) }
	if ($maxfiles -and -not [String]::IsNullOrEmpty($maxfiles) -and -not [String]::IsNullOrWhiteSpace($maxfiles)) { $Options.Add('maxfiles', $maxfiles) }
	if ($mkdir) { $Options.Add('mkdir', $mkdir) }
	if ($monhost -and -not [String]::IsNullOrEmpty($monhost) -and -not [String]::IsNullOrWhiteSpace($monhost)) { $Options.Add('monhost', $monhost) }
	if ($mountpoint -and -not [String]::IsNullOrEmpty($mountpoint) -and -not [String]::IsNullOrWhiteSpace($mountpoint)) { $Options.Add('mountpoint', $mountpoint) }
	if ($namespace -and -not [String]::IsNullOrEmpty($namespace) -and -not [String]::IsNullOrWhiteSpace($namespace)) { $Options.Add('namespace', $namespace) }
	if ($nocow) { $Options.Add('nocow', $nocow) }
	if ($nodes -and -not [String]::IsNullOrEmpty($nodes) -and -not [String]::IsNullOrWhiteSpace($nodes)) { $Options.Add('nodes', $nodes) }
	if ($nowritecache) { $Options.Add('nowritecache', $nowritecache) }
	if ($options -and -not [String]::IsNullOrEmpty($options) -and -not [String]::IsNullOrWhiteSpace($options)) { $Options.Add('options', $options) }
	if ($password) { $Options.Add('password', $($password | ConvertFrom-SecureString -AsPlainText)) }
	if ($pool -and -not [String]::IsNullOrEmpty($pool) -and -not [String]::IsNullOrWhiteSpace($pool)) { $Options.Add('pool', $pool) }
	if ($port -and -not [String]::IsNullOrEmpty($port) -and -not [String]::IsNullOrWhiteSpace($port)) { $Options.Add('port', $port) }
	if ($preallocation -and -not [String]::IsNullOrEmpty($preallocation) -and -not [String]::IsNullOrWhiteSpace($preallocation)) { $Options.Add('preallocation', $preallocation) }
	if ($prunebackups -and -not [String]::IsNullOrEmpty($prunebackups) -and -not [String]::IsNullOrWhiteSpace($prunebackups)) { $Options.Add('prune-backups', $prunebackups) }
	if ($saferemove) { $Options.Add('saferemove', $saferemove) }
	if ($saferemove_throughput -and -not [String]::IsNullOrEmpty($saferemove_throughput) -and -not [String]::IsNullOrWhiteSpace($saferemove_throughput)) { $Options.Add('saferemove_throughput', $saferemove_throughput) }
	if ($server -and -not [String]::IsNullOrEmpty($server) -and -not [String]::IsNullOrWhiteSpace($server)) { $Options.Add('server', $server) }
	if ($server2 -and -not [String]::IsNullOrEmpty($server2) -and -not [String]::IsNullOrWhiteSpace($server2)) { $Options.Add('server2', $server2) }
	if ($shared) { $Options.Add('shared', $shared) }
	if ($smbversion -and -not [String]::IsNullOrEmpty($smbversion) -and -not [String]::IsNullOrWhiteSpace($smbversion)) { $Options.Add('smbversion', $smbversion) }
	if ($sparse) { $Options.Add('sparse', $sparse) }
	if ($subdir -and -not [String]::IsNullOrEmpty($subdir) -and -not [String]::IsNullOrWhiteSpace($subdir)) { $Options.Add('subdir', $subdir) }
	if ($tagged_only) { $Options.Add('tagged_only', $tagged_only) }
	if ($transport -and -not [String]::IsNullOrEmpty($transport) -and -not [String]::IsNullOrWhiteSpace($transport)) { $Options.Add('transport', $transport) }
	if ($username -and -not [String]::IsNullOrEmpty($username) -and -not [String]::IsNullOrWhiteSpace($username)) { $Options.Add('username', $username) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/storage/{storage}" -Options $Options
}
function Remove-Storage {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# The storage identifier.
		[string]
		$storage
	)
	$Options = @()
	$Options.Add('storage', $storage)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/storage/{storage}" -Options $Options
}
function Get-Access {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/access"
}
function Get-AccessUsers {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		# Optional filter for enable property.
		[switch]
		$enabled,
		# Include group and token information.
		[switch]
		$full
	)
	$Options = @()
	if ($enabled) { $Options.Add('enabled', $enabled) }
	if ($full) { $Options.Add('full', $full) }
	Invoke-ProxmoxAPI -Method GET -Resource "/access/users" -Options $Options
}
function New-AccessUsers {
	[CmdletBinding()]
	param(
		# 
		[string]
		$comment,
		# 
		[string]
		$email,
		# Enable the account (default). You can set this to '0' to disable the account
		[switch]
		$enable,
		# Account expiration date (seconds since epoch). '0' means no expiration date.
		[integer]
		$expire,
		# 
		[string]
		$firstname,
		# 
		[string]
		$groups,
		# Keys for two factor auth (yubico).
		[string]
		$keys,
		# 
		[string]
		$lastname,
		# Initial password.
		[securestring]
		$password,
		[Parameter(Mandatory)]
		# User ID
		[string]
		$userid
	)
	$Options = @()
	$Options.Add('userid', $userid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($email -and -not [String]::IsNullOrEmpty($email) -and -not [String]::IsNullOrWhiteSpace($email)) { $Options.Add('email', $email) }
	if ($enable) { $Options.Add('enable', $enable) }
	if ($expire -and -not [String]::IsNullOrEmpty($expire) -and -not [String]::IsNullOrWhiteSpace($expire)) { $Options.Add('expire', $expire) }
	if ($firstname -and -not [String]::IsNullOrEmpty($firstname) -and -not [String]::IsNullOrWhiteSpace($firstname)) { $Options.Add('firstname', $firstname) }
	if ($groups -and -not [String]::IsNullOrEmpty($groups) -and -not [String]::IsNullOrWhiteSpace($groups)) { $Options.Add('groups', $groups) }
	if ($keys -and -not [String]::IsNullOrEmpty($keys) -and -not [String]::IsNullOrWhiteSpace($keys)) { $Options.Add('keys', $keys) }
	if ($lastname -and -not [String]::IsNullOrEmpty($lastname) -and -not [String]::IsNullOrWhiteSpace($lastname)) { $Options.Add('lastname', $lastname) }
	if ($password) { $Options.Add('password', $($password | ConvertFrom-SecureString -AsPlainText)) }
	Invoke-ProxmoxAPI -Method POST -Resource "/access/users" -Options $Options
}
function Get-AccessUsersUserid {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# User ID
		[string]
		$userid
	)
	$Options = @()
	$Options.Add('userid', $userid)
	Invoke-ProxmoxAPI -Method GET -Resource "/access/users/{userid}" -Options $Options
}
function Set-AccessUsersUserid {
	[CmdletBinding()]
	param(
		# 
		[switch]
		$append,
		# 
		[string]
		$comment,
		# 
		[string]
		$email,
		# Enable the account (default). You can set this to '0' to disable the account
		[switch]
		$enable,
		# Account expiration date (seconds since epoch). '0' means no expiration date.
		[integer]
		$expire,
		# 
		[string]
		$firstname,
		# 
		[string]
		$groups,
		# Keys for two factor auth (yubico).
		[string]
		$keys,
		# 
		[string]
		$lastname,
		[Parameter(Mandatory)]
		# User ID
		[string]
		$userid
	)
	$Options = @()
	$Options.Add('userid', $userid)
	if ($append) { $Options.Add('append', $append) }
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($email -and -not [String]::IsNullOrEmpty($email) -and -not [String]::IsNullOrWhiteSpace($email)) { $Options.Add('email', $email) }
	if ($enable) { $Options.Add('enable', $enable) }
	if ($expire -and -not [String]::IsNullOrEmpty($expire) -and -not [String]::IsNullOrWhiteSpace($expire)) { $Options.Add('expire', $expire) }
	if ($firstname -and -not [String]::IsNullOrEmpty($firstname) -and -not [String]::IsNullOrWhiteSpace($firstname)) { $Options.Add('firstname', $firstname) }
	if ($groups -and -not [String]::IsNullOrEmpty($groups) -and -not [String]::IsNullOrWhiteSpace($groups)) { $Options.Add('groups', $groups) }
	if ($keys -and -not [String]::IsNullOrEmpty($keys) -and -not [String]::IsNullOrWhiteSpace($keys)) { $Options.Add('keys', $keys) }
	if ($lastname -and -not [String]::IsNullOrEmpty($lastname) -and -not [String]::IsNullOrWhiteSpace($lastname)) { $Options.Add('lastname', $lastname) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/access/users/{userid}" -Options $Options
}
function Remove-AccessUsersUserid {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# User ID
		[string]
		$userid
	)
	$Options = @()
	$Options.Add('userid', $userid)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/access/users/{userid}" -Options $Options
}
function Get-AccessUsersTfa {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		# Request all entries as an array.
		[switch]
		$multiple,
		[Parameter(Mandatory)]
		# User ID
		[string]
		$userid
	)
	$Options = @()
	$Options.Add('userid', $userid)
	if ($multiple) { $Options.Add('multiple', $multiple) }
	Invoke-ProxmoxAPI -Method GET -Resource "/access/users/{userid}/tfa" -Options $Options
}
function Get-AccessUsersToken {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# User ID
		[string]
		$userid
	)
	$Options = @()
	$Options.Add('userid', $userid)
	Invoke-ProxmoxAPI -Method GET -Resource "/access/users/{userid}/token" -Options $Options
}
function Get-AccessUsersTokenTokenid {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# User-specific token identifier.
		[string]
		$tokenid,
		[Parameter(Mandatory)]
		# User ID
		[string]
		$userid
	)
	$Options = @()
	$Options.Add('tokenid', $tokenid)
	$Options.Add('userid', $userid)
	Invoke-ProxmoxAPI -Method GET -Resource "/access/users/{userid}/token/{tokenid}" -Options $Options
}
function New-AccessUsersTokenTokenid {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		# 
		[string]
		$comment,
		# API token expiration date (seconds since epoch). '0' means no expiration date.
		[integer]
		$expire,
		# Restrict API token privileges with separate ACLs (default), or give full privileges of corresponding user.
		[switch]
		$privsep,
		[Parameter(Mandatory)]
		# User-specific token identifier.
		[string]
		$tokenid,
		[Parameter(Mandatory)]
		# User ID
		[string]
		$userid
	)
	$Options = @()
	$Options.Add('tokenid', $tokenid)
	$Options.Add('userid', $userid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($expire -and -not [String]::IsNullOrEmpty($expire) -and -not [String]::IsNullOrWhiteSpace($expire)) { $Options.Add('expire', $expire) }
	if ($privsep) { $Options.Add('privsep', $privsep) }
	Invoke-ProxmoxAPI -Method POST -Resource "/access/users/{userid}/token/{tokenid}" -Options $Options
}
function Set-AccessUsersTokenTokenid {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		# 
		[string]
		$comment,
		# API token expiration date (seconds since epoch). '0' means no expiration date.
		[integer]
		$expire,
		# Restrict API token privileges with separate ACLs (default), or give full privileges of corresponding user.
		[switch]
		$privsep,
		[Parameter(Mandatory)]
		# User-specific token identifier.
		[string]
		$tokenid,
		[Parameter(Mandatory)]
		# User ID
		[string]
		$userid
	)
	$Options = @()
	$Options.Add('tokenid', $tokenid)
	$Options.Add('userid', $userid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($expire -and -not [String]::IsNullOrEmpty($expire) -and -not [String]::IsNullOrWhiteSpace($expire)) { $Options.Add('expire', $expire) }
	if ($privsep) { $Options.Add('privsep', $privsep) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/access/users/{userid}/token/{tokenid}" -Options $Options
}
function Remove-AccessUsersTokenTokenid {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# User-specific token identifier.
		[string]
		$tokenid,
		[Parameter(Mandatory)]
		# User ID
		[string]
		$userid
	)
	$Options = @()
	$Options.Add('tokenid', $tokenid)
	$Options.Add('userid', $userid)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/access/users/{userid}/token/{tokenid}" -Options $Options
}
function Get-AccessGroups {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/access/groups"
}
function New-AccessGroups {
	[CmdletBinding()]
	param(
		# 
		[string]
		$comment,
		[Parameter(Mandatory)]
		# 
		[string]
		$groupid
	)
	$Options = @()
	$Options.Add('groupid', $groupid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	Invoke-ProxmoxAPI -Method POST -Resource "/access/groups" -Options $Options
}
function Get-AccessGroupsGroupid {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# 
		[string]
		$groupid
	)
	$Options = @()
	$Options.Add('groupid', $groupid)
	Invoke-ProxmoxAPI -Method GET -Resource "/access/groups/{groupid}" -Options $Options
}
function Set-AccessGroupsGroupid {
	[CmdletBinding()]
	param(
		# 
		[string]
		$comment,
		[Parameter(Mandatory)]
		# 
		[string]
		$groupid
	)
	$Options = @()
	$Options.Add('groupid', $groupid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/access/groups/{groupid}" -Options $Options
}
function Remove-AccessGroupsGroupid {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# 
		[string]
		$groupid
	)
	$Options = @()
	$Options.Add('groupid', $groupid)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/access/groups/{groupid}" -Options $Options
}
function Get-AccessRoles {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/access/roles"
}
function New-AccessRoles {
	[CmdletBinding()]
	param(
		# 
		[string]
		$privs,
		[Parameter(Mandatory)]
		# 
		[string]
		$roleid
	)
	$Options = @()
	$Options.Add('roleid', $roleid)
	if ($privs -and -not [String]::IsNullOrEmpty($privs) -and -not [String]::IsNullOrWhiteSpace($privs)) { $Options.Add('privs', $privs) }
	Invoke-ProxmoxAPI -Method POST -Resource "/access/roles" -Options $Options
}
function Get-AccessRolesRoleid {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# 
		[string]
		$roleid
	)
	$Options = @()
	$Options.Add('roleid', $roleid)
	Invoke-ProxmoxAPI -Method GET -Resource "/access/roles/{roleid}" -Options $Options
}
function Set-AccessRolesRoleid {
	[CmdletBinding()]
	param(
		# 
		[switch]
		$append,
		# 
		[string]
		$privs,
		[Parameter(Mandatory)]
		# 
		[string]
		$roleid
	)
	$Options = @()
	$Options.Add('roleid', $roleid)
	if ($append) { $Options.Add('append', $append) }
	if ($privs -and -not [String]::IsNullOrEmpty($privs) -and -not [String]::IsNullOrWhiteSpace($privs)) { $Options.Add('privs', $privs) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/access/roles/{roleid}" -Options $Options
}
function Remove-AccessRolesRoleid {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# 
		[string]
		$roleid
	)
	$Options = @()
	$Options.Add('roleid', $roleid)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/access/roles/{roleid}" -Options $Options
}
function Get-AccessAcl {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/access/acl"
}
function Set-AccessAcl {
	[CmdletBinding()]
	param(
		# Remove permissions (instead of adding it).
		[switch]
		$delete,
		# List of groups.
		[string]
		$groups,
		[Parameter(Mandatory)]
		# Access control path
		[string]
		$path,
		# Allow to propagate (inherit) permissions.
		[switch]
		$propagate,
		[Parameter(Mandatory)]
		# List of roles.
		[string]
		$roles,
		# List of API tokens.
		[string]
		$tokens,
		# List of users.
		[string]
		$users
	)
	$Options = @()
	$Options.Add('path', $path)
	$Options.Add('roles', $roles)
	if ($delete) { $Options.Add('delete', $delete) }
	if ($groups -and -not [String]::IsNullOrEmpty($groups) -and -not [String]::IsNullOrWhiteSpace($groups)) { $Options.Add('groups', $groups) }
	if ($propagate) { $Options.Add('propagate', $propagate) }
	if ($tokens -and -not [String]::IsNullOrEmpty($tokens) -and -not [String]::IsNullOrWhiteSpace($tokens)) { $Options.Add('tokens', $tokens) }
	if ($users -and -not [String]::IsNullOrEmpty($users) -and -not [String]::IsNullOrWhiteSpace($users)) { $Options.Add('users', $users) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/access/acl" -Options $Options
}
function Get-AccessDomains {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/access/domains"
}
function New-AccessDomains {
	[CmdletBinding()]
	param(
		# Automatically create users if they do not exist.
		[switch]
		$autocreate,
		# LDAP base domain name
		[string]
		$base_dn,
		# LDAP bind domain name
		[string]
		$bind_dn,
		# Path to the CA certificate store
		[string]
		$capath,
		# username is case-sensitive
		[switch]
		$casesensitive,
		# Path to the client certificate
		[string]
		$cert,
		# Path to the client certificate key
		[string]
		$certkey,
		# OpenID Client ID
		[string]
		$clientid,
		# OpenID Client Key
		[string]
		$clientkey,
		# Description.
		[string]
		$comment,
		# Use this as default realm
		[switch]
		$default,
		# AD domain name
		[string]
		$domain,
		# LDAP filter for user sync.
		[string]
		$filter,
		# The objectclasses for groups.
		[string]
		$group_classes,
		# LDAP base domain name for group sync. If not set, the base_dn will be used.
		[string]
		$group_dn,
		# LDAP filter for group sync.
		[string]
		$group_filter,
		# LDAP attribute representing a groups name. If not set or found, the first value of the DN will be used as name.
		[string]
		$group_name_attr,
		# OpenID Issuer Url
		[string]
		$issuerurl,
		# LDAP protocol mode.
		[string]
		$mode,
		# LDAP bind password. Will be stored in '/etc/pve/priv/realm/<REALM>.pw'.
		[securestring]
		$password,
		# Server port.
		[integer]
		$port,
		[Parameter(Mandatory)]
		# Authentication domain ID
		[string]
		$realm,
		# Use secure LDAPS protocol. DEPRECATED: use 'mode' instead.
		[switch]
		$secure,
		# Server IP address (or DNS name)
		[string]
		$server1,
		# Fallback Server IP address (or DNS name)
		[string]
		$server2,
		# LDAPS TLS/SSL version. It's not recommended to use version older than 1.2!
		[string]
		$sslversion,
		# The default options for behavior of synchronizations.
		[string]
		$syncdefaultsoptions,
		# Comma separated list of key=value pairs for specifying which LDAP attributes map to which PVE user field. For example, to map the LDAP attribute 'mail' to PVEs 'email', write  'email=mail'. By default, each PVE user field is represented  by an LDAP attribute of the same name.
		[string]
		$sync_attributes,
		# Use Two-factor authentication.
		[string]
		$tfa,
		[Parameter(Mandatory)]
		# Realm type.
		[string]
		$type,
		# OpenID claim used to generate the unique username.
		[string]
		$usernameclaim,
		# LDAP user attribute name
		[string]
		$user_attr,
		# The objectclasses for users.
		[string]
		$user_classes,
		# Verify the server's SSL certificate
		[switch]
		$verify
	)
	$Options = @()
	$Options.Add('realm', $realm)
	$Options.Add('type', $type)
	if ($autocreate) { $Options.Add('autocreate', $autocreate) }
	if ($base_dn -and -not [String]::IsNullOrEmpty($base_dn) -and -not [String]::IsNullOrWhiteSpace($base_dn)) { $Options.Add('base_dn', $base_dn) }
	if ($bind_dn -and -not [String]::IsNullOrEmpty($bind_dn) -and -not [String]::IsNullOrWhiteSpace($bind_dn)) { $Options.Add('bind_dn', $bind_dn) }
	if ($capath -and -not [String]::IsNullOrEmpty($capath) -and -not [String]::IsNullOrWhiteSpace($capath)) { $Options.Add('capath', $capath) }
	if ($casesensitive) { $Options.Add('case-sensitive', $casesensitive) }
	if ($cert -and -not [String]::IsNullOrEmpty($cert) -and -not [String]::IsNullOrWhiteSpace($cert)) { $Options.Add('cert', $cert) }
	if ($certkey -and -not [String]::IsNullOrEmpty($certkey) -and -not [String]::IsNullOrWhiteSpace($certkey)) { $Options.Add('certkey', $certkey) }
	if ($clientid -and -not [String]::IsNullOrEmpty($clientid) -and -not [String]::IsNullOrWhiteSpace($clientid)) { $Options.Add('client-id', $clientid) }
	if ($clientkey -and -not [String]::IsNullOrEmpty($clientkey) -and -not [String]::IsNullOrWhiteSpace($clientkey)) { $Options.Add('client-key', $clientkey) }
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($default) { $Options.Add('default', $default) }
	if ($domain -and -not [String]::IsNullOrEmpty($domain) -and -not [String]::IsNullOrWhiteSpace($domain)) { $Options.Add('domain', $domain) }
	if ($filter -and -not [String]::IsNullOrEmpty($filter) -and -not [String]::IsNullOrWhiteSpace($filter)) { $Options.Add('filter', $filter) }
	if ($group_classes -and -not [String]::IsNullOrEmpty($group_classes) -and -not [String]::IsNullOrWhiteSpace($group_classes)) { $Options.Add('group_classes', $group_classes) }
	if ($group_dn -and -not [String]::IsNullOrEmpty($group_dn) -and -not [String]::IsNullOrWhiteSpace($group_dn)) { $Options.Add('group_dn', $group_dn) }
	if ($group_filter -and -not [String]::IsNullOrEmpty($group_filter) -and -not [String]::IsNullOrWhiteSpace($group_filter)) { $Options.Add('group_filter', $group_filter) }
	if ($group_name_attr -and -not [String]::IsNullOrEmpty($group_name_attr) -and -not [String]::IsNullOrWhiteSpace($group_name_attr)) { $Options.Add('group_name_attr', $group_name_attr) }
	if ($issuerurl -and -not [String]::IsNullOrEmpty($issuerurl) -and -not [String]::IsNullOrWhiteSpace($issuerurl)) { $Options.Add('issuer-url', $issuerurl) }
	if ($mode -and -not [String]::IsNullOrEmpty($mode) -and -not [String]::IsNullOrWhiteSpace($mode)) { $Options.Add('mode', $mode) }
	if ($password) { $Options.Add('password', $($password | ConvertFrom-SecureString -AsPlainText)) }
	if ($port -and -not [String]::IsNullOrEmpty($port) -and -not [String]::IsNullOrWhiteSpace($port)) { $Options.Add('port', $port) }
	if ($secure) { $Options.Add('secure', $secure) }
	if ($server1 -and -not [String]::IsNullOrEmpty($server1) -and -not [String]::IsNullOrWhiteSpace($server1)) { $Options.Add('server1', $server1) }
	if ($server2 -and -not [String]::IsNullOrEmpty($server2) -and -not [String]::IsNullOrWhiteSpace($server2)) { $Options.Add('server2', $server2) }
	if ($sslversion -and -not [String]::IsNullOrEmpty($sslversion) -and -not [String]::IsNullOrWhiteSpace($sslversion)) { $Options.Add('sslversion', $sslversion) }
	if ($syncdefaultsoptions -and -not [String]::IsNullOrEmpty($syncdefaultsoptions) -and -not [String]::IsNullOrWhiteSpace($syncdefaultsoptions)) { $Options.Add('sync-defaults-options', $syncdefaultsoptions) }
	if ($sync_attributes -and -not [String]::IsNullOrEmpty($sync_attributes) -and -not [String]::IsNullOrWhiteSpace($sync_attributes)) { $Options.Add('sync_attributes', $sync_attributes) }
	if ($tfa -and -not [String]::IsNullOrEmpty($tfa) -and -not [String]::IsNullOrWhiteSpace($tfa)) { $Options.Add('tfa', $tfa) }
	if ($usernameclaim -and -not [String]::IsNullOrEmpty($usernameclaim) -and -not [String]::IsNullOrWhiteSpace($usernameclaim)) { $Options.Add('username-claim', $usernameclaim) }
	if ($user_attr -and -not [String]::IsNullOrEmpty($user_attr) -and -not [String]::IsNullOrWhiteSpace($user_attr)) { $Options.Add('user_attr', $user_attr) }
	if ($user_classes -and -not [String]::IsNullOrEmpty($user_classes) -and -not [String]::IsNullOrWhiteSpace($user_classes)) { $Options.Add('user_classes', $user_classes) }
	if ($verify) { $Options.Add('verify', $verify) }
	Invoke-ProxmoxAPI -Method POST -Resource "/access/domains" -Options $Options
}
function Get-AccessDomainsRealm {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Authentication domain ID
		[string]
		$realm
	)
	$Options = @()
	$Options.Add('realm', $realm)
	Invoke-ProxmoxAPI -Method GET -Resource "/access/domains/{realm}" -Options $Options
}
function Set-AccessDomainsRealm {
	[CmdletBinding()]
	param(
		# Automatically create users if they do not exist.
		[switch]
		$autocreate,
		# LDAP base domain name
		[string]
		$base_dn,
		# LDAP bind domain name
		[string]
		$bind_dn,
		# Path to the CA certificate store
		[string]
		$capath,
		# username is case-sensitive
		[switch]
		$casesensitive,
		# Path to the client certificate
		[string]
		$cert,
		# Path to the client certificate key
		[string]
		$certkey,
		# OpenID Client ID
		[string]
		$clientid,
		# OpenID Client Key
		[string]
		$clientkey,
		# Description.
		[string]
		$comment,
		# Use this as default realm
		[switch]
		$default,
		# A list of settings you want to delete.
		[string]
		$delete,
		# Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.
		[string]
		$digest,
		# AD domain name
		[string]
		$domain,
		# LDAP filter for user sync.
		[string]
		$filter,
		# The objectclasses for groups.
		[string]
		$group_classes,
		# LDAP base domain name for group sync. If not set, the base_dn will be used.
		[string]
		$group_dn,
		# LDAP filter for group sync.
		[string]
		$group_filter,
		# LDAP attribute representing a groups name. If not set or found, the first value of the DN will be used as name.
		[string]
		$group_name_attr,
		# OpenID Issuer Url
		[string]
		$issuerurl,
		# LDAP protocol mode.
		[string]
		$mode,
		# LDAP bind password. Will be stored in '/etc/pve/priv/realm/<REALM>.pw'.
		[securestring]
		$password,
		# Server port.
		[integer]
		$port,
		[Parameter(Mandatory)]
		# Authentication domain ID
		[string]
		$realm,
		# Use secure LDAPS protocol. DEPRECATED: use 'mode' instead.
		[switch]
		$secure,
		# Server IP address (or DNS name)
		[string]
		$server1,
		# Fallback Server IP address (or DNS name)
		[string]
		$server2,
		# LDAPS TLS/SSL version. It's not recommended to use version older than 1.2!
		[string]
		$sslversion,
		# The default options for behavior of synchronizations.
		[string]
		$syncdefaultsoptions,
		# Comma separated list of key=value pairs for specifying which LDAP attributes map to which PVE user field. For example, to map the LDAP attribute 'mail' to PVEs 'email', write  'email=mail'. By default, each PVE user field is represented  by an LDAP attribute of the same name.
		[string]
		$sync_attributes,
		# Use Two-factor authentication.
		[string]
		$tfa,
		# LDAP user attribute name
		[string]
		$user_attr,
		# The objectclasses for users.
		[string]
		$user_classes,
		# Verify the server's SSL certificate
		[switch]
		$verify
	)
	$Options = @()
	$Options.Add('realm', $realm)
	if ($autocreate) { $Options.Add('autocreate', $autocreate) }
	if ($base_dn -and -not [String]::IsNullOrEmpty($base_dn) -and -not [String]::IsNullOrWhiteSpace($base_dn)) { $Options.Add('base_dn', $base_dn) }
	if ($bind_dn -and -not [String]::IsNullOrEmpty($bind_dn) -and -not [String]::IsNullOrWhiteSpace($bind_dn)) { $Options.Add('bind_dn', $bind_dn) }
	if ($capath -and -not [String]::IsNullOrEmpty($capath) -and -not [String]::IsNullOrWhiteSpace($capath)) { $Options.Add('capath', $capath) }
	if ($casesensitive) { $Options.Add('case-sensitive', $casesensitive) }
	if ($cert -and -not [String]::IsNullOrEmpty($cert) -and -not [String]::IsNullOrWhiteSpace($cert)) { $Options.Add('cert', $cert) }
	if ($certkey -and -not [String]::IsNullOrEmpty($certkey) -and -not [String]::IsNullOrWhiteSpace($certkey)) { $Options.Add('certkey', $certkey) }
	if ($clientid -and -not [String]::IsNullOrEmpty($clientid) -and -not [String]::IsNullOrWhiteSpace($clientid)) { $Options.Add('client-id', $clientid) }
	if ($clientkey -and -not [String]::IsNullOrEmpty($clientkey) -and -not [String]::IsNullOrWhiteSpace($clientkey)) { $Options.Add('client-key', $clientkey) }
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($default) { $Options.Add('default', $default) }
	if ($delete -and -not [String]::IsNullOrEmpty($delete) -and -not [String]::IsNullOrWhiteSpace($delete)) { $Options.Add('delete', $delete) }
	if ($digest -and -not [String]::IsNullOrEmpty($digest) -and -not [String]::IsNullOrWhiteSpace($digest)) { $Options.Add('digest', $digest) }
	if ($domain -and -not [String]::IsNullOrEmpty($domain) -and -not [String]::IsNullOrWhiteSpace($domain)) { $Options.Add('domain', $domain) }
	if ($filter -and -not [String]::IsNullOrEmpty($filter) -and -not [String]::IsNullOrWhiteSpace($filter)) { $Options.Add('filter', $filter) }
	if ($group_classes -and -not [String]::IsNullOrEmpty($group_classes) -and -not [String]::IsNullOrWhiteSpace($group_classes)) { $Options.Add('group_classes', $group_classes) }
	if ($group_dn -and -not [String]::IsNullOrEmpty($group_dn) -and -not [String]::IsNullOrWhiteSpace($group_dn)) { $Options.Add('group_dn', $group_dn) }
	if ($group_filter -and -not [String]::IsNullOrEmpty($group_filter) -and -not [String]::IsNullOrWhiteSpace($group_filter)) { $Options.Add('group_filter', $group_filter) }
	if ($group_name_attr -and -not [String]::IsNullOrEmpty($group_name_attr) -and -not [String]::IsNullOrWhiteSpace($group_name_attr)) { $Options.Add('group_name_attr', $group_name_attr) }
	if ($issuerurl -and -not [String]::IsNullOrEmpty($issuerurl) -and -not [String]::IsNullOrWhiteSpace($issuerurl)) { $Options.Add('issuer-url', $issuerurl) }
	if ($mode -and -not [String]::IsNullOrEmpty($mode) -and -not [String]::IsNullOrWhiteSpace($mode)) { $Options.Add('mode', $mode) }
	if ($password) { $Options.Add('password', $($password | ConvertFrom-SecureString -AsPlainText)) }
	if ($port -and -not [String]::IsNullOrEmpty($port) -and -not [String]::IsNullOrWhiteSpace($port)) { $Options.Add('port', $port) }
	if ($secure) { $Options.Add('secure', $secure) }
	if ($server1 -and -not [String]::IsNullOrEmpty($server1) -and -not [String]::IsNullOrWhiteSpace($server1)) { $Options.Add('server1', $server1) }
	if ($server2 -and -not [String]::IsNullOrEmpty($server2) -and -not [String]::IsNullOrWhiteSpace($server2)) { $Options.Add('server2', $server2) }
	if ($sslversion -and -not [String]::IsNullOrEmpty($sslversion) -and -not [String]::IsNullOrWhiteSpace($sslversion)) { $Options.Add('sslversion', $sslversion) }
	if ($syncdefaultsoptions -and -not [String]::IsNullOrEmpty($syncdefaultsoptions) -and -not [String]::IsNullOrWhiteSpace($syncdefaultsoptions)) { $Options.Add('sync-defaults-options', $syncdefaultsoptions) }
	if ($sync_attributes -and -not [String]::IsNullOrEmpty($sync_attributes) -and -not [String]::IsNullOrWhiteSpace($sync_attributes)) { $Options.Add('sync_attributes', $sync_attributes) }
	if ($tfa -and -not [String]::IsNullOrEmpty($tfa) -and -not [String]::IsNullOrWhiteSpace($tfa)) { $Options.Add('tfa', $tfa) }
	if ($user_attr -and -not [String]::IsNullOrEmpty($user_attr) -and -not [String]::IsNullOrWhiteSpace($user_attr)) { $Options.Add('user_attr', $user_attr) }
	if ($user_classes -and -not [String]::IsNullOrEmpty($user_classes) -and -not [String]::IsNullOrWhiteSpace($user_classes)) { $Options.Add('user_classes', $user_classes) }
	if ($verify) { $Options.Add('verify', $verify) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/access/domains/{realm}" -Options $Options
}
function Remove-AccessDomainsRealm {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# Authentication domain ID
		[string]
		$realm
	)
	$Options = @()
	$Options.Add('realm', $realm)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/access/domains/{realm}" -Options $Options
}
function New-AccessDomainsRealmSync {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		# If set, does not write anything.
		[switch]
		$dryrun,
		# Enable newly synced users immediately.
		[switch]
		$enablenew,
		# If set, uses the LDAP Directory as source of truth, deleting users or groups not returned from the sync. Otherwise only syncs information which is not already present, and does not deletes or modifies anything else.
		[switch]
		$full,
		# Remove ACLs for users or groups which were removed from the config during a sync.
		[switch]
		$purge,
		[Parameter(Mandatory)]
		# Authentication domain ID
		[string]
		$realm,
		# Select what to sync.
		[string]
		$scope
	)
	$Options = @()
	$Options.Add('realm', $realm)
	if ($dryrun) { $Options.Add('dry-run', $dryrun) }
	if ($enablenew) { $Options.Add('enable-new', $enablenew) }
	if ($full) { $Options.Add('full', $full) }
	if ($purge) { $Options.Add('purge', $purge) }
	if ($scope -and -not [String]::IsNullOrEmpty($scope) -and -not [String]::IsNullOrWhiteSpace($scope)) { $Options.Add('scope', $scope) }
	Invoke-ProxmoxAPI -Method POST -Resource "/access/domains/{realm}/sync" -Options $Options
}
function Get-AccessOpenid {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/access/openid"
}
function New-AccessAuthUrl {
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		# Authentication domain ID
		[string]
		$realm,
		[Parameter(Mandatory)]
		# Redirection Url. The client should set this to the used server url (location.origin).
		[string]
		$redirecturl
	)
	$Options = @()
	$Options.Add('realm', $realm)
	$Options.Add('redirect-url', $redirecturl)
	Invoke-ProxmoxAPI -Method POST -Resource "/access/openid/auth-url" -Options $Options
}
function Get-AccessTfa {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/access/tfa"
}
function New-AccessTfa {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# The response to the current authentication challenge.
		[string]
		$response
	)
	$Options = @()
	$Options.Add('response', $response)
	Invoke-ProxmoxAPI -Method POST -Resource "/access/tfa" -Options $Options
}
function New-AccessLogin {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# OpenId authorization code.
		[string]
		$code,
		[Parameter(Mandatory)]
		# Redirection Url. The client should set this to the used server url (location.origin).
		[string]
		$redirecturl,
		[Parameter(Mandatory)]
		# OpenId state.
		[string]
		$state
	)
	$Options = @()
	$Options.Add('code', $code)
	$Options.Add('redirect-url', $redirecturl)
	$Options.Add('state', $state)
	Invoke-ProxmoxAPI -Method POST -Resource "/access/openid/login" -Options $Options
}
function Get-AccessTicket {
	[CmdletBinding()]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/access/ticket"
}
function Get-AccessTfaUserid {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
		[Parameter(Mandatory)]
		# User ID
		[string]
		$userid
	)
	$Options = @()
	$Options.Add('userid', $userid)
	Invoke-ProxmoxAPI -Method GET -Resource "/access/tfa/{userid}" -Options $Options
}
function New-AccessTfaUserid {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		# When responding to a u2f challenge: the original challenge string
		[string]
		$challenge,
		# A description to distinguish multiple entries from one another
		[string]
		$description,
		# The current password.
		[securestring]
		$password,
		# A totp URI.
		[string]
		$totp,
		[Parameter(Mandatory)]
		# TFA Entry Type.
		[string]
		$type,
		[Parameter(Mandatory)]
		# User ID
		[string]
		$userid,
		# The current value for the provided totp URI, or a Webauthn/U2F challenge response
		[string]
		$value
	)
	$Options = @()
	$Options.Add('type', $type)
	$Options.Add('userid', $userid)
	if ($challenge -and -not [String]::IsNullOrEmpty($challenge) -and -not [String]::IsNullOrWhiteSpace($challenge)) { $Options.Add('challenge', $challenge) }
	if ($description -and -not [String]::IsNullOrEmpty($description) -and -not [String]::IsNullOrWhiteSpace($description)) { $Options.Add('description', $description) }
	if ($password) { $Options.Add('password', $($password | ConvertFrom-SecureString -AsPlainText)) }
	if ($totp -and -not [String]::IsNullOrEmpty($totp) -and -not [String]::IsNullOrWhiteSpace($totp)) { $Options.Add('totp', $totp) }
	if ($value -and -not [String]::IsNullOrEmpty($value) -and -not [String]::IsNullOrWhiteSpace($value)) { $Options.Add('value', $value) }
	Invoke-ProxmoxAPI -Method POST -Resource "/access/tfa/{userid}" -Options $Options
}
function Get-AccessTfaId {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# A TFA entry id.
		[string]
		$id,
		[Parameter(Mandatory)]
		# User ID
		[string]
		$userid
	)
	$Options = @()
	$Options.Add('id', $id)
	$Options.Add('userid', $userid)
	Invoke-ProxmoxAPI -Method GET -Resource "/access/tfa/{userid}/{id}" -Options $Options
}
function Set-AccessTfaId {
	[CmdletBinding()]
	param(
		# A description to distinguish multiple entries from one another
		[string]
		$description,
		# Whether the entry should be enabled for login.
		[switch]
		$enable,
		[Parameter(Mandatory)]
		# A TFA entry id.
		[string]
		$id,
		# The current password.
		[securestring]
		$password,
		[Parameter(Mandatory)]
		# User ID
		[string]
		$userid
	)
	$Options = @()
	$Options.Add('id', $id)
	$Options.Add('userid', $userid)
	if ($description -and -not [String]::IsNullOrEmpty($description) -and -not [String]::IsNullOrWhiteSpace($description)) { $Options.Add('description', $description) }
	if ($enable) { $Options.Add('enable', $enable) }
	if ($password) { $Options.Add('password', $($password | ConvertFrom-SecureString -AsPlainText)) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/access/tfa/{userid}/{id}" -Options $Options
}
function Remove-AccessTfaId {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# A TFA entry id.
		[string]
		$id,
		# The current password.
		[securestring]
		$password,
		[Parameter(Mandatory)]
		# User ID
		[string]
		$userid
	)
	$Options = @()
	$Options.Add('id', $id)
	$Options.Add('userid', $userid)
	if ($password) { $Options.Add('password', $($password | ConvertFrom-SecureString -AsPlainText)) }
	Invoke-ProxmoxAPI -Method DELETE -Resource "/access/tfa/{userid}/{id}" -Options $Options
}
function Set-AccessPassword {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# The new password.
		[securestring]
		$password,
		[Parameter(Mandatory)]
		# User ID
		[string]
		$userid
	)
	$Options = @()
	$Options.Add('password', $password)
	$Options.Add('userid', $userid)
	Invoke-ProxmoxAPI -Method PUT -Resource "/access/password" -Options $Options
}
function Get-AccessPermissions {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		# Only dump this specific path, not the whole tree.
		[string]
		$path,
		# User ID or full API token ID
		[string]
		$userid
	)
	$Options = @()
	if ($path -and -not [String]::IsNullOrEmpty($path) -and -not [String]::IsNullOrWhiteSpace($path)) { $Options.Add('path', $path) }
	if ($userid -and -not [String]::IsNullOrEmpty($userid) -and -not [String]::IsNullOrWhiteSpace($userid)) { $Options.Add('userid', $userid) }
	Invoke-ProxmoxAPI -Method GET -Resource "/access/permissions" -Options $Options
}
function Get-Pools {
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/pools"
}
function New-Pools {
	[CmdletBinding()]
	param(
		# 
		[string]
		$comment,
		[Parameter(Mandatory)]
		# 
		[string]
		$poolid
	)
	$Options = @()
	$Options.Add('poolid', $poolid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	Invoke-ProxmoxAPI -Method POST -Resource "/pools" -Options $Options
}
function Get-PoolsPoolid {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		# 
		[string]
		$poolid
	)
	$Options = @()
	$Options.Add('poolid', $poolid)
	Invoke-ProxmoxAPI -Method GET -Resource "/pools/{poolid}" -Options $Options
}
function Set-PoolsPoolid {
	[CmdletBinding()]
	param(
		# 
		[string]
		$comment,
		# Remove vms/storage (instead of adding it).
		[switch]
		$delete,
		[Parameter(Mandatory)]
		# 
		[string]
		$poolid,
		# List of storage IDs.
		[string]
		$storage,
		# List of virtual machines.
		[string]
		$vms
	)
	$Options = @()
	$Options.Add('poolid', $poolid)
	if ($comment -and -not [String]::IsNullOrEmpty($comment) -and -not [String]::IsNullOrWhiteSpace($comment)) { $Options.Add('comment', $comment) }
	if ($delete) { $Options.Add('delete', $delete) }
	if ($storage -and -not [String]::IsNullOrEmpty($storage) -and -not [String]::IsNullOrWhiteSpace($storage)) { $Options.Add('storage', $storage) }
	if ($vms -and -not [String]::IsNullOrEmpty($vms) -and -not [String]::IsNullOrWhiteSpace($vms)) { $Options.Add('vms', $vms) }
	Invoke-ProxmoxAPI -Method PUT -Resource "/pools/{poolid}" -Options $Options
}
function Remove-PoolsPoolid {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		# 
		[string]
		$poolid
	)
	$Options = @()
	$Options.Add('poolid', $poolid)
	Invoke-ProxmoxAPI -Method DELETE -Resource "/pools/{poolid}" -Options $Options
}
function Get-Version {
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
	)
	Invoke-ProxmoxAPI -Method GET -Resource "/version"
}
Export-ModuleMember -Function @(
	'Get-Cluster'
	'Get-ClusterReplication'
	'New-ClusterReplication'
	'Get-ClusterReplicationId'
	'Set-ClusterReplicationId'
	'Remove-ClusterReplicationId'
	'Get-ClusterMetrics'
	'Get-ClusterMetricsServer'
	'Get-ClusterMetricsServerId'
	'New-ClusterMetricsServerId'
	'Set-ClusterMetricsServerId'
	'Remove-ClusterMetricsServerId'
	'Get-ClusterConfig'
	'New-ClusterConfig'
	'Get-ClusterConfigApiversion'
	'Get-ClusterFirewall'
	'Get-ClusterConfigNodes'
	'New-ClusterConfigNodesNode'
	'Remove-ClusterConfigNodesNode'
	'Get-ClusterBackup'
	'New-ClusterBackup'
	'Get-ClusterConfigJoin'
	'New-ClusterConfigJoin'
	'Get-ClusterBackupInfo'
	'Get-ClusterConfigTotem'
	'Get-ClusterHa'
	'Get-ClusterConfigQdevice'
	'Get-ClusterAcme'
	'Get-ClusterFirewallGroups'
	'New-ClusterFirewallGroups'
	'Get-ClusterFirewallGroupsGroup'
	'New-ClusterFirewallGroupsGroup'
	'Remove-ClusterFirewallGroupsGroup'
	'Get-ClusterFirewallGroupsGroupPos'
	'Set-ClusterFirewallGroupsGroupPos'
	'Remove-ClusterFirewallGroupsGroupPos'
	'Get-ClusterCeph'
	'Get-ClusterFirewallRules'
	'New-ClusterFirewallRules'
	'Get-ClusterFirewallRulesPos'
	'Set-ClusterFirewallRulesPos'
	'Remove-ClusterFirewallRulesPos'
	'Get-ClusterJobs'
	'Get-ClusterFirewallIpset'
	'New-ClusterFirewallIpset'
	'Get-ClusterFirewallIpsetName'
	'New-ClusterFirewallIpsetName'
	'Remove-ClusterFirewallIpsetName'
	'Get-ClusterFirewallIpsetNameCidr'
	'Set-ClusterFirewallIpsetNameCidr'
	'Remove-ClusterFirewallIpsetNameCidr'
	'Get-ClusterSdn'
	'Set-ClusterSdn'
	'Get-ClusterFirewallAliases'
	'New-ClusterFirewallAliases'
	'Get-ClusterFirewallAliasesName'
	'Set-ClusterFirewallAliasesName'
	'Remove-ClusterFirewallAliasesName'
	'Get-ClusterLog'
	'Get-ClusterFirewallOptions'
	'Set-ClusterFirewallOptions'
	'Get-ClusterResources'
	'Get-ClusterFirewallMacros'
	'Get-ClusterTasks'
	'Get-ClusterFirewallRefs'
	'Get-ClusterOptions'
	'Set-ClusterOptions'
	'Get-ClusterBackupId'
	'Set-ClusterBackupId'
	'Remove-ClusterBackupId'
	'Get-ClusterBackupIncludedVolumes'
	'Get-ClusterStatus'
	'Get-ClusterBackupInfoNotBackedUp'
	'Get-ClusterNextid'
	'Get-ClusterHaResources'
	'New-ClusterHaResources'
	'Get-ClusterHaResourcesSid'
	'Set-ClusterHaResourcesSid'
	'Remove-ClusterHaResourcesSid'
	'New-ClusterHaResourcesMigrate'
	'New-ClusterHaResourcesRelocate'
	'Get-Nodes'
	'Get-Node'
	'Get-NodeQemu'
	'New-NodeQemu'
	'Get-NodeQemuVmid'
	'Remove-NodeQemuVmid'
	'Get-NodeQemuFirewall'
	'Get-NodeQemuFirewallRules'
	'New-NodeQemuFirewallRules'
	'Get-NodeQemuFirewallRulesPos'
	'Set-NodeQemuFirewallRulesPos'
	'Remove-NodeQemuFirewallRulesPos'
	'Get-NodeQemuAgent'
	'New-NodeQemuAgent'
	'Get-NodeQemuFirewallAliases'
	'New-NodeQemuFirewallAliases'
	'Get-NodeQemuFirewallAliasesName'
	'Set-NodeQemuFirewallAliasesName'
	'Remove-NodeQemuFirewallAliasesName'
	'Get-NodeQemuRrd'
	'Get-NodeQemuFirewallIpset'
	'New-NodeQemuFirewallIpset'
	'Get-NodeQemuFirewallIpsetName'
	'New-NodeQemuFirewallIpsetName'
	'Remove-NodeQemuFirewallIpsetName'
	'Get-NodeQemuFirewallIpsetNameCidr'
	'Set-NodeQemuFirewallIpsetNameCidr'
	'Remove-NodeQemuFirewallIpsetNameCidr'
	'Get-NodeQemuRrddata'
	'Get-NodeQemuFirewallOptions'
	'Set-NodeQemuFirewallOptions'
	'Get-NodeQemuConfig'
	'New-NodeQemuConfig'
	'Set-NodeQemuConfig'
	'Get-NodeQemuFirewallLog'
	'Get-NodeQemuPending'
	'Get-NodeQemuFirewallRefs'
	'Set-NodeQemuUnlink'
	'New-NodeQemuAgentFsfreezeFreeze'
	'New-NodeQemuVncproxy'
	'New-NodeQemuAgentFsfreezeStatus'
	'New-NodeQemuTermproxy'
	'New-NodeQemuAgentFsfreezeThaw'
	'Get-NodeQemuVncwebsocket'
	'New-NodeQemuAgentFstrim'
	'New-NodeQemuSpiceproxy'
	'Get-NodeQemuAgentGetFsinfo'
	'Get-NodeQemuStatus'
	'Get-NodeQemuAgentGetHostName'
	'Set-NodeQemuSendkey'
	'Get-NodeQemuAgentGetMemoryBlockInfo'
	'Get-NodeQemuFeature'
	'Get-NodeQemuAgentGetMemoryBlocks'
	'New-NodeQemuClone'
	'Get-NodeQemuAgentGetOsinfo'
	'New-NodeQemuMoveDisk'
	'Get-NodeQemuAgentGetTime'
	'Get-NodeQemuMigrate'
	'New-NodeQemuMigrate'
	'Get-NodeQemuAgentGetTimezone'
	'New-NodeQemuMonitor'
	'Get-NodeQemuAgentGetUsers'
	'Set-NodeQemuResize'
	'Get-NodeQemuAgentGetVcpus'
	'Get-NodeQemuSnapshot'
	'New-NodeQemuSnapshot'
	'Get-NodeQemuAgentInfo'
	'New-NodeQemuTemplate'
	'Get-NodeQemuAgentNetworkGetInterfaces'
	'New-NodeQemuAgentPing'
	'Get-NodeLxc'
	'New-NodeLxc'
	'Get-NodeLxcVmid'
	'Remove-NodeLxcVmid'
	'Get-NodeLxcConfig'
	'Set-NodeLxcConfig'
	'Get-NodeLxcStatus'
	'Get-NodeLxcStatusCurrent'
	'Get-NodeLxcSnapshot'
	'New-NodeLxcSnapshot'
	'New-NodeLxcStatusStart'
	'Get-NodeLxcFirewall'
	'New-NodeLxcStatusStop'
	'Get-NodeLxcRrd'
	'New-NodeLxcStatusShutdown'
	'Get-NodeLxcRrddata'
	'New-NodeLxcStatusSuspend'
	'New-NodeLxcVncproxy'
	'New-NodeLxcStatusResume'
	'New-NodeLxcTermproxy'
	'New-NodeLxcStatusReboot'
	'Get-NodeLxcVncwebsocket'
	'Get-NodeLxcSnapshotSnapname'
	'Remove-NodeLxcSnapshotSnapname'
	'New-NodeLxcSnapshotSnapnameRollback'
	'Get-NodeLxcSnapshotSnapnameConfig'
	'Set-NodeLxcSnapshotSnapnameConfig'
	'New-NodeLxcSpiceproxy'
	'Get-NodeLxcFirewallRules'
	'New-NodeLxcFirewallRules'
	'Get-NodeLxcFirewallRulesPos'
	'Set-NodeLxcFirewallRulesPos'
	'Remove-NodeLxcFirewallRulesPos'
	'New-NodeLxcMigrate'
	'Get-NodeLxcFirewallAliases'
	'New-NodeLxcFirewallAliases'
	'Get-NodeLxcFirewallAliasesName'
	'Set-NodeLxcFirewallAliasesName'
	'Remove-NodeLxcFirewallAliasesName'
	'Get-NodeLxcFeature'
	'Get-NodeLxcFirewallIpset'
	'New-NodeLxcFirewallIpset'
	'Get-NodeLxcFirewallIpsetName'
	'New-NodeLxcFirewallIpsetName'
	'Remove-NodeLxcFirewallIpsetName'
	'Get-NodeLxcFirewallIpsetNameCidr'
	'Set-NodeLxcFirewallIpsetNameCidr'
	'Remove-NodeLxcFirewallIpsetNameCidr'
	'New-NodeLxcTemplate'
	'Get-NodeLxcFirewallOptions'
	'Set-NodeLxcFirewallOptions'
	'New-NodeLxcClone'
	'Get-NodeLxcFirewallLog'
	'Set-NodeLxcResize'
	'Get-NodeLxcFirewallRefs'
	'New-NodeLxcMoveVolume'
	'Get-NodeLxcPending'
	'Get-NodeCeph'
	'Get-NodeCephOsd'
	'New-NodeCephOsd'
	'Remove-NodeCephOsdOsdid'
	'New-NodeCephOsdIn'
	'New-NodeCephOsdOut'
	'New-NodeCephOsdScrub'
	'New-NodeVzdump'
	'Get-NodeCephMds'
	'New-NodeCephMdsName'
	'Remove-NodeCephMdsName'
	'Get-NodeServices'
	'Get-NodeCephMgr'
	'New-NodeCephMgrId'
	'Remove-NodeCephMgrId'
	'Get-NodeSubscription'
	'New-NodeSubscription'
	'Set-NodeSubscription'
	'Remove-NodeSubscription'
	'Get-NodeCephMon'
	'New-NodeCephMonMonid'
	'Remove-NodeCephMonMonid'
	'Get-NodeNetwork'
	'New-NodeNetwork'
	'Set-NodeNetwork'
	'Remove-NodeNetwork'
	'Get-NodeCephFs'
	'New-NodeCephFsName'
	'Get-NodeTasks'
	'Get-NodeCephPools'
	'New-NodeCephPools'
	'Get-NodeCephPoolsName'
	'Set-NodeCephPoolsName'
	'Remove-NodeCephPoolsName'
	'Get-NodeScan'
	'Get-NodeCephConfig'
	'Get-NodeHardware'
	'Get-NodeCephConfigdb'
	'Get-NodeCapabilities'
	'New-NodeCephInit'
	'Get-NodeStorage'
	'New-NodeCephStop'
	'Get-NodeDisks'
	'New-NodeCephStart'
	'Get-NodeApt'
	'New-NodeCephRestart'
	'Get-NodeFirewall'
	'Get-NodeCephStatus'
	'Get-NodeReplication'
	'Get-NodeCephCrush'
	'Get-NodeCertificates'
	'Get-NodeCephLog'
	'Get-NodeConfig'
	'Set-NodeConfig'
	'Get-NodeCephRules'
	'Get-NodeSdn'
	'Get-NodeVzdumpDefaults'
	'Get-NodeVersion'
	'Get-NodeVzdumpExtractconfig'
	'Get-NodeStatus'
	'New-NodeStatus'
	'Get-NodeServicesService'
	'Get-NodeServicesServiceState'
	'New-NodeServicesServiceStart'
	'New-NodeServicesServiceStop'
	'New-NodeServicesServiceRestart'
	'New-NodeServicesServiceReload'
	'Get-NodeNetstat'
	'New-NodeExecute'
	'Get-NodeNetworkIface'
	'Set-NodeNetworkIface'
	'Remove-NodeNetworkIface'
	'New-NodeWakeonlan'
	'Get-NodeTasksUpid'
	'Remove-NodeTasksUpid'
	'Get-NodeTasksLog'
	'Get-NodeTasksStatus'
	'Get-NodeRrd'
	'Get-NodeScanNfs'
	'Get-NodeRrddata'
	'Get-NodeScanCifs'
	'Get-NodeSyslog'
	'Get-NodeScanPbs'
	'Get-NodeJournal'
	'Get-NodeScanGlusterfs'
	'New-NodeVncshell'
	'Get-NodeScanIscsi'
	'New-NodeTermproxy'
	'Get-NodeScanLvm'
	'Get-NodeVncwebsocket'
	'Get-NodeScanLvmthin'
	'New-NodeSpiceshell'
	'Get-NodeScanZfs'
	'Get-NodeDns'
	'Set-NodeDns'
	'Get-NodeHardwarePci'
	'Get-NodeHardwarePciPciid'
	'Get-NodeHardwarePciMdev'
	'Get-NodeTime'
	'Set-NodeTime'
	'Get-NodeHardwareUsb'
	'Get-NodeAplinfo'
	'New-NodeAplinfo'
	'Get-NodeCapabilitiesQemu'
	'Get-NodeCapabilitiesQemuCpu'
	'Get-NodeCapabilitiesQemuMachines'
	'Get-NodeQueryUrlMetadata'
	'Get-NodeStorage'
	'Get-NodeStoragePrunebackups'
	'Remove-NodeStoragePrunebackups'
	'Get-NodeStorageContent'
	'New-NodeStorageContent'
	'Get-NodeStorageContentVolume'
	'New-NodeStorageContentVolume'
	'Set-NodeStorageContentVolume'
	'Remove-NodeStorageContentVolume'
	'Get-NodeStorageFileRestoreList'
	'Get-NodeStorageStatus'
	'Get-NodeStorageFileRestoreDownload'
	'Get-NodeStorageRrd'
	'Get-NodeStorageRrddata'
	'New-NodeStorageUpload'
	'New-NodeStorageDownloadUrl'
	'Get-NodeReport'
	'Get-NodeDisksLvm'
	'New-NodeDisksLvm'
	'Remove-NodeDisksLvmName'
	'New-NodeStartall'
	'Get-NodeDisksLvmthin'
	'New-NodeDisksLvmthin'
	'Remove-NodeDisksLvmthinName'
	'New-NodeStopall'
	'Get-NodeDisksDirectory'
	'New-NodeDisksDirectory'
	'Remove-NodeDisksDirectoryName'
	'New-NodeMigrateall'
	'Get-NodeDisksZfs'
	'New-NodeDisksZfs'
	'Get-NodeDisksZfsName'
	'Remove-NodeDisksZfsName'
	'Get-NodeHosts'
	'New-NodeHosts'
	'Get-NodeDisksList'
	'Get-Storage'
	'New-Storage'
	'Get-Storage'
	'Set-Storage'
	'Remove-Storage'
	'Get-Access'
	'Get-AccessUsers'
	'New-AccessUsers'
	'Get-AccessUsersUserid'
	'Set-AccessUsersUserid'
	'Remove-AccessUsersUserid'
	'Get-AccessUsersTfa'
	'Get-AccessUsersToken'
	'Get-AccessUsersTokenTokenid'
	'New-AccessUsersTokenTokenid'
	'Set-AccessUsersTokenTokenid'
	'Remove-AccessUsersTokenTokenid'
	'Get-AccessGroups'
	'New-AccessGroups'
	'Get-AccessGroupsGroupid'
	'Set-AccessGroupsGroupid'
	'Remove-AccessGroupsGroupid'
	'Get-AccessRoles'
	'New-AccessRoles'
	'Get-AccessRolesRoleid'
	'Set-AccessRolesRoleid'
	'Remove-AccessRolesRoleid'
	'Get-AccessAcl'
	'Set-AccessAcl'
	'Get-AccessDomains'
	'New-AccessDomains'
	'Get-AccessDomainsRealm'
	'Set-AccessDomainsRealm'
	'Remove-AccessDomainsRealm'
	'New-AccessDomainsRealmSync'
	'Get-AccessOpenid'
	'New-AccessAuthUrl'
	'Get-AccessTfa'
	'New-AccessTfa'
	'New-AccessLogin'
	'Get-AccessTicket'
	'Get-AccessTfaUserid'
	'New-AccessTfaUserid'
	'Get-AccessTfaId'
	'Set-AccessTfaId'
	'Remove-AccessTfaId'
	'Set-AccessPassword'
	'Get-AccessPermissions'
	'Get-Pools'
	'New-Pools'
	'Get-PoolsPoolid'
	'Set-PoolsPoolid'
	'Remove-PoolsPoolid'
	'Get-Version'

)
