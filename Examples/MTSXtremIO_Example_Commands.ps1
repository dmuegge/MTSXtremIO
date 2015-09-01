<#

MTSXtremIO Example Commands

#>


Import-Module MTSXtremIO


# XtremIO Connection example
Disable-CertificateValidation
Set-XIOAPIConnectionInfo -username "admin" -passwordfile "C:\Users\dmuegge\XtremIO.txt" -hostname "RTTXtremIO"


# Get examples
Get-XIOCluster | Where {$_[0]}
Get-XIOCluster | Select name,sys-psnt-serial-number,license-id,sys-sw-version,size-and-capacity,sys-health-state,data-reduction-ratio-text,compression-factor-text,dedup-ratio-text | ft
Get-XIOCluster | Select name,num-of-bricks,num-of-ib-switches,num-of-ssds,num-of-vols,fc-port-speed,iscsi-port-speed,useful-ssd-space-per-ssd,ud-ssd-space,ud-ssd-space-in-use,vol-size | ft
Get-XIOStorageController | Select name,part-number,serial-number,os-version,node-health-state | ft
Get-XIOVolume | Select Name,lb-size,vol-size,logical-space-in-use -first 5 | ft
Get-XIOVolume | Where Name -EQ "lab-datastore"
Get-XIOVolume | Select Name,@{Name="VolGB";Expression={$_."vol-size" / 1024 /1024}} -First 2
Get-XIOBrick | ft
Get-XIOXenvs | Select Name,Index,xms-id | ft
Get-XIOVolumeFolder |  Select -First 1
Get-XIOCluster | Where {$_}
Get-XIOLunMap | ft
Get-XIOInitiator | ft
Get-XIOSnapshot | Select Name,@{Name="AncestorValumeName";Expression={$_."ancestor-vol-id"[1]}},creation-time,vol-size,logical-space-in-use | ft

Get-XIOInitiator | ft
Get-XIOInitiatorGroup | ft
Get-XIOInitiatorGroupFolder | Select caption
Get-XIODataProtectionGroup | ft
Get-XIOSSD | ft
Get-XIOTarget | ft
@('X1-bad','X1-SC2-fc1') | Get-XIOTarget | select name,port-address
Get-XIOTargetGroup | ft
Get-XIOIscsiPortal | ft
Get-XIOIscsiRoute | ft

Get-XIOVolume | Select Name,vol-size,logical-space-in-use | ft



# Get Volume Performance
$AllVolPerf = @()
for ($i = 1; $i -lt 3; $i++){ 
    $Volinfo = Get-XIOVolume
    $AllVolPerf += $Volinfo | Select @{Name="TimeStamp";Expression={(Get-Date -Format s).Replace("T"," ")}},Name,rd-iops,wr-iops,rd-bw,wr-bw,rd-latency,wr-latency,unaligned-iops,unaligned-bw #| Export-csv -Path "C:\Users\dmuegge\Dropbox\DTools\Scripts\PS\XtremIO-POC\RTT-XIO_Vol_Perf.csv" -Append -NoTypeInformation
    Start-Sleep -Seconds 5
}
$AllVolPerf | ft

# Get Disk Performance
$AllSSDPerf = @()
for ($i = 1; $i -lt 3; $i++){ 
    $SSDInfo = Get-XIOSSD
    $AllSSDPerf += $SSDInfo | Select @{Name="TimeStamp";Expression={(Get-Date -Format s).Replace("T"," ")}},Name,index,slot-num,rd-iops,wr-iops,rd-bw,wr-bw #| Export-csv -Path "C:\Users\dmuegge\Dropbox\DTools\Scripts\PS\XtremIO-POC\RTT-XIO_Disk_Perf.csv" -Append -NoTypeInformation
    Start-Sleep -Seconds 5
}
$AllSSDPerf | ft

# Create Volume Folder
New-XIOVolumeFolder -Caption "DMTest" -ParentFolderName "/"

# Rename Volume Folder
Rename-XIOVolumeFolder -Caption "DMFolder" -FolderName "/DMTest"

# Create Volumes
New-XIOVolume -VolSize 10m -VolName DMTest01 -ParentFolderID /DMFolder
New-XIOVolume -VolSize 10m -VolName DMTest02 -ParentFolderID /DMFolder

# Rename Volumes
Update-XIOVolume -VolName "DMTest01" -NewVolName "DMVol01"

# Update Volumes
Update-XIOVolume -VolName "DMVol01" -NewVolSize 10g
Update-XIOVolume -VolName "DMVol01" -VaaiTpAlerts enable

# Create Initiator Group Folder
New-XIOIGFolder -Caption "DMTest01" -ParentFolderName "/"

# Rename Initiator Group Folder
Rename-XIOIGFolder -Caption "DMFolder" -FolderName "/DMTest01"


# Create Lun Maps
Get-XIOInitiatorGroup | Where Name -Like "xesx*" | Select name,index | foreach-object{New-XIOLunMap -Name "DMVol01" -InitiatorGroup $_.index}


# Create Snapshots
New-XIOSnapshot -VolName "DMVol01" -SnapName ("DMVol01_" + (Get-Date -Format yyyyMMdd-HHmmss)) -FolderID "/DMFolder"

for ($i = 1; $i -lt 30; $i++)
{ 
    New-XIOSnapshot -VolName "DMVol01" -SnapName ("DMVol01_" + (Get-Date -Format yyyyMMdd-HHmmss)) -FolderID "/DMFolder"
    Start-Sleep -Seconds 1
}


# Delete Snapshots
Get-XIOSnapshot | Select Name | Where Name -like "DMVol01*" | ForEach-Object {Remove-XIOSnapshot -VolName $_.Name}


# Delete Lun Maps
Get-XIOLunMap | Where vol-name -like "DMVol*" | Foreach-object{Remove-XIOLunMap -Name $_.'mapping-id'[1]}

# Delete Volumes
Remove-XIOVolume -VolName "DMVol01"
Remove-XIOVolume -VolName "DMTest02"
Get-XIOVolume | Where Name -like "DMVol*" |  ForEach-Object {Remove-XIOVolume -VolName $_.Name} 



# Delete Volume Folders
Remove-XIOVolumeFolder -Name "/DMFolder"
