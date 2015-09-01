<#

MTSXtremIO Smoke Test code

Used to test functionality of all XtremIO REST API objects via MTSXtremIO PowerShell module 

#>

Import-Module MTSXtremIO

# XtremIO Connection example
Disable-CertificateValidation
Set-XIOAPIConnectionInfo -username "admin" -passwordfile "C:\Users\dmuegge\Dropbox\DTools\Scripts\PS\!Passwords\RTTLab-admdmuegge-XtremIO.txt" -hostname "192.168.1.59"

# Get Tests
Get-XIOAPITypes
Get-XIOAPITypes | foreach-object {if($_.Name -ne $null){Get-XIOItem -UriString $_.Name}}

$Clusters = @('RTTXtremIO','RTTXtremIO')
Get-XIOCluster
Get-XIOCluster -Name $Clusters[0] | Select-Object name,sys-psnt-serial-number,sys-sw-version | FT
Get-XIOCluster -ID 1 | Select-Object name,sys-psnt-serial-number,sys-sw-version | FT
$Clusters[0] | Get-XIOCluster | Select-Object name,sys-psnt-serial-number,sys-sw-version | FT
$Clusters | Get-XIOCluster | Select-Object name,sys-psnt-serial-number,sys-sw-version | FT

$Bricks = @('X1','X1')
Get-XIOBrick
Get-XIOBrick -Name $Bricks[0]
Get-XIOBrick -ID 1
$Bricks | Get-XIOBrick

$XEnvs = @('X1-SC1-E1','X1-SC2-E1','X1-SC1-E2','X1-SC2-E2')
Get-XIOXenvs
Get-XIOXenvs -Name $XEnvs[0] | Select-Object Name,Index,xms-id | FT
Get-XIOXenvs -ID 1 | Select-Object Name,Index,xms-id | FT
Get-XIOXenvs | Select-Object Name,Index,xms-id | FT
 $XEnvs| Get-XIOXenvs | Select-Object Name,Index,xms-id | FT

$Volumes = @('DMSQLVol01','DMSQLVol02')
Get-XIOVolume | Select Name,lb-size,vol-size,logical-space-in-use | FT
Get-XIOVolume -Name $Volumes[0]
Get-XIOVolume -ID 1
$Volumes | Get-XIOVolume | Select Name,lb-size,vol-size,logical-space-in-use | FT

$VolumeFolders = @('/DMFolder01','/TN_HyperV_Test')
Get-XIOVolumeFolder
Get-XIOVolumeFolder | Select-Object Name,caption,num-of-vols,num-of-subfolders | FT
Get-XIOVolumeFolder -Name $VolumeFolders[0] | Select-Object Name,caption,num-of-vols,num-of-subfolders | FT
Get-XIOVolumeFolder -ID 1 | Select-Object Name,caption,num-of-vols,num-of-subfolders | FT
$VolumeFolders | Get-XIOVolumeFolder | Select-Object Name,caption,num-of-vols,num-of-subfolders | FT

$StorageControllers = @('X1-SC1','X1-SC2')
Get-XIOStorageController
Get-XIOStorageController -Name $StorageControllers[0] | Select-Object name,part-number,serial-number,os-version,node-health-state | FT
Get-XIOStorageController -ID 1 | Select-Object name,part-number,serial-number,os-version,node-health-state | FT
$StorageControllers | Get-XIOStorageController | Select name,part-number,serial-number,os-version,node-health-state | FT

$DataProtectionGroups = @('X1-DPG','X1-DPG')
Get-XIODataProtectionGroup
Get-XIODataProtectionGroup -Name $DataProtectionGroups[0] | Select-Object Name,protection-state | FT
Get-XIODataProtectionGroup -ID 1 | Select-Object Name,protection-state | FT
$DataProtectionGroups | Get-XIODataProtectionGroup | Select-Object Name,protection-state | FT

$Snapshots = @('towerdb1.snap.01202015-15:37','towerdb2.snap.01202015-15:37','towerdb4.snap.01202015-15:37')
Get-XIOSnapshot
Get-XIOSnapshot | Select-Object Name,@{Name="AncestorValumeName";Expression={$_."ancestor-vol-id"[1]}},creation-time,vol-size,logical-space-in-use | ft
Get-XIOSnapshot -Name $Snapshots[0] | Select-Object Name,@{Name="AncestorValumeName";Expression={$_."ancestor-vol-id"[1]}},creation-time,vol-size,logical-space-in-use | ft
Get-XIOSnapshot -ID 73 | Select-Object Name,@{Name="AncestorValumeName";Expression={$_."ancestor-vol-id"[1]}},creation-time,vol-size,logical-space-in-use | ft
$Snapshots | Get-XIOSnapshot | Select-Object Name,@{Name="AncestorValumeName";Expression={$_."ancestor-vol-id"[1]}},creation-time,vol-size,logical-space-in-use | ft

$Initiators = @('esxlab4b-hba1','esxlab4a-hba2','esxlab4c-hba1','esxlab4b-hba2')
Get-XIOInitiator
Get-XIOInitiator -Name $Initiators[0] | ft
Get-XIOInitiator -ID 1 | ft
Get-XIOInitiator | Select-Object Name,initiator-id,ig-id,port-type | ft
$Initiators | Get-XIOInitiator | Select-Object Name,initiator-id,ig-id,port-type | ft

$InitiatorGroups = @('esxlab4b','esxlab4a','esxlab4c')
Get-XIOInitiatorGroup
Get-XIOInitiatorGroup | Select-Object Name,index,ig-id
Get-XIOInitiatorGroup -Name $InitiatorGroups[0] | Select-Object Name,index,ig-id
Get-XIOInitiatorGroup -ID 1 | Select-Object Name,index,ig-id
$InitiatorGroups | Get-XIOInitiatorGroup | Select-Object Name,index,ig-id

$InitiatorGroupFolders = @('/lab-cluster','/extreme-performance-cluster')
Get-XIOInitiatorGroupFolder
Get-XIOInitiatorGroupFolder | Select-Object Name,caption,index,folder-id
Get-XIOInitiatorGroupFolder -Name $InitiatorGroupFolders[0] | Select-Object Name,caption,index,folder-id
Get-XIOInitiatorGroupFolder -ID 1 | Select-Object Name,caption,index,folder-id
$InitiatorGroupFolders | Get-XIOInitiatorGroupFolder | Select-Object Name,caption,index,folder-id

$Targets = @('X1-SC2-fc1','X1-SC2-fc2','X1-SC1-fc1')
Get-XIOTarget
Get-XIOTarget | Select-Object name,index,tar-id,tg-id
Get-XIOTarget -Name $Targets[0] | Select-Object name,index,tar-id,tg-id
Get-XIOTarget -ID 1 | Select-Object name,index,tar-id,tg-id
$Targets | Get-XIOTarget | Select-Object name,index,tar-id,tg-id

$TargetGroups = @('Default','Default')
Get-XIOTargetGroup
Get-XIOTargetGroup -Name $TargetGroups[0]
Get-XIOTargetGroup -ID 1
$TargetGroups | Get-XIOTargetGroup

$IscsiPortals = @('10.20.20.1/24','10.20.20.1/24')
Get-XIOIscsiPortal
Get-XIOIscsiPortal -Name $IscsiPortals[0]
Get-XIOIscsiPortal -ID 1
$IscsiPortals | Get-XIOIscsiPortal

$IscsiRoutes = @('RG1','RG1')
Get-XIOIscsiRoute
Get-XIOIscsiRoute -Name $IscsiRoutes[0]
Get-XIOIscsiRoute -ID 1
$IscsiRoutes | Get-XIOIscsiRoute

$LunMaps = @('2_2_1','105_2_1')
Get-XIOLunMap
Get-XIOLunMap -Name $LunMaps[0]
Get-XIOLunMap -ID 1
$LunMaps | Get-XIOLunMap

$SSDs = @('wwn-0x5000cca02b226ea0','wwn-0x5000cca02b224e5c')
Get-XIOSSD
Get-XIOSSD -Name $SSDs[0]
Get-XIOSSD -ID 1
$SSDs | Get-XIOSSD

Get-XIOEvent
Get-XIOEvent -ToDateTime ([System.convert]::ToDateTime('4/19/2015'))
Get-XIOEvent -FromDateTime ([System.convert]::ToDateTime('7/16/2015')) -ToDateTime ([System.convert]::ToDateTime('7/17/2015'))
# Apparent issues with this API object waiting on EMC feedback


# New/Set/Remove Tests
$Volumes = @()
$VolumeFolders = @()




<#



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



Get-XIOLunMap | Where vol-name -like "DMSQLVol01" | Foreach-object{Remove-XIOLunMap -Name $_.'mapping-id'[1]}
Get-XIOInitiatorGroup | Where Name -Like "xesx*" | Select name,index | foreach-object{New-XIOLunMap -Name "DMSQL01" -InitiatorGroup $_.index}




((Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/types/events/from-date-time="2015-07-01 05:00:00"?to-date-time="2015-07-10 05:00:00"' -Headers $Global:XIOAPIHeaders).events | Select timestamp,id,event_code | FT).Count
(Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/types/events/from-date-time="2015-07-01 05:00:00"?to-date-time="2015-07-10 05:00:00"' -Headers $Global:XIOAPIHeaders).events | Select timestamp,id,event_code | Select -First 1 -Last 1| FT

((Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/types/events/from-date-time="2015-07-01 05:00:00"?to-date-time="2015-08-10 05:00:00"' -Headers $Global:XIOAPIHeaders).events | Select timestamp,id,event_code | FT).Count
(Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/types/events/from-date-time="2015-07-01 05:00:00"?to-date-time="2015-08-10 05:00:00"' -Headers $Global:XIOAPIHeaders).events | Select timestamp,id,event_code | Select -First 1 -Last 1| FT

((Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/types/events/from-date-time="2015-07-01 05:00:00"?to-date-time="2015-08-31 05:00:00"' -Headers $Global:XIOAPIHeaders).events | Select timestamp,id,event_code | FT).Count
(Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/types/events/from-date-time="2015-07-01 05:00:00"?to-date-time="2015-08-31 05:00:00"' -Headers $Global:XIOAPIHeaders).events | Select timestamp,id,event_code | Select -First 1 -Last 1| FT



((Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/types/events' -Headers $Global:XIOAPIHeaders).events | Select timestamp,id,event_code | FT).Count
(Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/types/events' -Headers $Global:XIOAPIHeaders).events | Select timestamp,id,event_code | Select -First 1 -Last 1| FT



Get-XIOEvent -FromDateTime ([System.convert]::ToDateTime('7/16/2015')) -ToDateTime ([System.convert]::ToDateTime('7/17/2015'))
Get-XIOEvent -FromDateTime ([System.convert]::ToDateTime('8/20/2015'))
Get-XIOEvent -ToDateTime ([System.convert]::ToDateTime('7/19/2015'))

#>