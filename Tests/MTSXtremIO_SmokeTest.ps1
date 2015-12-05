<#

MTSXtremIO Smoke Test code

Used to test functionality of all XtremIO REST API objects via MTSXtremIO PowerShell module 


DO NOT RUN THIS SCRIPT ON PRODUCTION ARRAYS
DO NOT USE IF YOU DO NOT UNDERSTAND THIS CODE. IT WILL CREATE AND DELETE OBJECTS!!

Script has not yet beened designed to run and complete automated tests.
Is meant to be used for manual testing.


#>

Import-Module MTSXtremIO -Force 


#region Initial Connection
# XtremIO Connection example
Disable-CertificateValidation

# Set-XIOAPIConnectionInfo -Credential (Get-Credential) -hostname "192.168.1.59"

Set-XIOAPIConnectionInfo -username "admin" -passwordfile "C:\Users\dmuegge\Dropbox\DTools\Scripts\PS\!Passwords\RTTLab-admdmuegge-XtremIO.txt" -hostname "192.168.1.59"

#endregion


#region Get Types
Get-XIOAPITypes
Get-XIOAPITypes | foreach-object {if($_.Name -ne $null){Get-XIOItem -UriString $_.Name}}
#endregion


#region object performance

Get-XIOPerformance -Entity Volume -RecordLimit 10

Get-XIOPerformance -Entity Volume -FromTime '10/1/2015' -ToTime '10/2/2015' -ObjectList @('lab-datastore') -Granularity one_hour -Cluster RTTXtremIO | Select-Object timestamp,name,avg__iops,avg__avg_latency | FT -AutoSize

Get-XIOPerformance -Entity Volume -FromTime '10/1/2015' -ToTime '10/2/2015' -ObjectList @('lab-datastore') -Granularity one_hour -Cluster 1 | Select-Object timestamp,name,avg__iops,avg__avg_latency | FT -AutoSize

Get-XIOPerformance -Entity Target -FromTime '10/1/2015' -ToTime '10/2/2015' -Granularity one_hour | FT -AutoSize

#endregion


#region XMS (Get)
$Xmss = @('xms','xms')
Get-XIOXms
Get-XIOXms xms
Get-XIOXms -Name $Xmss[0] | Select-Object name,index,xms-id,version | FT
Get-XIOXms -ID 1 | Select-Object name,index,xms-id,version | FT
$Xmss[0] | Get-XIOXms | Select-Object name,index,xms-id,version | FT
$Xmss | Get-XIOXms | Select-Object name,index,xms-id,version | FT -AutoSize
#endregion


#region User Account (Get,New,Remove)
$Users = @('xms2','xms3')
New-XIOUserAccount -Name 'dmuegge01' -Role read_only -Password 'p@ssw0rd'
$Users | New-XIOUserAccount -Role read_only -Password 'p@ssw0rd'

Get-XIOUserAccount
Get-XIOUserAccount | Select-Object Name,Index,Role | FT -AutoSize
Get-XIOUserAccount -Name $Users[0] | Select-Object Name,Index,Role | FT -AutoSize
Get-XIOUserAccount -ID 4 | Select-Object Name,Index,Role | FT -AutoSize
$Users[0] | Get-XIOUserAccount | Select-Object Name,Index,Role | FT -AutoSize
$Users | Get-XIOUserAccount | Select-Object Name,Index,Role | FT -AutoSize

Remove-XIOUserAccount -Name 'DAM01'
$Users |  Remove-XIOUserAccount

#endregion


#region Cluster (Get)
$Clusters = @('RTTXtremIO','RTTXtremIO')
Get-XIOCluster
Get-XIOCluster -Name $Clusters[0] | Select-Object name,index,sys-psnt-serial-number,sys-sw-version | FT
Get-XIOCluster -ID 1 | Select-Object name,index,sys-psnt-serial-number,sys-sw-version | FT
$Clusters[0] | Get-XIOCluster | Select-Object name,sys-psnt-serial-number,sys-sw-version | FT
$Clusters | Get-XIOCluster | Select-Object name,sys-psnt-serial-number,sys-sw-version | FT -AutoSize
#endregion


#region X-Brick (Get)
$Bricks = @('X1','X1')
Get-XIOBrick
Get-XIOBrick -Name $Bricks[0]
Get-XIOBrick -ID 1
$Bricks | Get-XIOBrick

Get-XIOBrick -Name X1 -Cluster 1

Get-XIOBrick -ID 1 -Cluster 1

Get-XIOBrick -Name X1 -Cluster 'RTTXtremIO'

Get-XIOBrick -ID 1 -Cluster 'RTTXtremIO'

Get-XIOBrick -Cluster 'RTTXtremIO'

Get-XIOBrick -Cluster 1

#endregion


#region XEnv (Get)
$XEnvs = @('X1-SC1-E1','X1-SC2-E1','X1-SC1-E2','X1-SC2-E2')
Get-XIOXenvs
Get-XIOXenvs -Name $XEnvs[0] | Select-Object Name,Index,xms-id | FT
Get-XIOXenvs -ID 1 | Select-Object Name,Index,xms-id | FT
Get-XIOXenvs | Select-Object Name,Index,xms-id | FT
$XEnvs| Get-XIOXenvs | Select-Object Name,Index,xms-id | FT

Get-XIOXenvs -ID 1 -Cluster 1
Get-XIOXenvs -ID 1 -Cluster 'RTTXtremIO'

Get-XIOXenvs -Name 'X1-SC1-E1' -Cluster 1
Get-XIOXenvs -Name 'X1-SC1-E1' -Cluster 'RTTXtremIO'

Get-XIOXenv -Cluster 1
Get-XIOXenvs -Cluster 'RTTXtremIO'


#endregion


#region Storage Controller (Get)
$StorageControllers = @('X1-SC1','X1-SC2')
Get-XIOStorageController
Get-XIOStorageController -Name $StorageControllers[0] | Select-Object name,part-number,serial-number,os-version,node-health-state | FT
Get-XIOStorageController -ID 1 | Select-Object name,part-number,serial-number,os-version,node-health-state | FT
$StorageControllers | Get-XIOStorageController | Select-Object name,part-number,serial-number,os-version,node-health-state | FT


Get-XIOStorageController -Name 'X1-SC1' -Cluster 1

Get-XIOStorageController -Name 'X1-SC1' -Cluster 'RTTXtremIO'

Get-XIOStorageController -ID 1 -Cluster 1

Get-XIOStorageController -ID 1 -Cluster 'RTTXtremIO'

Get-XIOStorageController -Cluster 1

Get-XIOStorageController -Cluster 'RTTXtremIO'


#endregion


#region Storage Controller PSU (Get)
$StorageControllerPSUs = @('X1-SC1-PSU-L','X1-SC2-PSU-L')
Get-XIOStorageControllerPSU
Get-XIOStorageControllerPSU -Name $StorageControllers[0] | Select-Object name,index,part-number,serial-number | FT
Get-XIOStorageControllerPSU -ID 1 | Select-Object name,index,part-number,serial-number | FT
$StorageControllerPSUs | Get-XIOStorageControllerPSU | Select-Object name,index,part-number,serial-number | FT

Get-XIOStorageControllerPSU -Name 'X1-SC1-PSU-L' -Cluster 1

Get-XIOStorageControllerPSU -Name 'X1-SC1-PSU-L' -Cluster 'RTTXtremIO'

Get-XIOStorageControllerPSU -ID 1 -Cluster 1

Get-XIOStorageControllerPSU -ID 1 -Cluster 'RTTXtremIO'

Get-XIOStorageControllerPSU -Cluster 1

Get-XIOStorageControllerPSU -Cluster 'RTTXtremIO'

#endregion


#region Data Protection Groups (Get)
$DataProtectionGroups = @('X1-DPG','X1-DPG')
Get-XIODataProtectionGroup
Get-XIODataProtectionGroup -Name $DataProtectionGroups[0] | Select-Object Name,protection-state | FT
Get-XIODataProtectionGroup -ID 1 | Select-Object Name,protection-state | FT
$DataProtectionGroups | Get-XIODataProtectionGroup | Select-Object Name,protection-state | FT

Get-XIODataProtectionGroup -Name 'X1-DPG' -Cluster 1

Get-XIODataProtectionGroup -Name 'X1-DPG' -Cluster 'RTTXtremIO'

Get-XIODataProtectionGroup -ID 1 -Cluster 1

Get-XIODataProtectionGroup -ID 1 -Cluster 'RTTXtremIO'

Get-XIODataProtectionGroup -Cluster 1

Get-XIODataProtectionGroup -Cluster 'RTTXtremIO'

#endregion


#region Tags (Get,New,Set,Remove)
$Tags = @('/Volume/DAM01','/Volume/DAM02','/Volume/dmuegge03')
$TagCaptions = @('dmuegge01','dmuegge02','dmuegge03')
$NewNames = @('DAM01','DAM02','DAM03')


$TagCaptions | New-XIOTag -Type Volume
New-XIOTag -Type Volume -Name $TagCaptions[0] -ObjectName 'AtlasSQL'
Set-XIOTag -Name $Tags[1] -NewName $NewNames[1] -XmsID 1


Get-XIOTag
Get-XIOTag | Select-Object Name,index,caption,object-type,num-of-direct-objs | FT
Get-XIOTag -Name $Tags[0] | Select-Object Name,caption,object-type,num-of-direct-objs | FT
$Tags | Get-XIOTag | Select-Object Name,caption,object-type,num-of-direct-objs | FT

#$Tags | Set-XIOTag - TODO - Experiment more with pipeline options for Set

$Tags | Remove-XIOTag


Get-XIOTag -Name '/Volume/DMFolder01' -Cluster 1

Get-XIOTag -Name '/Volume/DMFolder01' -Cluster 'RTTXtremIO'



Get-XIOTag -Cluster 1

Get-XIOTag -Cluster 'RTTXtremIO'


#endregion


#region TagObjects (Get,Add,Remove)

Get-XIOTagObject -Name '/Volume/DMFolder01'


Get-XIOTagObject -Name '/Volume/DMFolder01' -Cluster 1

Get-XIOTagObject -Name '/Volume/DMFolder01' -Cluster 'RttXtremIO'



#endregion


#region Volume (Get,New,Set,Remove)
$Volumes = @('DAM03','DAM04')
$Volumes = @('DAM01','DAM02')
$Volumes = @('DAM01','DAM02','DAM03','DAM04')

$Volumes | New-XIOVolume -Size 10g

$Volumes | Get-Volume

Get-XIOVolume | foreach-object{ $_.Name }

(Get-XIOVolume -Name 'DAM01').GetType()


Get-XIOVolume -Name 'DAM01' | select name,small-io-alerts | Export-Csv Test.csv


$Volumes | Get-XIOVolume -Name 'DAM01' | Get-Member
Get-XIOVolume -Name 'DAM01' | Set-XIOVolume -SmallIOAlerts enable


$Volumes = @('DAM03','DAM04')
$Volumes | Get-XIOVolume | Set-XIOVolume -SmallIOAlerts disable

Set-XIOVolume -Name 'DAM04' -SmallIOAlerts enable 


 
$Volumes | Get-XIOVolume | Set-XIOVolume -SmallIOAlerts enable

$tnames = @(
'ParameterBinderBase',
'ParameterBinderController',
'ParameterBinding',
'TypeConversion'

)

trace-command -name ParameterBinding -expression{Get-XIOVolume -Name 'DAM01' | Select-Object name | Set-XIOVolume -SmallIOAlerts enable} -pshost -FilePath debug.txt

Get-XIOVolume -Name 'DAM01.snap.0001' | Write-Output

$Volumes | Get-XIOVolume | Select Name,Index | Remove-XIOVolume
$Volumes | ForEach-Object{Set-XIOVolume -Name $_ -SmallIOAlerts enable}


Get-XIOVolume -Name $Volumes[0] -Cluster 1
Get-XIOVolume | Select-Object Name,index,lb-size,vol-size,logical-space-in-use | Where Name -Like 'DAM*' | FT -AutoSize
Get-XIOVolume -ID 64 |  Select Name
$Volumes | Get-XIOVolume | Select-object Name,index,lb-size,vol-size,logical-space-in-use | FT -AutoSize


New-XIOVolume -Name 'DAM05' -Size 10g


$Volumes | Get-XIOVolume | Remove-XIOVolume
$Volumes | Remove-XIOVolume




Get-XIOVolume -Name 'DAM01' -Cluster 1

Get-XIOVolume -Name 'DAM01' -Cluster 'RTTXtremIO'

Get-XIOVolume -ID 64 -Cluster 1

Get-XIOVolume -ID 64 -Cluster 'RTTXtremIO'

Get-XIOVolume -Cluster 1

Get-XIOVolume -Cluster 'RTTXtremIO'



# TODO - Need work on parameters via pipeline from Get to set and remove
#endregion


#region Snapshot (Get,New,Set,Update,Remove)
$Snapshots = @('DAM01','DAM02','DAM03')
Get-XIOSnapshot
$Snapshots | Get-XIOSnapshot

Get-XIOSnapshot | Select-Object Name,@{Name="AncestorValumeName";Expression={$_."ancestor-vol-id"[1]}},creation-time,vol-size,logical-space-in-use | ft -AutoSize

Get-XIOSnapshot | Where Name -like 'DAM*' | Select-Object Name,@{Name="AncestorValumeName";Expression={$_."ancestor-vol-id"[1]}},creation-time,vol-size,logical-space-in-use | ft -AutoSize

Get-XIOSnapshot -Name $Snapshots[0] | Select-Object Name,@{Name="AncestorValumeName";Expression={$_."ancestor-vol-id"[1]}},creation-time,vol-size,logical-space-in-use | ft
Get-XIOSnapshot -ID 73 | Select-Object Name,@{Name="AncestorValumeName";Expression={$_."ancestor-vol-id"[1]}},creation-time,vol-size,logical-space-in-use | ft
$Snapshots | Get-XIOSnapshot | Select-Object Name,@{Name="AncestorValumeName";Expression={$_."ancestor-vol-id"[1]}},creation-time,vol-size,logical-space-in-use | ft
 

New-XIOSnapshot -VolList @('DAM01','DAM02') -SnapSuffix '.Snap.0003'
New-XIOSnapshot -VolList @('DAM03','DAM04') -SnapSuffix ('{0}{1}' -f '.Snap_',(Get-Date -Format yyyyMMdd-HHmmss)) -SnapSetName 'SQLDATA02'
New-XIOSnapshot -TagList @('/Volume/DAM01','/Volume/DAM02') -SnapSuffix '.Snap004'
New-XIOSnapshot -TagList @('/Volume/DAM01','/Volume/DAM02') -SnapSuffix ('{0}{1}' -f '.Snap_',(Get-Date -Format yyyyMMdd-HHmmss)) -SnapSetName 'DAM01_Set0010'


(Get-XIOConsistencyGroup -Name 'DAMTest01').index

New-XIOSnapshot -CGID ((Get-XIOConsistencyGroup -Name 'DAMTest01').index) -SnapSuffix 'CG_Test001'


Get-XIOSnapshot | Where Name -like 'DAM*' | Select Name,index | FT -AutoSize


Update-XIOSnapshot -SourceVol 'DAM01' -DestVol 'DAM01.snap.0001' -NoBackup
Update-XIOSnapshot -SourceSnapSet 'SQLDATA01' -DestSnapSet 'SQLDATA02'



Get-XIOConsistencyGroup


Update-XIOSnapshot -SourceCG 'DAMTest01'



Get-XIOSnapshot | Where Name -match 'DAM[0-9]{2}.Snap_.*' | Select-Object Name,@{Name="AncestorValumeName";Expression={$_."ancestor-vol-id"[1]}},creation-time,vol-size,logical-space-in-use | ft -AutoSize
Get-XIOSnapshot | Where Name -match 'DAM[0-9]{2}.Snap_.*' | Remove-XIOSnapshot
Remove-XIOSnapshot -Name 'DAM04.Snap_20150920-100827.snapshot.1442758483'



Get-XIOSnapshot -Name 'DAM01.snapshot.1443023909' -Cluster 1

Get-XIOSnapshot -Name 'DAM01.snapshot.1443023909' -Cluster 'RTTXtremIO'

Get-XIOSnapshot -ID 70 -Cluster 1

Get-XIOSnapshot -ID 70 -Cluster 'RTTXtremIO'

Get-XIOSnapshot -Cluster 1

Get-XIOSnapshot -Cluster 'RTTXtremIO'



#endregion


#region SnapshotSet (Get,Remove)

$SnapSets = @('DMTestSet','DMTestSet','DMTestSet')
Get-XIOSnapshotSet
Get-XIOSnapshotSet | Select-Object Name,index,tag-list,num-of-vols,vol-list | ft -AutoSize
Get-XIOSnapshotSet -Name $SnapSets[0] | Select-Object Name,index,tag-list,num-of-vols,vol-list | ft
Get-XIOSnapshotSet -ID 13 | Select-Object Name,index,tag-list,num-of-vols,vol-list | ft
$SnapSets | Get-XIOSnapshotSet | Select-Object Name,index,tag-list,num-of-vols,vol-list | ft


Remove-XIOSnapshotSet -Name 'SnapshotSet.1442758483'
Remove-XIOSnapshotSet -ID 7
Remove-XIOSnapshotSet -ID 7 -Cluster 1


Get-XIOSnapshotSet -Name 'SnapshotSet.1445975677' -Cluster 1

Get-XIOSnapshotSet -Name 'SnapshotSet.1445975677' -Cluster 'RTTXtremIO'

Get-XIOSnapshotSet -ID 1 -Cluster 1

Get-XIOSnapshotSet -ID 1 -Cluster 'RTTXtremIO'

Get-XIOSnapshotSet -Cluster 1

Get-XIOSnapshotSet -Cluster 'RTTXtremIO'


#endregion


#region Schedulers (Get,New,Set,Remove) TODO

# TODO - Test all scheduler functionality

$Schedulers = @('','')
Get-XIOScheduler
Get-XIOScheduler | Select-Object name,index,enabled-state,snapshot-type,last-activation-time | ft
Get-XIOScheduler -Name $Schedulers[0] | Select-Object name,index,enabled-state,snapshot-type,last-activation-time | ft
Get-XIOScheduler -ID 1 | Select-Object name,index,enabled-state,snapshot-type,last-activation-time | ft
$Schedulers | Get-XIOScheduler | Select-Object name,index,enabled-state,snapshot-type,last-activation-time | ft

New-XIOScheduler -ObjectType Volume -Time '12:00:00' -SchedulerType Explicit -ObjectID 66 -Suffix ('{0}{1}' -f '.SnapSchedule01_',(Get-Date -Format yyyyMMdd-HHmmss))

Set-XIOScheduler -Name DAMTest01 -ObjectID 66 -SchedulerType Explicit -ObjectType Volume -Time '11:00:00' -SnapType ReadOnly

Remove-XIOScheduler -Name DAMTest01 -Cluster 'RTTXtremIO'


# TODO - Test multiple cluster support
Get-XIOScheduler -Name 'SnapshotSet.1445975677' -Cluster 1

Get-XIOScheduler -Name 'SnapshotSet.1445975677' -Cluster 'RTTXtremIO'

Get-XIOScheduler -ID 1 -Cluster 1

Get-XIOScheduler -ID 1 -Cluster 'RTTXtremIO'

Get-XIOScheduler -Cluster 1

Get-XIOScheduler -Cluster 'RTTXtremIO'


#endregion


#region Initiators (Get,New,Set,Remove) TODO
$Initiators = @('esxlab4b-hba1','esxlab4a-hba2','esxlab4c-hba1','esxlab4b-hba2')
Get-XIOInitiator
Get-XIOInitiator -Name $Initiators[0] | ft
Get-XIOInitiator -ID 1 | ft
Get-XIOInitiator | Select-Object Name,initiator-id,ig-id,port-type | ft
$Initiators | Get-XIOInitiator | Select-Object Name,initiator-id,ig-id,port-type | ft

New-XIOInitiator -Name DAMTest01 -IgID 1 -PortAddress

Set-XIOInitiator -Name DAMTest01

Remove-XIOInitiator -Name DAMTest01

#endregion


#region Initiator Groups (Get,New,Set,Remove) TODO

$InitiatorGroups = @('esxlab4b','esxlab4a','esxlab4c')
Get-XIOInitiatorGroup
Get-XIOInitiatorGroup | Select-Object Name,index,ig-id
Get-XIOInitiatorGroup -Name $InitiatorGroups[0] | Select-Object Name,index,ig-id
Get-XIOInitiatorGroup -ID 1 | Select-Object Name,index,ig-id
$InitiatorGroups | Get-XIOInitiatorGroup | Select-Object Name,index,ig-id

New-XIOInitiatorGroup -Name 'DAMHostA' -InitiatorList 

Set-XIOInitiatorGroup -Name 'DAMHostA' -NewName 'DAMHostAA'

Remove-XIOInitiatorGroup -Name 'DAMHostAA'

#endregion


#region Consistency Groups (Get,New,Set,Remove)

$ConsistencyGroups = @('DAMTest01','DAMTest02')

Get-XIOConsistencyGroup
Get-XIOConsistencyGroup -Cluster 2
Get-XIOConsistencyGroup | Select-Object Name,index,tag-list,vol-list | FT -AutoSize
Get-XIOConsistencyGroup -Name $ConsistencyGroups[0] | Select-Object Name,index,tag-list,vol-list | FT
Get-XIOConsistencyGroup -ID 1 | Select-Object Name,index,tag-list,vol-list | FT
$ConsistencyGroups | Get-XIOConsistencyGroup | Select-Object Name,index,tag-list,vol-list | FT -AutoSize

 
New-XIOConsistencyGroup -Name 'DAMTest00' -VolList @('DAM03') -TagList @('/Volume/DAM04')
New-XIOConsistencyGroup -Name 'DAMTest00' -Cluster 'RTTXtremIO'
New-XIOConsistencyGroup -Name 'DAMTest00' -Cluster 1 # Does not work
New-XIOConsistencyGroup -Name 'DAMTest01'
New-XIOConsistencyGroup -Name 'DAMTest02'

Set-XIOConsistencyGroup -Name 'DAMTest00' -NewName 'DAMTest03'

Remove-XIOConsistencyGroup -Name 'DAMTest00'
Remove-XIOConsistencyGroup -Name 'DAMTest01'
Remove-XIOConsistencyGroup -Name 'DAMTest02'
Remove-XIOConsistencyGroup -Name 'DAMTest03'
$ConsistencyGroups | Remove-XIOConsistencyGroup



#endregion


#region Consistency Group Volumes (Get,Add,Remove)

$Volumes = @('DAM01','DAM02')
$Volumes = @('DAM03','DAM04')
$CGroups = @('DAMTest01','DAMTest02')

# Get Consistency Group Volumes
(Get-XIOConsistencyGroupVolume -Name 'DAMTest01')."vol-list"
(Get-XIOConsistencyGroupVolume -Name 'DAMTest02')."vol-list"
$CGroups | Get-XIOConsistencyGroupVolume


# Add volumes by name
$Volumes = @('DAM01','DAM02')
$Volumes | Add-XIOConsistencyGroupVolume -ConsistencyGroup 'DAMTest01'
$Volumes = @('DAM03','DAM04')
$Volumes | Add-XIOConsistencyGroupVolume -ConsistencyGroup 'DAMTest02'

Add-XIOConsistencyGroupVolume -Name 'DAM01' -ConsistencyGroup 'DAMTest01' -Cluster 'RTTXtremIO'
Add-XIOConsistencyGroupVolume -Name 'DAM02' -ConsistencyGroup 'DAMTest01' -Cluster 1
Add-XIOConsistencyGroupVolume -Name 'DAM01' -ConsistencyGroup 'DAMTest01'
Add-XIOConsistencyGroupVolume -Name 'DAM01' -ConsistencyGroup 'DAMTest01'
Add-XIOConsistencyGroupVolume -Name 'DAM02' -ConsistencyGroup 'DAMTest01'

Add-XIOConsistencyGroupVolume -Name 'DAM03' -ConsistencyGroup 'DAMTest02' -Cluster 1
Add-XIOConsistencyGroupVolume -Name 'DAM04' -ConsistencyGroup 'DAMTest02' -Cluster 'RTTXtremIO'




# Add volumes by ID
Add-XIOConsistencyGroupVolume -ID 64 -ConsistencyGroup 1


# Remove Volumes
Remove-XIOConsistencyGroupVolume -ConsistencyGroup 'DAMTest01' -Name 'DAM01'
Remove-XIOConsistencyGroupVolume -ConsistencyGroup 'DAMTest01' -Name 'DAM02'


# Clear Gonsistency Groups
$Volumes = @('DAM01','DAM02')
$Volumes | Remove-XIOConsistencyGroupVolume -ConsistencyGroup 'DAMTest01'
$Volumes = @('DAM03','DAM04')
$Volumes | Remove-XIOConsistencyGroupVolume -ConsistencyGroup 'DAMTest02'


#endregion


#region Targets (Get,Set) TODO

$Targets = @('X1-SC2-fc1','X1-SC2-fc2','X1-SC1-fc1')
Get-XIOTarget
Get-XIOTarget | Select-Object name,index,tar-id,tg-id
Get-XIOTarget -Name $Targets[0] | Select-Object name,index,tar-id,tg-id
Get-XIOTarget -ID 1 | Select-Object name,index,tar-id,tg-id
$Targets | Get-XIOTarget | Select-Object name,index,tar-id,tg-id

Set-XIOTarget -Name 'T1' -MTU ''

#endregion


#region Target Groups (Get)

$TargetGroups = @('Default','Default')
Get-XIOTargetGroup
Get-XIOTargetGroup -Name $TargetGroups[0]
Get-XIOTargetGroup -ID 1
$TargetGroups | Get-XIOTargetGroup

#endregion


#region iSCSI Portals (Get,New,Remove) TODO

$IscsiPortals = @('10.20.20.0/24','10.20.22.0/24')
Get-XIOIscsiPortal
Get-XIOIscsiPortal -Name $IscsiPortals[0]
Get-XIOIscsiPortal -ID 1
$IscsiPortals | Get-XIOIscsiPortal

New-XIOIscsiPortal -Name '10.20.20.0/24'
$IscsiPortals | New-XIOIscsiPortal


Remove-XIOIscsiPortal -Name '10.20.20.0/24'
$IscsiPortals | Remove-XIOIscsiPortal


Get-XIOIscsiPortal | Where Name -like "10.20*" | Remove-XIOIscsiPortal

#endregion


#region iSCSI Routes (Get,New,Remove) TODO

$IscsiRoutes = @('RG1','RG1')
Get-XIOIscsiRoute
Get-XIOIscsiRoute -Name $IscsiRoutes[0]
Get-XIOIscsiRoute -ID 1
$IscsiRoutes | Get-XIOIscsiRoute

New-XIOIscsiRoute -Name 'RG1' -DestNetwok '10.20.20.0/24' -Gateway '10.20.20.1'

Remove-XIOIscsiRoute -Name 'RG1'

#endregion


#region LUN Maps (Get,New,Remove) TODO

$LunMaps = @('2_2_1','105_2_1')
Get-XIOLunMap
Get-XIOLunMap -Name $LunMaps[0]
Get-XIOLunMap -ID 1
$LunMaps | Get-XIOLunMap

Get-XIOInitiatorGroup | Where Name -Like "xesx*" | Select name,index | foreach-object{New-XIOLunMap -Name "DMVol01" -InitiatorGroup $_.index}

Get-XIOLunMap | Where vol-name -like "DMSQLVol01" | Foreach-object{Remove-XIOLunMap -Name $_.'mapping-id'[1]}

#endregion


#region LDAP Configuration (Get,Set) TODO

$LDAPConfigs = @('DMLDAP01','DMLDAP02')
Get-XIOLDAPConfiguration -Name 'DMLDAP01'
Get-XIOLDAPConfiguration -ID 1
$LDAPConfigs | Get-XIOLDAPConfiguration

Set-XIOLDAPConfiguration -Name 'DMLDAP01'




#endregion


#region Alerts (Get) TODO

$Alerts = @('DAMAlert01','DAMAlert02')

Get-XIOAlert
Get-XIOAlert -Name ''
Get-XIOAlert -ID 1

$Alerts | Get-XIOAlert


#endregion


#region Local Disks (Get) TODO

$LocalDisks = @('Disk01','Disk02')
Get-XIOLocalDisk



#endregion


#region BBUs (Get) TODO

Get-XIOBBU

#endregion


#region DAEs (Get) TODO

Get-XIODAE

#endregion


#region DAE PSUs (Get) TODO

Get-XIODAEPSU

#endregion


#region Infifniband Switches (Get) TODO

Get-XIOInfinibandSwitch

#endregion


#region DAE Controllers (Get) TODO

Get-XIODAEController

#endregion


#region Alert Definition (Get,Set) TODO

Get-XIOAlertDefinition


Set-XIOAlertDefinition -Name


#endregion


#region Email Notifiers (Get,Set) TODO

$EmailNotifier = @('DMEnotify01','DMEnotify02')
Get-XIOEmailNotifier -Name 'DMEnotify01'
Get-XIOEmailNotifier -ID 1

$EmailNotifier | Get-XIOEmailNotifier

Set-XIOEmailNotifier -Name $EmailNotifier[0] -State enable -sender 'test@test.com'


#endregion


#region SNMP Notifiers (Get,Set) TODO


$SNMPNotifier = @('DMSNMPnotify01','DMSNMPnotify02')
Get-XIOSNMPNotifier -Name 'DMSNMPnotify01'
Get-XIOSNMPNotifier -ID 1

$SNMPNotifier | Get-XIOSNMPNotifier

Set-XIOSNMPNotifier -Name 'DMSNMPNotify01' -State enable -Community 'Public'



#endregion


#region SYR Notifiers (Get,Set) TODO

$SYRNotifier = @('DMSYRnotify01','DMSYRnotify02')
Get-XIOSYRNotifier -Name 'DMSYRnotify01'
Get-XIOSYRNotifier -ID 1

$SYRNotifier | Get-XIOSYRNotifier

Set-XIOSYRNotifier -Name 'DMSYRnotify01' -State enable



#endregion


#region SysLog Notifiers (Get,Set) TODO

$SyslogNotifier = @('DMLognotify01','DMLognotify02')
Get-XIOSyslogNotifier -Name 'DMLognotify01'
Get-XIOSyslogNotifier -ID 1

$SyslogNotifier | Get-XIOSyslogNotifier

Set-XIOSyslogNotifier -Name 'DMLognotify01' -State enable

#endregion


#region SSDs (Get)

$SSDs = @('wwn-0x5000cca02b226ea0','wwn-0x5000cca02b224e5c')
Get-XIOSSD
Get-XIOSSD -Name $SSDs[0]
Get-XIOSSD -ID 1
$SSDs | Get-XIOSSD

#endregion


#region Slot (Get)

Get-XIOSlot

#endregion


#region Event (Get)
$Events = Get-XIOEvent
$Events | Select timestamp,id,event_code -First 1 | FT
$Events | Select timestamp,id,event_code -Last 1 | FT
$Events.count

$Events = Get-XIOEvent -FromDateTime ([System.convert]::ToDateTime('12/01/2015'))
$Events | Select timestamp,id,event_code -First 1 | FT
$Events | Select timestamp,id,event_code -Last 1 | FT
$Events.count

$Events = Get-XIOEvent -ToDateTime ([System.convert]::ToDateTime('12/03/2015'))
$Events | Select timestamp,id,event_code -First 1 | FT
$Events | Select timestamp,id,event_code -Last 1 | FT
$Events.count


$Events = Get-XIOEvent -FromDateTime ([System.convert]::ToDateTime('11/15/2015')) -ToDateTime ([System.convert]::ToDateTime('11/17/2015'))
$Events | Select timestamp,id,event_code -First 1 | FT
$Events | Select timestamp,id,event_code -Last 1 | FT
$Events.count

# Apparent issues with this API object waiting on EMC feedback
[System.Web.HttpUtility]::UrlEncode(([System.convert]::ToDateTime('4/19/2015')))

Get-XIOEvent -FromDateTime ([System.convert]::ToDateTime('7/16/2015')) -ToDateTime ([System.convert]::ToDateTime('7/17/2015'))
Get-XIOEvent -FromDateTime ([System.convert]::ToDateTime('8/20/2015'))
Get-XIOEvent -ToDateTime ([System.convert]::ToDateTime('7/19/2015'))


https://192.168.1.59/api/json/v2/types/events/from-date-time=2015-10-01%2000:00:00?to-date-time=2015-11-17%2000:00:00

((Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/types/events/from-date-time="2015-07-01 05:00:00"?to-date-time="2015-08-31 05:00:00"' -Headers $Global:XIOAPIHeaders).events | Select timestamp,id,event_code | FT).Count
((Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/types/events?from-date-time="2015-07-01 05:00:00"&to-date-time="2015-08-31 05:00:00"' -Headers $Global:XIOAPIHeaders).events | Select timestamp,id,event_code | FT).Count
((Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/types/events?from-date-time=2015-07-01%2005:00:00' -Headers $Global:XIOAPIHeaders).events | Select timestamp,id,event_code | FT).Count


<#
((Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/types/events/from-date-time="2015-07-01 05:00:00"?to-date-time="2015-08-31 05:00:00"' -Headers $Global:XIOAPIHeaders).events | Select timestamp,id,event_code | FT).Count
(Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/types/events/from-date-time="2015-07-01 05:00:00"?to-date-time="2015-08-31 05:00:00"' -Headers $Global:XIOAPIHeaders).events | Select timestamp,id,event_code | Select -First 1 -Last 1| FT

((Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/types/events' -Headers $Global:XIOAPIHeaders).events | Select timestamp,id,event_code | FT).Count
(Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/types/events' -Headers $Global:XIOAPIHeaders).events | Select timestamp,id,event_code | Select -First 1 -Last 1| FT

#>

#endregion





# AdHoc RAW Commands
Get-XIOAPITypes
$UriObject = 'performance'

(Get-XIOItem -UriString $UriObject).$UriObject

$UriString += ($UriObject + '/?name=' + $Name)
$UriString = ($UriObject + '/' + $ID)

$UriString = [String]::Empty
$UriString += ($UriObject + '/?entity=target')

Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders

Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/v2/types/performance?entity=Volume&limit=100&obj-list=DAM01&obj-list=DAM02&from-time=2015-10-01%2012:00:00&to-time=2015-10-02%2012:00:00' -Headers $Global:XIOAPIHeaders

Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/v2/types/volumes/64?cluster-id=1' -Headers $Global:XIOAPIHeaders

Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/v2/types/volumes/64?cluster-name=RTTXtremIO' -Headers $Global:XIOAPIHeaders




Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/v2/types/performance?entity=Target&limit=10&from-time=2015-10-01%2012:00:00&to-time=2015-10-02%2012:00:00&prop=avg__iops&cluster-name=RTTXtremIO' -Headers $Global:XIOAPIHeaders

Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/v2/types/performance?entity=ConsistencyGroup&limit=10&from-time=2015-10-01%2012:00:00&to-time=2015-10-02%2012:00:00' -Headers $Global:XIOAPIHeaders


$JSoNBody = New-Object -TypeName psobject
$JSoNBody | Add-Member -MemberType NoteProperty -Name vol-id -Value $Name
$JSoNBody | Add-Member -MemberType NoteProperty -Name cg-id -Value $ConsistencyGroup
Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)


($JSoNBody | ConvertTo-Json)
Invoke-RestMethod -Method Get -Uri 'https://192.168.1.59/api/json/v2/types/' -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)



#>