# Load MTSXremIO Module
Import-Module MTSXtremIO -Force
Import-Module MTSGeneral -Force
Import-Module MTSChart -Force
Import-Module MTSMSExcel -Force

# XtremIO Connection Setup
Disable-CertificateValidation
Set-XIOAPIConnectionInfo -username "admin" -passwordfile "C:\Users\dmuegge\Dropbox\DTools\Scripts\PS\!Passwords\RTTLab-admdmuegge-XtremIO.txt" -hostname "192.168.1.59"


Get-Command -Module MTSXtremIO

Get-XIOAPITypes

Get-Help Get-XIOVolume -full


#region Provisioning


### Volumes
# Create Volumes
$VolInfo = Import-csv -Path C:\Users\dmuegge\Dropbox\DTools\Scripts\PS\XtremIO\CPUG\Volumes.csv
$VolInfo | ForEach-Object {New-XIOVolume -Name $_.Name -Size $_.Size }

New-XIOVolume -Name 'DMCPUGWeb05' -Size 10g


# Get Volumes
Get-XIOVolume | Select Name,index,vol-size,vaai-tp-alerts,small-io-alerts,unaligned-io-alerts,tag-list | Sort-Object Name | FT -AutoSize
Get-XIOVolume | Where Name -like "DMCPUG*" | Select Name,vol-size,vaai-tp-alerts,small-io-alerts,unaligned-io-alerts,tag-list | Sort-Object Name | FT -AutoSize


# Set Volumes
Get-XIOVolume | Where-Object Name -like "DMCPUGSQLData*" | Set-XIOVolume -Property Size -Value 20g
Get-XIOVolume | Where-Object Name -like "DMCPUG*" | Set-XIOVolume -Property VaaiTpAlerts -Value enabled



### Tags
# New Tags
New-XIOTag -Name 'DMCPUG' -Type Volume


# Get Tags
Get-XIOTag | Select Name | FT -AutoSize
Get-XIOTag | Select Name | Get-XIOTagObject | Group-Object TagName -NoElement
Get-XIOTag | Where-Object Name -like '*DMCPUG*' | ForEach-Object{$_.Name; $_.'direct-list' | Sort-Object | ForEach-Object{$_[1]}; }


# Get Tag Objects
Get-XIOTagObject -Name '/Volume/DMCPUG' | Sort-Object TagObject


# Add Tag Objects
Get-XIOVolume | Where Name -like "DMCPUG*" | Add-XIOTagObject -TagName '/Volume/DMCPUG' -Type Volume



### LUN Maps
# Get LUN Maps
Get-XIOLunMap | Select-Object vol-name,ig-name | Sort-Object vol-name,ig-name | FT -AutoSize
Get-XIOLunMap | Where-Object vol-name -like 'DMCPUG*' | Select-Object vol-name,ig-name | Sort-Object vol-name,ig-name | FT -AutoSize

Get-XIOLunMap | Where-Object vol-name -like 'DMCPUG*' | Group-Object vol-name | Sort-object vol-name | ForEach-Object {$_.Name; $_.Group.'ig-name' | Sort-object; ' '}


# Map LUNS
Get-XIOInitiatorGroup | Where Name -Like "xesx*" | Select name,index | foreach-object{New-XIOLunMap -Name 'DMCPUGWeb05' -InitiatorGroup $_.index}

Get-XIOInitiatorGroup | Where Name -Like "xesx*" | Select name,index | foreach-object{ $ig = $_; Get-XIOVolume | Where-Object Name -Like 'DMCPUG*' | Foreach-Object {New-XIOLunMap -Name $_.Name -InitiatorGroup $ig.index}}


#endregion


#region Reporting

# Inventory/Configuration Reporting
Get-XIOCluster | Select name,sys-psnt-serial-number,license-id,sys-sw-version,size-and-capacity,sys-health-state,data-reduction-ratio-text,compression-factor-text,dedup-ratio-text | ft -AutoSize
Get-XIOCluster | Select name,num-of-bricks,num-of-ib-switches,num-of-ssds,num-of-vols,fc-port-speed,iscsi-port-speed,useful-ssd-space-per-ssd,ud-ssd-space,ud-ssd-space-in-use | ft -AutoSize
Get-XIOStorageController | Select name,part-number,serial-number,os-version,node-health-state | ft -AutoSize
Get-XIOXenvs | Select-Object name,index,xenv-state,cpu-usage | ft -AutoSize
Get-XIOInitiator | Select-object Name,index,port-address,initiator-conn-state | ft -AutoSize
Get-XIOVolume | where {$_.'ancestor-vol-id'[0] -eq $null} | Select Name,lb-size,vol-size,logical-space-in-use | Sort-Object Name | ft -AutoSize
Get-XIOSnapshot | Select Name,@{Name="AncestorVolumeName";Expression={$_."ancestor-vol-id"[1]}},creation-time,vol-size,logical-space-in-use | Sort-Object Name | ft -AutoSize



# XtremIO SPCollect
$ExcelApp = New-ExcelApplication -Visible
$ExcelWorkbook = New-ExcelWorkbook -ExcelApplication $ExcelApp
# High-Level cluster information
$ExcelSheet = Get-XIOCluster | Select name,sys-psnt-serial-number,license-id,sys-sw-version,size-and-capacity,sys-health-state,data-reduction-ratio-text,compression-factor-text,dedup-ratio-text | Write-PSObjectToSheet -ExcelWorkbook $ExcelWorkbook -WorksheetName "Cluster_Summary"
Write-SheetFormatting -Worksheet $ExcelSheet -ExcelWorkbook $ExcelWorkbook -FreezeTopPane -AutoFitCol
# Detail cluster information
$ExcelSheet = Get-XIOCluster | Select name,num-of-bricks,num-of-ib-switches,num-of-ssds,num-of-vols,fc-port-speed,iscsi-port-speed,@{Name="Usable GB/SSD";Expression={$_."useful-ssd-space-per-ssd" / 1024 /1024}},@{Name="Total Usable GB";Expression={$_."ud-ssd-space" / 1024 /1024}},@{Name="Total GB in Use";Expression={$_."ud-ssd-space-in-use" / 1024 /1024}} | Write-PSObjectToSheet -ExcelWorkbook $ExcelWorkbook -WorksheetName "Cluster_Detail"
Write-SheetFormatting -Worksheet $ExcelSheet -ExcelWorkbook $ExcelWorkbook -FreezeTopPane -AutoFitCol
# Controller information
$AllSPInfo = @()
Get-XIOStorageController | Select name,part-number,serial-number,os-version,node-health-state | ForEach-Object{$AllSPInfo += $_}
$ExcelSheet = Write-PSObjectToSheet -InputObject $AllSPInfo -ExcelWorkbook $ExcelWorkbook -WorksheetName "Controller_Detail"
Write-SheetFormatting -Worksheet $ExcelSheet -ExcelWorkbook $ExcelWorkbook -FreezeTopPane -AutoFitCol
# XEnvs information
$AllXenvInfo = @()
Get-XIOXenvs | Select-Object name,index,xenv-state,cpu-usage | ForEach-Object{$AllXenvInfo += $_}
$ExcelSheet = Write-PSObjectToSheet -InputObject $AllXenvInfo -ExcelWorkbook $ExcelWorkbook -WorksheetName "XEnv_Detail"
Write-SheetFormatting -Worksheet $ExcelSheet -ExcelWorkbook $ExcelWorkbook -FreezeTopPane -AutoFitCol
# Initiator information
$AllInitInfo = @()
Get-XIOInitiator | Select-object Name,index,port-address,initiator-conn-state | ForEach-Object{$AllInitInfo += $_}
$ExcelSheet = Write-PSObjectToSheet -InputObject $AllInitInfo -ExcelWorkbook $ExcelWorkbook -WorksheetName "Initiator_Detail"
Write-SheetFormatting -Worksheet $ExcelSheet -ExcelWorkbook $ExcelWorkbook -FreezeTopPane -AutoFitCol
# Volume information
$AllVolInfo = @()
Get-XIOVolume | where {$_.'ancestor-vol-id'[0] -eq $null} | Select Name,lb-size,@{Name="Provisioned GB";Expression={$_."vol-size" / 1024 /1024}},@{Name="Logical GB";Expression={$_."logical-space-in-use" / 1024 /1024}} | Sort-Object Name | ForEach-Object{$AllVolInfo += $_}
$ExcelSheet = Write-PSObjectToSheet -InputObject $AllVolInfo -ExcelWorkbook $ExcelWorkbook -WorksheetName "Volume_Detail"
Write-SheetFormatting -Worksheet $ExcelSheet -ExcelWorkbook $ExcelWorkbook -FreezeTopPane -AutoFitCol -AutoFilter
# Snapshot information
$AllSnapInfo = @()
Get-XIOSnapshot | Select Name,@{Name="AncestorValumeName";Expression={$_."ancestor-vol-id"[1]}},creation-time,@{Name="Provisioned GB";Expression={$_."vol-size" / 1024 /1024}},@{Name="Logical GB";Expression={$_."logical-space-in-use" / 1024 /1024}} | Sort-Object Name | ForEach-Object{$AllSnapInfo += $_}
$ExcelSheet = Write-PSObjectToSheet -InputObject $AllSnapInfo -ExcelWorkbook $ExcelWorkbook -WorksheetName "Snapshot_Detail"
Write-SheetFormatting -Worksheet $ExcelSheet -ExcelWorkbook $ExcelWorkbook -FreezeTopPane -AutoFitCol -AutoFilter




# Performance Reporting

[Datetime]$FromTime = [DateTime]::Parse('10/1/2015 00:00:00').ToUniversalTime()
[Datetime]$ToTime = [DateTime]::Parse('10/2/2015 00:00:00').ToUniversalTime()


Get-XIOPerformance -Entity Cluster -FromTime $FromTime -ToTime $ToTime -Granularity one_hour | Select * | FT -AutoSize

Get-XIOPerformance -Entity Volume -FromTime '10/1/2015 4:00:00' -ToTime '10/2/2015 4:00:00' -ObjectList @('lab-datastore') -Granularity one_hour | Select-Object timestamp,name,avg__iops,avg__avg_latency | FT -AutoSize

Get-XIOPerformance -Entity Volume -FromTime (((Get-Date).AddDays(-1)).ToUniversalTime()) -ToTime ((Get-Date).ToUniversalTime()) -ObjectList @('lab-datastore') | Select-Object timestamp,name,avg__iops,avg__avg_latency | FT -AutoSize

out-mtschart -InputObject (Get-XIOPerformance -Entity Volume -FromTime '10/1/2015 4:00:00' -ToTime '10/5/2015 4:00:00' -Granularity one_hour `
             -ObjectList @('lab-datastore')) `
             -XValue 'timestamp' `
             -XInterval 20 `
             -Width 800 -Height 600 `
             -ChartTitle 'Volume - lab-datastore' `
             -ChartType Line `
             -ChartFullPath 'C:\Users\dmuegge\Dropbox\DTools\Scripts\PS\XtremIO\CPUG\test.png' `
             -YValues 'avg__iops,avg__rd_iops,avg__wr_iops' `
             -LegendOn | Out-Null
iex 'C:\Users\dmuegge\Dropbox\DTools\Scripts\PS\XtremIO\CPUG\test.png'

#endregion


#region Snapshot Management
Get-XIOVolume | Where Name -Like 'DAM02*' | Select-Object Name

# Create Snapshots
New-XIOSnapshot -VolList @('DAM02') -SnapSuffix ("_" + (Get-Date -Format yyyyMMdd-HHmmssfff))

Write-Host (Get-Date)
for ($i = 0; $i -lt 20; $i++)
{ 
    New-XIOSnapshot -VolList @('DAM02') -SnapSuffix ("_" + (Get-Date -Format yyyyMMdd-HHmmssfff))
    Start-Sleep -Milliseconds 900
}
Write-Host (Get-Date)
Get-XIOSnapshot | Where-Object Name -like "DAM02*" | Select Name,@{Name="AncestorVolumeName";Expression={$_."ancestor-vol-id"[1]}},creation-time,vol-size,logical-space-in-use | Sort-Object Name | ft -AutoSize
(Get-XIOSnapshot | Where-Object Name -like "DAM02*").Count


# Delete Snapshots
Get-XIOSnapshot | Select Name | Where Name -like "DAM02*" | ForEach-Object {Remove-XIOSnapshot -VolName $_.Name}




# SQL Snapshot refresh
Get-XIOVolume | Where Name -Like 'DMSQLVol01*' | Select-Object Name

# Initial Snapshot Setup and LUN Mapping
$SourceVolume = 'DMSQLVol01'
$SourceDatabase = 'SnapTest01'
$TargetDatabaseName = 'SnapTest01_QA'
$TargetDeviceName = 'DMSQLVol01.Snap_20150923-102044'
$TargetSnapDeviceID = '514f0c53d2600159'
$VMName = 'DAMAnalysis'
$DriveLetter = 'K'
$datapath = 'K:\SnapTest01.mdf'
$logpath = 'K:\SnapTest01_log.ldf'


# Detach Database
$Result = Set-DBDetach -SQLServer $VMName -dbname $TargetDatabaseName

# Check if database detach successful
if($Result){

    # Get Disk Number
    $OldDisk = Get-Disk | Where UniqueId -eq $TargetSnapDeviceID

    # Offline Disk
    Set-Disk -Number ($OldDisk.Number) -IsOffline $true

    # Refresh SnapShot
    Update-XIOSnapshot -SourceVol $SourceVolume -DestVol $TargetDeviceName

    # Rescan Windows Disks
    Update-HostStorageCache

}

# Get Disk Number
$NewDisk = Get-Disk | Where UniqueId -eq $TargetSnapDeviceID

# Set mount and drive path 
Set-Disk -Number ($NewDisk.Number) -IsReadOnly $false
Set-Disk -Number ($NewDisk.Number) -IsOffline $false


Start-Sleep -Seconds 1
$CurrentDriveLetter = (get-partition -DiskNumber ($NewDisk.Number)).DriveLetter
if( -not ($CurrentDriveLetter -eq $DriveLetter)){

    Remove-PartitionAccessPath -DiskNumber ($NewDisk.Number) -PartitionNumber 1 -AccessPath ($CurrentDriveLetter + ':\')
    Add-PartitionAccessPath -DiskNumber ($NewDisk.Number) -PartitionNumber 1 -AccessPath ($DriveLetter + ':\')
}


# Verify Files and attach database
if ((Test-Path -Path $datapath) -and (Test-path -Path $logpath)){
 
	# Attach Database
	$DBAttachResult = Set-DBAttach -dbname $TargetDatabaseName -datapath $datapath -logpath $logpath
 
}


# Remove all but last two snapshot versions
$SnapCount = (Get-XIOVolume | Where-Object Name -like "DMSQLVol01.snapshot*").Count
Get-XIOVolume | Where-Object Name -like "DMSQLVol01.snapshot*" | Sort-Object Name | Select-Object -First ($SnapCount - 2) | Remove-XIOVolume
Get-XIOVolume | Where-Object Name -like "DMSQLVol01.snapshot*" | Sort-Object Name | Select-Object Name,Index | FT -AutoSize



#endregion



#region clean up

# Remove LUN Mappings
Get-XIOLunMap | Where vol-name -like "DMCPUG*" | Foreach-object{Remove-XIOLunMap -Name $_.'mapping-id'[1]}

# Remove Tag Objects
Get-XIOVolume | Where Name -like "DMCPUG*" | Remove-XIOTagObject -TagName '/Volume/DMCPUG' -Type Volume

# Remove Tag
Remove-XIOTag -Name '/Volume/DMCPUG'

# Remove Volumes
Get-XIOVolume | Where-Object Name -like "DMCPUG*" | Remove-XIOVolume

#endregion