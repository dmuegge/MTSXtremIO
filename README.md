MTSXtremIO
=============
EMC XtremIO PowerShell Module


Introduction
-------
This module provides a set of PowerShell advanced functions which access the features of the EMC XtremIO REST API

The module has full coverage over the 2.0 version of the XtremIO REST API(XtremIO 4.x)

The first four Cmdlets are to setup a connection to the XtremIO XMS, which is how you connect to the REST API. One XMS can manage multiple XtremIO clusters. 

- New-PasswordFile
- Get-PasswordFromFile
- Disable-CertificateValidation
- Set-XIOAPIConnectionInfo


There are 41 Cmdlets to retrieve information about XtremIO objects.
 
- Get-XIOPerformance
- Get-XIOAlert
- Get-XIOAlertDefinition
- Get-XIOAPITypes
- Get-XIOBBU
- Get-XIOBrick
- Get-XIOCluster
- Get-XIOConsistencyGroup
- Get-XIOConsistencyGroupVolume
- Get-XIODAE
- Get-XIODAEController
- Get-XIODAEPSU
- Get-XIODataProtectionGroup
- Get-XIOEmailNotifier
- Get-XIOEvent
- Get-XIOInfinibandSwitch
- Get-XIOInitiator
- Get-XIOInitiatorGroup
- Get-XIOIscsiPortal
- Get-XIOIscsiRoute
- Get-XIOItem
- Get-XIOLDAPConfiguration
- Get-XIOLocalDisk
- Get-XIOLunMap
- Get-XIOPerformance
- Get-XIOScheduler
- Get-XIOSlot
- Get-XIOSnapshot
- Get-XIOSnapshotSet
- Get-XIOSNMPNotifier
- Get-XIOSSD
- Get-XIOStorageController
- Get-XIOStorageControllerPSU
- Get-XIOSYRNotifier
- Get-XIOSyslogNotifier
- Get-XIOTag
- Get-XIOTarget
- Get-XIOTargetGroup
- Get-XIOUserAccount
- Get-XIOVolume
- Get-XIOXenvs
- Get-XIOXms
 
There are 11 Cmdlets for creating XtremIO objects.

- New-XIOConsistencyGroup
- New-XIOInitiator
- New-XIOInitiatorGroup
- New-XIOIscsiPortal
- New-XIOIscsiRoute
- New-XIOLunMap
- New-XIOScheduler
- New-XIOSnapshot
- New-XIOTag
- New-XIOUserAccount
- New-XIOVolume

There are 13 Cmdlets for removing XtremIO objects.

- Remove-XIOConsistencyGroup
- Remove-XIOConsistencyGroupVolume
- Remove-XIOInitiator
- Remove-XIOInitiatorGroup
- Remove-XIOIscsiPortal
- Remove-XIOIscsiRoute
- Remove-XIOLunMap
- Remove-XIOScheduler
- Remove-XIOSnapshot
- Remove-XIOSnapshotSet
- Remove-XIOTag
- Remove-XIOUserAccount
- Remove-XIOVolume

There are 16 Cmdlets for changing various XtremIO objects. 

- Add-XIOConsistencyGroupVolume
- Set-XIOAlertDefinition
- Set-XIOConsistencyGroup
- Set-XIOEmailNotifier
- Set-XIOInitiator
- Set-XIOInitiatorGroup
- Set-XIOLDAPConfiguration
- Set-XIOScheduler
- Set-XIOSnapshot
- Set-XIOSNMPNotifier
- Set-XIOSYRNotifier
- Set-XIOSyslogNotifier
- Set-XIOTag
- Set-XIOTarget
- Set-XIOVolume
- Update-XIOSnapshot


Requirements
-------
PowerShell Version 4

Should work under PowerShell 3.0 but has not been tested yet

Primary requirement is Invoke-RestMethod Cmdlet introduced in PowerShell 3.0


Version
-------
- 0.10.0 2015-01-31 - Initial Creation

- 0.11.0 2015-02-09 - Completed initial Get CmdLets

- 0.12.0 2015-02-20 - Added New, Update, and Remove CmdLets for common objects

- 0.13.0 2015-03-08 - Updated comments and published to GitHub

- 0.20.0 2015-08-30 - Changed Set-XIOAPIConnectionIno to hostname as parameter. This is a very minor breaking change needed so user no longer needs to know entire URI path. Misc parameter changes.

- 0.25.0 2015-09-01 - Added external help file. Additional improvements around parameters and pipeline support. Added Get-XIOEvent CmdLet. Changed Update/Rename CmdLets to Set and added Aliases. Added MTSXtremIO_SmokeTest_v1. Added MTSXtremIO_Example_Commands

- 0.30.0 2015-09-12 - Renamed MTSXtremIO_SmokeTest.ps1, Code optimizations with UriString, add tests, add help.

- 0.40.0 2015-09-29 - Added 4.0 cmdlets and updated help


Disclaimer/License
-----------
THE (MTSXtremIO PowerShell Module) IS PROVIDED WITHOUT WARRANTY OF ANY KIND.

See license.txt in the root of the GitHub project for licensing information