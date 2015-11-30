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


There are 42 Cmdlets to retrieve information about XtremIO objects.
 
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
- Get-XIOTagObject
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

There are 14 Cmdlets for removing XtremIO objects.

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
- Remove-XIOTagObject
- Remove-XIOUserAccount
- Remove-XIOVolume

There are 17 Cmdlets for changing various XtremIO objects. 

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
- Add-XIOTagObject
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

- 0.41.0 2015-10-17 - Added Tag Object Cmdlets, updated Get-XIOPerformance, pipeline improvements, started adding SupportsShouldProcess, and updated help

- 0.42.0 2015-11-22 - Add Multi-Cluster support to Get-XIOBrick, Get-XIOEnvs, Get-XIOStorageController, Get-XIOStorageControllerPSU, Get-XIODataProtectionGroup, Get-XIOTag, Get-XIOTagObject, Get-XIOVolume, Get-XIOSnapshotSet, Get-XIOScheduler, Get-XIOInitiator. Added ability to do adhoc authentication with Set-XIOAPIConnectionInfo. Corrected implementation of cmdlet aliases. Updated help.

- 0.43.0 2015-11-30 - Add Multi-Cluster support to remaining applicable Get functions and updated corresponding help documentation. Re-factored some code to reduce repetition. Added other help information. Added multi-cluster support and supports should process to all new,set,and remove cmdlets.   


Notes
------

All Cmdlets have help information, but additional details need to be added.

Pipeline functionality needs to be added or improved for some Cmdlets (Mostly New and Set). 

Functions and/or options to control snapshot backup functionality needs to be added (Maybe? This can be done easily).

Improvements to be made on error handling messages and information messages.

Authentication and certificates improvements - Client certificate authentication

Possibly adjust ID parameters to Index - Need to do more testing of piping gets to new,set, and remove commands

Plan is to move version number to 1.0.0 when above improvements have been completed and code tested as well as possible with limited testing resources.

Future plan to complete automated testing using Pester.

Would welcome any assistance testing and providing feedback on issues.


Disclaimer/License
-----------
THE (MTSXtremIO PowerShell Module) IS PROVIDED WITHOUT WARRANTY OF ANY KIND.

See license.txt in the root of the GitHub project for licensing information