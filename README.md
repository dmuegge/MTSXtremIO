MTSXtremIO
=============
EMC XtremIO PowerShell Module

Introduction
-------
This module provides PowerShell access to the EMC XtremIO REST API

The module has full read coverage over the 1.0 version of the XtremIO REST API(XtremIO 3.x)
There is create, update and delete functionality for the most common objects listed below:
Volume Folders
Volumes
Snapshots
Lunmaps

Currently working on additional functionality to provide full API coverage

Requirements
-------
PowerShell Version 4
Should work under PowerShell 3.0 but has not been tested yet
Primary requirement is Invoke-RestMethod Cmdlet introduced in PowerShell 3.0

Version
-------
0.10.0 2015-01-31 - Initial Creation
0.11.0 2015-02-09 - Completed initial Get CmdLets
0.12.0 2015-02-20 - Added New, Update, and Remove CmdLets for common objects
0.13.0 2015-03-08 - Updated comments and published to GitHub
0.20.0 2015-08-30 - Changed Set-XIOAPIConnectionIno to hostname as parameter
                    This is a very minor breaking change - needed so user no
                    longer needs to understand entire URI path
                    misc parameter changes
0.25.0 2015-09-01 - Added external help file
                    Additional improvements around parameters and pipeline support
                    Added Get-XIOEvent CmdLet
                    Changed Update/Rename CmdLets to Set and added Aliases
					Added MTSXtremIO_SmokeTest_v1
					Added MTSXtremIO_Example_Commands


Disclaimer/License
-----------

THE (MTSXtremIO PowerShell Module) IS PROVIDED WITHOUT WARRANTY OF ANY KIND.

See license.txt in the root of the GitHub project for licensing information