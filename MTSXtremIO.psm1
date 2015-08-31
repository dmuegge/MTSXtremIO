<# Module Name:     MTSXtremIO.psm1
## 
## Author:          David Muegge
## Purpose:         Provides PowerShell access to the EMC XtremIO REST API
##																					
## Requirements:    PowerShell Version 4
## 					
##					
## History:         0.10.0 2015-01-31 - Initial Creation
##                  0.11.0 2015-02-09 - Completed initial Get CmdLets
##                  0.12.0 2015-02-20 - Added New, Update, and Remove CmdLets for common objects
##                  0.13.0 2015-03-08 - Updated comments and published to GitHub
##                  0.20.0 2015-08-30 - Changed Set-XIOAPIConnectionIno to hostname as parameter
##                                      This is a very minor breaking change - needed so user no
##                                      longer needs to understand entire URI path
##                                      misc parameter changes
##
## Notes:
##                  This module hase full read coverage over the 3.0 version of the XtremIO REST API
##                  There is create, update and delete functionality for the most common objects 
##                  listed below:
##                      Volume Folders
##                      Volumes
##                      Snapshots
##                      Lunmaps
##
##                                  
##                                                                             
####################################################################################################
## Disclaimer
## ****************************************************************
## * THE (MTSXtremIO PowerShell Module)                           *
## * IS PROVIDED WITHOUT WARRANTY OF ANY KIND.                    *
## *                                                              *
## * This module is licensed under the terms of the MIT license.  *
## * See license.txt in the root of the github project            *
## *                                                              *
## **************************************************************** 
###################################################################################################>


# Base, helper and connection functions
function New-PasswordFile{
<#
.SYNOPSIS
    Creates enrypted password file

.DESCRIPTION
    Will prompt for password and write encrypted password to file
    Encryption key is generated based on current windows user security token

.PARAMETER Path
    Path to location of encrypted password file

.PARAMETER Filename
    Filename of enrypted password file

.INPUTS
    Filename and path
    Will prompt for password to be encrypted

.OUTPUTS
    Encrypted password file

.EXAMPLE
    New-PasswordFile -Path "C:\Temp\Passwords" -Filename "lab-PWD.txt"

.NOTES
    This cmdlet is used allow the use of basic authentication and persist password info

#>
	[CmdletBinding()]
	param ( 
		[Parameter(Mandatory=$True)][Alias('p')][string]$Path,
		[Parameter(Mandatory=$True)][Alias('f')][string]$Filename
	)
        
    If(Test-Path -Path $Path){
	    $passwd = Read-Host -prompt 'Password' -assecurestring
        $FullFilePath = $Path + '\' + $Filename
        New-Item -Path $FullFilePath -ItemType File
	    ConvertFrom-SecureString -securestring $passwd | Out-File -FilePath $FullFilePath.ToString()
    }
    Else
    {
        Write-Error -Message ('[New-PasswordFile] :: Path file not found: ' + $Path)
    }

    
} # New-PasswordFile

function Get-PasswordFromFile{
<#
.SYNOPSIS
   Get password from encrypted password file 

.DESCRIPTION
    Read password from encrypted file
    Encryption key is based on windows user security token of logged on user when file was created

.PARAMETER FullPath
    Path to location of encrypted password file
        
.INPUTS
    Encrypted password file
    
.OUTPUTS
    UnEncrypted password

.EXAMPLE
    New-PasswordFile -Path "C:\Temp\Passwords" -Filename "lab-PWD.txt"

.NOTES
    This cmdlet is used allow the use of basic authentication and persist authentication info

#>
	[CmdletBinding()]
	param ( 
		[Parameter(Mandatory=$True)][Alias('f')][string]$FullPath
	)

    
    # Test file existence and retrieve file object
    If(Test-Path -Path $FullPath){

        $File = Get-item -Path $FullPath
        $filedata = Get-Content -Path $File.FullName
        $password = ConvertTo-SecureString -String $filedata
        $BSTR = [System.Runtime.InteropServices.marshal]::SecureStringToBSTR($password)
        $password = [System.Runtime.InteropServices.marshal]::PtrToStringAuto($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        return $password

    }
    else
    {
        Write-Error -Message ('[Get-PasswordFromFile] :: Password file not found: ' + $FullPath)
    }
    
} # Get-PasswordFromFile

function Disable-CertificateValidation{
<#
.SYNOPSIS
    Disable certificate validation

.DESCRIPTION
    Ignore SSL errors - This would not be used if self signed certificates were not used and the proper CA cert was installed

.EXAMPLE
    Disable-CertificateValidation

.NOTES
    

#>
[CmdletBinding()]
param()

add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;

    public class IDontCarePolicy : ICertificatePolicy {
    public IDontCarePolicy() {}
    public bool CheckValidationResult(
        ServicePoint sPoint, X509Certificate cert,
        WebRequest wRequest, int certProb) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName IDontCarePolicy 

} # Disable-CertificateValidation

function Set-XIOAPIConnectionInfo{
<#
.SYNOPSIS
    Set XtremIO Connection Information
    
.DESCRIPTION
    Stores XtremIO REST API connection and authentication information

.PARAMETER username
    API username
        
.PARAMETER passwordfile
    File for API user
        
.PARAMETER baseuri
    Base URL of XtremIO XMS server
        
.PARAMETER certpath
    Certificate store path
        
.PARAMETER certthumbprint
    Certificate store path
        
.EXAMPLE
    Set-XIOAPIConnectionInfo -username "Admin" -passwordfile "C:\temp\password.txt" -baseurl "https://192.168.1.59/api/json/types/"

.NOTES

    Client certificate functionality has not been implemented yet


#>
	[CmdletBinding()]
	param ([Parameter(Mandatory=$True)][Alias('u')][string]$username,
           [Parameter(Mandatory=$True)][Alias('p')][string]$passwordfile,
           [Parameter(Mandatory=$True)][Alias('h')][string]$hostname,
           [Parameter(Mandatory=$False)][ValidateNotNullOrEmpty()][Alias('c')][string]$certpath=$null,
           [Parameter(Mandatory=$False)][ValidateNotNullOrEmpty()][Alias('t')][string]$certthumbprint=$null           
           )

    # Encode basic authorization header
    $upassword = Get-PasswordFromFile -FullPath $passwordfile
    $auth = $username + ':' + $upassword
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $EncodedPassword = [System.Convert]::ToBase64String($Encoded)

    # set base uri
    $baseuri = 'https://' + $hostname + '/api/json/types/'

    # Define global connection variables
    New-Variable -Name XIOAPIBaseUri -Value $baseuri -Scope Global -Force
    New-Variable -Name XIOAPIHeaders -Value @{'Authorization'="Basic $($EncodedPassword)"} -Scope Global -Force

    # Setup root certificate validation - this requires installation of root certificate in client store - TODO****
    if($certpath){
            
    }
} # Set-XIOAPIConnectionInfo

function Get-XIOAPITypes{
<#
.SYNOPSIS
    Get XtremIO API Types Information
    
.DESCRIPTION
    Get XtremIO API Types Information
 
.EXAMPLE
    Get XtremIO Object Types
    Get-XIOAPITypes

#>
	[CmdletBinding()]
	param ()
        
    $Uri = $Global:XIOAPIBaseUri
    ($Uri.Remove($Uri.LastIndexOf('/'),1))
    (Invoke-RestMethod -Method Get -Uri $Uri -Headers $Global:XIOAPIHeaders).Children
    
} # Get-XIOAPITypes

function Get-XIOItem{
<#
.SYNOPSIS
    Get XtremIO Item list
    
.DESCRIPTION
    Get XtremIO Item list

.PARAMETER UriString
    URI String for Query
        
.EXAMPLE
    List clusters
    (Get-XIOItem -UriString "clusters").clusters

.EXAMPLE
    Get XtremIO bricks
    (Get-XIOItem -UriString "bricks").bricks

.EXAMPLE
    Get XtremIO volumes
    (Get-XIOItem -UriString "volumes").volumes

.EXAMPLE
    Get XtremIO volume folders
    (Get-XIOItem -UriString "volume-folders").folders

.EXAMPLE
    Get XtremIO storage controllers
    (Get-XIOItem -UriString "storage-controllers")."storage-controllers"

.EXAMPLE
    Get XtremIO target groups
    (Get-XIOItem -UriString "target-groups")."target-groups"

.EXAMPLE
    Get XtremIO lun maps
    (Get-XIOItem -UriString "lun-maps")."lun-maps"

.EXAMPLE
    Get XtremIO initiator group folders
    (Get-XIOItem -UriString "ig-folders").folders

.EXAMPLE
    Get XtremIO snapshots
    (Get-XIOItem -UriString "snapshots").snapshots

.EXAMPLE
    Get XtremIO iscsi portals
    (Get-XIOItem -UriString "iscsi-portals")."iscsi-portals"

.EXAMPLE
    Get XtremIO xenvs
    (Get-XIOItem -UriString "xenvs").xenvs

.EXAMPLE
    Get XtremIO iscsi routes
    (Get-XIOItem -UriString "iscsi-routes")."iscsi-routes"

.EXAMPLE
    Get XtremIO events
    (Get-XIOItem -UriString "events").events

.EXAMPLE
    Get XtremIO initiator groups
    (Get-XIOItem -UriString "initiator-groups")."initiator-groups"

.EXAMPLE
    Get XtremIO initiators
    (Get-XIOItem -UriString "initiators").initiators

.EXAMPLE
    Get XtremIO ssds 
    (Get-XIOItem -UriString "ssds").ssds

.EXAMPLE
    Get XtremIO data-protection-groups
    (Get-XIOItem -UriString "data-protection-groups")."data-protection-groups"

.EXAMPLE
    Get XtremIO targets
    (Get-XIOItem -UriString "targets").targets

.NOTES
    


#>
	[CmdletBinding()]
	param ([Parameter(Mandatory=$True)][Alias('u')][string]$UriString)
    
    Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
    
} # Get-XIOItem




# Read functions
function Get-XIOCluster{
<#
.SYNOPSIS
    Get XtremIO Cluster Information
    
.DESCRIPTION
    Get XtremIO Cluster Information

.PARAMETER Name
    Name String for Cluster Info Query by name

.PARAMETER ID
    ID String for Cluster Info Query by index

.EXAMPLE
    Get XtremIO Cluster Info by index
    Get-XIOCluster -ID 1
    
.EXAMPLE
    Get XtremIO Cluster Info by name    
    Get-XIOCluster -Name X1
    Get-XIOCluster X1

.EXAMPLE
    Get-XIOCluster

.NOTES
    


#>
[CmdletBinding(DefaultParameterSetName='AllClusters')]
param ( [Parameter( Mandatory=$true,
                    ValueFromPipeline=$true,
                    Position=0, 
                    ParameterSetName='ClusterByName')]
        [Alias('n')][string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='ClusterByID')]
        [Alias('i')][string]$ID=$null
        
)

    Process{
        # Return details of cluster names passed by parameter or pipeline
        if($Name){
            $UriString = 'clusters/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).Content
        }
    }
    End{
        
        # Return detail of specific cluster by ID
        if($ID){
            $UriString = 'clusters/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).Content
        }

        # No parameters passed return details of all clusters
        if($PSCmdlet.ParameterSetName -eq 'AllClusters'){
            $UriString = 'clusters/'
            (Get-XIOItem -UriString 'clusters').clusters | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
        
    }  
} # Get-XIOCluster

function Get-XIOBrick{
<#
.SYNOPSIS
    Get XtremIO Brick Information
    
.DESCRIPTION
    Get XtremIO Brick Information

.PARAMETER Name
    Name String for Brick Info Query by name
        
.PARAMETER ID
    ID String for Brick Info Query by index
        
.EXAMPLE
    Get XtremIO Brick Info by index
    Get-XIOBrick -ID 1
    
.EXAMPLE
    Get XtremIO Brick Info by name    
    Get-XIOBrick -Name X1

.NOTES
    


#>
[CmdletBinding(DefaultParameterSetName='AllBricks')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,  
                    Position=0,
                    ParameterSetName='BrickByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true, 
                    ParameterSetName='BrickByIndex')]
        [Alias('i')] 
        [string]$ID=$null
        
)
   
    Process{
        # Return details of brick names passed by parameter or pipeline
        if($Name){
            $UriString = 'bricks/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
    }
    End{
        
        # Return detail of specific brick by ID
        if($ID){
            $UriString = 'bricks/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }

        # No parameters passed return details of all bricks
        if($PSCmdlet.ParameterSetName -eq 'AllBricks'){
            $UriString = 'bricks/'
            (Get-XIOItem -UriString 'bricks').bricks | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }

    }
} # Get-XIOBrick

function Get-XIOXenvs{
<#
.SYNOPSIS
    Get XtremIO Xenvs Information
    
.DESCRIPTION
    Get XtremIO Xenvs Information

.PARAMETER Name
    Name String for Xenvs Info Query by name
        
.PARAMETER ID
    ID String for Xenvs Info Query by index
        
.EXAMPLE
    Get XtremIO Xenvs Info by index
    Get-XIOXenvs -ID 1
    
.EXAMPLE
    Get XtremIO Xenvs Info by name    
    Get-XIOXenvs -Name X1
    Get-XIOXenvs X1

.EXAMPLE
    Get XtremIO Xenvs Info by name    
    Get-XIOXenvs


.NOTES
    


#>
[CmdletBinding(DefaultParameterSetName='AllXEnvs')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true, 
                    Position=0,
                    ParameterSetName='XenvsByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='XenvsByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
   
    Process 
    {
        
        # Return details of xenv names passed by parameter or pipeline
        if($Name){
            $UriString = 'xenvs/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
                
        }
        
    }
    End 
    {
        # Return detail of specific xenv by ID
        if($ID){
            $UriString = 'xenvs/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }

        # No parameters passed return details of all xenvs
        if($PSCmdlet.ParameterSetName -eq 'AllXEnvs'){
            $UriString = 'xenvs/'
            (Get-XIOItem -UriString 'xenvs').xenvs | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }

    }
    
} # Get-XIOXenvs

function Get-XIOVolume{
<#
.SYNOPSIS
    Get XtremIO Volume Information
    
.DESCRIPTION
    Get XtremIO Volume Information

.PARAMETER Name
    Name String for Volume Info Query by name
        
.PARAMETER ID
    ID String for Volume Info Query by index
        
.EXAMPLE
    Get XtremIO Volume Info by index
    Get-XIOVolume -ID 1
    
.EXAMPLE
    Get XtremIO Volume Info by name    
    Get-XIOVolume -Name X1
    Get-XIOVolume X1

.EXAMPLE
    Get-XIOVolume    

.NOTES
    


#>
[CmdletBinding(DefaultParameterSetName='AllVolumes')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='VolByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='VolByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)

    Process{
        # Return details of volume names passed by parameter or pipeline
        if($Name){
            $UriString = 'volumes/'
            $UriString += ('?name=' + $Name)
        }
        (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content

    }
    End{
        # Return detail of specific volume by ID
        if($ID){
            $UriString = 'volumes/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all volumes
        if($PSCmdlet.ParameterSetName -eq 'AllVolumes'){
            $UriString = 'volumes/'
            (Get-XIOItem -UriString 'volumes').volumes | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }

    }
} # Get-XIOVolume

function Get-XIOVolumeFolder{
<#
.SYNOPSIS
    Get XtremIO volume folder info
    
.DESCRIPTION
    Get XtremIO volume folder info

.PARAMETER Name
    String for name of folder
        
.PARAMETER ID
    String for ID of folder
        
.EXAMPLE
    Get volume folder by ID
    Get-XIOVolumeFolder -ID 1
    
.EXAMPLE
    Get volume folder by name
    Get-XIOVolumeFolder -Name "Test01"
    Get-XIOVolumeFolder "Test01"

.EXAMPLE
    Get-XIOVolumeFolder

.NOTES
    

#>
[CmdletBinding(DefaultParameterSetName='AllVolumeFolders')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true, 
                   Position=0, 
                   ParameterSetName='FolderByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='FolderByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)

    Process{
        
        # Return details of volume folder names passed by parameter or pipeline       
        if($Name){
            $UriString = 'volume-folders/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific volume folder by ID            
        if($ID){
            $UriString = 'volume-folders/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all volume folders
        if($PSCmdlet.ParameterSetName -eq 'AllVolumeFolders'){
            $UriString = 'volume-folders/'
            (Get-XIOItem -UriString 'volume-folders').folders | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOVolumeFolder

function Get-XIOStorageController{
<#
.SYNOPSIS
    Get XtremIO storage controller info
    
.DESCRIPTION
    Get XtremIO storage controller info

.PARAMETER Name
    String for name of storage controller
        
.PARAMETER ID
    String for ID of storage controller
        
.EXAMPLE
    Get storage controller by ID
    Get-XIOStorageController -ID 1
    
.EXAMPLE
    Get storage controller by name
    Get-XIOStorageController -Name "Test01"
    Get-XIOStorageController "Test01"

.EXAMPLE
    Get-XIOStorageController

.NOTES
    

#>
[CmdletBinding(DefaultParameterSetName='AllControllers')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,  
                   Position=0, 
                   ParameterSetName='SCByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='SCByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Process{
        # Return details of storage controller names passed by parameter or pipeline             
        if($Name){
            $UriString = 'storage-controllers/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific  storage controller by ID  
        if($ID){
            $UriString = 'storage-controllers/' 
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all  storage controllers
        if($PSCmdlet.ParameterSetName -eq 'AllControllers'){
            $UriString = 'storage-controllers/'
            (Get-XIOItem -UriString 'storage-controllers').'storage-controllers' | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOStorageController

function Get-XIODataProtectionGroup{
<#
.SYNOPSIS
    Get XtremIO Data Protection Group info
    
.DESCRIPTION
    Get XtremIO Data Protection Group info

.PARAMETER Name
    String for name of Data Protection Group
        
.PARAMETER ID
    String for ID of Data Protection Group
        
.EXAMPLE
    Get Data Protection Group by ID
    Get-XIODataProtectionGroup -ID 1
    
.EXAMPLE
    Get Data Protection Group by name
    Get-XIODataProtectionGroup -Name "Test01"
    Get-XIODataProtectionGroup "Test01"

.EXAMPLE
    Get-XIODataProtectionGroup

.NOTES
    

#>
[CmdletBinding(DefaultParameterSetName='AllDPGroups')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0, 
                   ParameterSetName='DPGByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='DPGByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)

    Process{
        # Return details of data protection group by name passed by parameter or pipeline
        if($Name){
            $UriString = 'data-protection-groups/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific data protection group by ID
        if($ID){
            $UriString = 'data-protection-groups/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all data protection groups
        if($PSCmdlet.ParameterSetName -eq 'AllDPGroups'){
            $UriString = 'data-protection-groups/'
            (Get-XIOItem -UriString 'data-protection-groups').'data-protection-groups' | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIODataProtectionGroup

function Get-XIOSnapshot{
<#
.SYNOPSIS
    Get XtremIO Snapshot Information
    
.DESCRIPTION
    Get XtremIO Snapshot Information

.PARAMETER Name
    Name String for Snapshot Info Query by name
        
.PARAMETER ID
    ID String for Snapshot Info Query by index
        
.EXAMPLE
    Get XtremIO Snapshot Info by index
    Get-XIOSnapshot -ID 1
    
.EXAMPLE
    Get XtremIO Snapshot Info by name    
    Get-XIOSnapshot -Name X1
    Get-XIOSnapshot X1

.EXAMPLE
    Get-XIOSnapshot

.NOTES
    


#>
[CmdletBinding(DefaultParameterSetName='AllSnapshots')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='SnapshotByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='SnapshotByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)

    Process{
        # Return details of snapshot by name passed by parameter or pipeline
        if($Name){
            $UriString = 'snapshots/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
    }
    End{
        # Return detail of specific snapshot by ID
        if($ID){
            $UriString = 'snapshots/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all snapshots
        if($PSCmdlet.ParameterSetName -eq 'AllSnapshots'){
            $UriString = 'snapshots/'
            (Get-XIOItem -UriString 'snapshots').snapshots | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOSnapshot

function Get-XIOInitiator{
<#
.SYNOPSIS
    Get XtremIO Initiator Information
    
.DESCRIPTION
    Get XtremIO Initiator Information

.PARAMETER Name
    Name String for Initiator Info Query by name
        
.PARAMETER ID
    ID String for Initiator Info Query by index
        
.EXAMPLE
    Get XtremIO Initiator Info by index
    Get-XIOInitiator -ID 1
    
.EXAMPLE
    Get XtremIO Initiator Info by name    
    Get-XIOInitiator -Name X1
    Get-XIOInitiator X1

.EXAMPLE
    Get-XIOInitiator

.NOTES
    


#>
[CmdletBinding(DefaultParameterSetName='AllInitiators')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,  
                    Position=0,
                    ParameterSetName='InitiatorByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='InitiatorByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)

    Process{
        # Return details of initiator by name passed by parameter or pipeline
        if($Name){
            $UriString = 'initiators/'
            $UriString += ('?name=' + $Name)

        }
        (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
    }
    End{
        # Return detail of specific initiator by ID
        if($ID){
            $UriString = 'initiators/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all initiator
        if($PSCmdlet.ParameterSetName -eq 'AllInitiators'){
            $UriString = 'initiators/'
            (Get-XIOItem -UriString 'initiators').initiators | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOInitiator

function Get-XIOInitiatorGroup{
<#
.SYNOPSIS
    Get XtremIO Initiator Group info
    
.DESCRIPTION
    Get XtremIO Initiator Group info

.PARAMETER Name
    String for name of Initiator Group
        
.PARAMETER ID
    String for ID of Initiator Group
        
.EXAMPLE
    Get Initiator Group by ID
    Get-XIOInitiatorGroup -ID 1
    
.EXAMPLE
    Get Initiator Group by name
    Get-XIOInitiatorGroup -Name "Test01"
    Get-XIOInitiatorGroup "Test01"

.EXAMPLE
    Get-XIOInitiatorGroup

.NOTES
    

#>
[CmdletBinding(DefaultParameterSetName='AllInitiatorGroups')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0, 
                   ParameterSetName='IGByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='IGByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)

    Process{
        # Return details of initiator group by name passed by parameter or pipeline          
        if($Name){
            $UriString = 'initiator-groups/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific initiator group by ID
        if($ID){ 
            $UriString = 'initiator-groups/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all initiator groups
        if($PSCmdlet.ParameterSetName -eq 'AllInitiatorGroups'){
            $UriString = 'initiator-groups/'
            (Get-XIOItem -UriString 'initiator-groups').'initiator-groups' | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOInitiatorGroup

function Get-XIOInitiatorGroupFolder{
<#
.SYNOPSIS
    Get XtremIO Initiator Group folder info
    
.DESCRIPTION
    Get XtremIO Initiator Group folder info

.PARAMETER Name
    String for name of Initiator Group folder
        
.PARAMETER ID
    String for ID of Initiator Group folder
        
.EXAMPLE
    Get Initiator Group folder by ID
    Get-XIOInitiatorGroupFolder -ID 1
    
.EXAMPLE
    Get Initiator Group folder by name
    Get-XIOInitiatorGroupFolder -Name "Test01"
    Get-XIOInitiatorGroupFolder "Test01"

.EXAMPLE
    Get-XIOInitiatorGroupFolder

.NOTES
    

#>
[CmdletBinding(DefaultParameterSetName='AllIGFolders')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0, 
                   ParameterSetName='IGFolderByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='IGFolderByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)

    Process{
        # Return details of initiator group folder by name passed by parameter or pipeline
        if($Name){
            $UriString = 'ig-folders/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific initiator group folder by ID
        if($ID){
            $UriString = 'ig-folders/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all initiator group folders
        if($PSCmdlet.ParameterSetName -eq 'AllIGFolders'){
            $UriString = 'ig-folders/'
            (Get-XIOItem -UriString 'ig-folders').folders | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOInitiatorGroupFolder

function Get-XIOTarget{
<#
.SYNOPSIS
    Get XtremIO Target Information
    
.DESCRIPTION
    Get XtremIO Target Information

.PARAMETER Name
    Name String for Target Info Query by name
        
.PARAMETER ID
    ID String for Target Info Query by index
        
.EXAMPLE
    Get XtremIO Target Info by index
    Get-XIOTarget -ID 1
    
.EXAMPLE
    Get XtremIO Target Info by name    
    Get-XIOTarget -Name X1
    Get-XIOTarget X1

.EXAMPLE
    Get-XIOTarget

.NOTES
    


#>
[CmdletBinding(DefaultParameterSetName='AllTargets')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='TargetByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='TargetByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)

    Process{
        # Return details of target by name passed by parameter or pipeline
        if($Name){
            $UriString = 'targets/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific target by ID
        if($ID){
            $UriString = 'targets/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        
        # No parameters passed return details of all targets
        if($PSCmdlet.ParameterSetName -eq 'AllTargets'){
            $UriString = 'targets/'
            (Get-XIOItem -UriString 'targets').targets | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOTarget

function Get-XIOTargetGroup{
<#
.SYNOPSIS
    Get XtremIO Target Group info
    
.DESCRIPTION
    Get XtremIO Target Group info

.PARAMETER Name
    String for name of Target Group
        
.PARAMETER ID
    String for ID of Target Group
        
.EXAMPLE
    Get Target Group by ID
    Get-XIOTargetGroup -ID 1
    
.EXAMPLE
    Get Target Group by name
    Get-XIOTargetGroup -Name "Test01"
    Get-XIOTargetGroup "Test01"

.EXAMPLE
    Get-XIOTargetGroup

.NOTES
    

#>
[CmdletBinding(DefaultParameterSetName='AllTargetGroups')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0, 
                   ParameterSetName='TGByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='TGByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Process{
        
        # Return details of target group by name passed by parameter or pipeline
        if($Name){
            $UriString = 'target-groups/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific target group by ID   
        if($ID){
            $UriString = 'target-groups/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all target groups
        if($PSCmdlet.ParameterSetName -eq 'AllTargetGroups'){
            $UriString = 'target-groups/'
            (Get-XIOItem -UriString 'target-groups').'target-groups' | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOTargetGroup

function Get-XIOIscsiPortal{
<#
.SYNOPSIS
    Get XtremIO iSCSI Portal info
    
.DESCRIPTION
    Get XtremIO iSCSI Portal info

.PARAMETER Name
    String for name of iSCSI Portal
        
.PARAMETER ID
    String for ID of iSCSI Portal
        
.EXAMPLE
    Get iSCSI Portal by ID
    Get-XIOIscsiPortal -ID 1
    
.EXAMPLE
    Get iSCSI Portal by name
    Get-XIOIscsiPortal -Name "Test01"
    Get-XIOIscsiPortal "Test01"

.EXAMPLE
    Get-XIOIscsiPortal

.NOTES
    

#>
[CmdletBinding(DefaultParameterSetName='AllISCSIPortals')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0, 
                   ParameterSetName='IsPortalByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='IsPortalByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)

    Process{
        # Return details of iscsi portal by name passed by parameter or pipeline                
        if($Name){
            $UriString = 'iscsi-portals/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific iscsi portal by ID
        if($ID){ 
            $UriString = 'iscsi-portals/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all iscsi portals
        if($PSCmdlet.ParameterSetName -eq 'AllISCSIPortals'){
            $UriString = 'iscsi-portals/'
            (Get-XIOItem -UriString 'iscsi-portals').'iscsi-portals' | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOIscsiPortal

function Get-XIOIscsiRoute{
<#
.SYNOPSIS
    Get XtremIO iSCSI Route info
    
.DESCRIPTION
    Get XtremIO iSCSI Route info

.PARAMETER Name
    String for name of iSCSI Route
        
.PARAMETER ID
    String for ID of iSCSI Route
        
.EXAMPLE
    Get iSCSI Route by ID
    Get-XIOIscsiRoute -ID 1
    
.EXAMPLE
    Get iSCSI Route by name
    Get-XIOIscsiRoute -Name "Test01"
    Get-XIOIscsiRoute "Test01"

.EXAMPLE
    Get-XIOIscsiRoute

.NOTES
    

#>
[CmdletBinding(DefaultParameterSetName='AllISCSIRoutes')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0, 
                   ParameterSetName='IsRouteByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='IsRouteByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)

    Process{
        # Return details of iscsi route by name passed by parameter or pipeline           
        if($Name){
            $UriString = 'iscsi-routes/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific iscsi route by ID
        if($ID){
            $UriString = 'iscsi-routes/' 
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all iscsi routes
        if($PSCmdlet.ParameterSetName -eq 'AllISCSIRoutes'){
            $UriString = 'iscsi-routes/'
            (Get-XIOItem -UriString 'iscsi-routes').'iscsi-routes' | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOIscsiRoute

function Get-XIOLunMap{
<#
.SYNOPSIS
    Get XtremIO Lun Map info
    
.DESCRIPTION
    Get XtremIO Lun Map info

.PARAMETER Name
    String for name of Lun Map
        
.PARAMETER ID
    String for ID of Lun Map
        
.EXAMPLE
    Get Lun Map by ID
    Get-XIOLunMap -ID 1
    
.EXAMPLE
    Get Lun Map by name
    Get-XIOLunMap -Name "Test01"
    Get-XIOLunMap "Test01"

.EXAMPLE
    Get-XIOLunMap

.NOTES
    

#>
[CmdletBinding(DefaultParameterSetName='AllLunMaps')]
param ( [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0, 
                   ParameterSetName='LunMapByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='LunMapByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)

    Process{
        # Return details of lun map by name passed by parameter or pipeline                
        if($Name){
            $UriString = 'lun-maps/'
            $UriString += ('?name=' + $Name)
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
    }
    End{
        # Return detail of specific lun map by ID
        if($ID){
            $UriString = 'lun-maps/'
            $UriString += $ID
            (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
        }
        # No parameters passed return details of all lun maps
        if($PSCmdlet.ParameterSetName -eq 'AllLunMaps'){
            $UriString = 'lun-maps/'
            (Get-XIOItem -UriString 'lun-maps').'lun-maps' | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOLunMap

function Get-XIOSSD{
<#
.SYNOPSIS
    Get XtremIO SSD Information
    
.DESCRIPTION
    Get XtremIO SSD Information

.PARAMETER Name
    Name String for SSD Info Query by name
        
.PARAMETER ID
    ID String for SSD Info Query by index
        
.EXAMPLE
    Get XtremIO SSD Info by index
    Get-XIOSSD -ID 1
    
.EXAMPLE
    Get XtremIO SSD Info by name    
    Get-XIOSSD -Name X1
    Get-XIOSSD X1

.EXAMPLE
    Get-XIOSSD

.NOTES
    


#>
[CmdletBinding(DefaultParameterSetName='AllSSDs')]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='SSDByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='SSDByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    Process{
        # Return details of ssd by name passed by parameter or pipeline
        if($Name){
            $UriString = 'ssds/'
            $UriString += ('?name=' + $Name)

        }
        (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
    }
    End{
        # Return detail of specific ssd by ID
        if($ID){
                $UriString = 'ssds/'
                $UriString += $ID
                (Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders).content
            }
        # No parameters passed return details of all ssds
        if($PSCmdlet.ParameterSetName -eq 'AllSSDs'){
            $UriString = 'ssds/'
            (Get-XIOItem -UriString 'ssds').ssds | ForEach-Object{(Invoke-RestMethod -Method Get -Uri ($Global:XIOAPIBaseUri + $UriString + '?name=' + ($_.Name)) -Headers $Global:XIOAPIHeaders).Content}
        }
    }
} # Get-XIOSSD





# Create functions
function New-XIOVolume{
<#
.SYNOPSIS
    Create New XtremIO Volume
    
.DESCRIPTION
    Create New XtremIO Volume

.PARAMETER Size
    String for Volume Size in KB(k)/MB(m)/GB(g)/TB(t)
    Must be greater than 0 and a multiple of 1MB
        
.PARAMETER Name
    String for Volume name
        
.PARAMETER Offset
    String for Volume offset 0-7
    Alignment offset for volumes of 512LB Size
        
.PARAMETER LBSize
    String for Logical Block Size 512(Default) or 4096
        
.PARAMETER SysID
    String for Cluster name or index when more
    than one cluster is defined 
        
.PARAMETER ParentFolderID
    String for folder name to create volume in 
        
.EXAMPLE
    New XtremIO Volume minimum requirements with defaults
    New-XIOVolume -VolSize "10m"
    
.EXAMPLE
    New XtremIO Volume named and created in specific volume folder    
    New-XIOVolume -VolSize "10m" -VolName "dtest" -ParentFolderID "/DMTest"

.NOTES
    
    TODO - Need to experiment with options of using pipline.
            


#>
[CmdletBinding()]
param ( [Parameter(Mandatory=$true)]
        [Alias('s')]
        [Alias('vs')]
        [Alias('VolSize')]
        [string]$Size=$null,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('n')] 
        [Alias('vn')]
        [Alias('VolName')]
        [string]$Name=$null,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('0','1','2','3','4','5','6','7')]
        [Alias('of')] 
        [string]$Offset=$null,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('512','4096')]
        [Alias('lbs')] 
        [string]$LBSize=$null,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('sid')] 
        [string]$SysID=$null,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('pf')] 
        [string]$ParentFolderID=$null
)
    
    
    $UriString = 'volumes'
    $JSoNBody = New-Object -TypeName psobject
    $JSoNBody | Add-Member -MemberType NoteProperty -Name vol-size -Value $Size 
    if($Name){$JSoNBody | Add-Member -MemberType NoteProperty -Name vol-name -Value $Name}
    if($LBSize){
        switch ($LBSize)
        {
            '512' {
                $JSoNBody | Add-Member -MemberType NoteProperty -Name lb-size -Value $LBSize
                if($Offset){$JSoNBody | Add-Member -MemberType NoteProperty -Name alignment-offset -Value $Offset}
            }
            '4096' {
                $JSoNBody | Add-Member -MemberType NoteProperty -Name lb-size -Value $LBSize
            }
        }
    }
    if($SysID){$JSoNBody | Add-Member -MemberType NoteProperty -Name sys-id -Value $SysID}
    if($ParentFolderID){$JSoNBody | Add-Member -MemberType NoteProperty -Name parent-folder-id -Value $ParentFolderID}

    
    Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
    

    
} # New-XIOVolume

function New-XIOVolumeFolder{
<#
.SYNOPSIS
    Create new XtremIO volume folder
    
.DESCRIPTION
    Create new XtremIO volume folder

.PARAMETER Caption
    String for name of new folder
        
.PARAMETER ParentFolderName
    String for folder name of parent folder
        
.EXAMPLE
    Create new top level folder
    New-XIOVolumeFolder -Caption "Test01" -ParentFolderName "/"
    
.EXAMPLE
    Create new subfolder under "/Test01"
    New-XIOVolumeFolder -Caption "Test" -ParentFolderName "/Test01"

.NOTES
    


#>
[CmdletBinding()]
param ( [Parameter(Mandatory=$true)]
        [Alias('c')] 
        [string]$Caption=$null,
        [Parameter(Mandatory=$true)]
        [Alias('pn')] 
        [string]$ParentFolderName=$null
)
    
    
    $UriString = 'volume-folders'
    $JSoNBody = New-Object -TypeName psobject
    $JSoNBody | Add-Member -MemberType NoteProperty -Name caption -Value $Caption
    if($ParentFolderName){$JSoNBody | Add-Member -MemberType NoteProperty -Name parent-folder-id -Value $ParentFolderName}        

    (Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)).Links
    


} # New-XIOVolumeFolder

function New-XIOLunMap{
<#
.SYNOPSIS
    Create new XtremIO LUN Map
    
.DESCRIPTION
    Create new XtremIO LUN Map

.PARAMETER Name
    Name string of volume to be mapped
        
.PARAMETER ID
    ID string of volume to be mapped
        
.PARAMETER InitiatorGroup
    Initiator Group's name or index number
        
.PARAMETER HostID
    Unique LUN identification, exposing the volume to the host (16K LUN mappings are currently supported)
        
.PARAMETER TargetGroup
    Target’s group's name or index number 
        
.EXAMPLE
    New XtremIO Volume minimum requirements with defaults
    New-XIOLunMap -VolSize "10m"
    
.EXAMPLE
    New XtremIO Volume named and created in specific volume folder    
    New-XIOLunMap -VolSize "10m" -VolName "dtest" -ParentFolderID "/DMTest"

.NOTES
    


#>
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true, 
                    Position=0,
                    ParameterSetName='VolByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true,ParameterSetName='VolByID')]
        [Alias('i')] 
        [int]$ID=$null,
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Alias('ig')] 
        [int]$InitiatorGroup=$null,
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Alias('hi')] 
        [int]$HostID=$null,
        [Parameter(Mandatory=$false,ParameterSetName='TGByID')]
        [Parameter(ParameterSetName='VolByName')]
        [Parameter(ParameterSetName='VolByID')]
        [ValidateNotNull()]
        [Alias('tgi')] 
        [int]$TargetGroupID=$null,
        [Parameter(Mandatory=$false,ParameterSetName='TGByName')]
        [Parameter(ParameterSetName='VolByName')]
        [Parameter(ParameterSetName='VolByID')]
        [ValidateNotNullOrEmpty()]
        [Alias('tgn')] 
        [string]$TargetGroupName=$null
)


        Begin{
            $UriString = 'lun-maps'
        }

        Process{
            
            $JSoNBody = New-Object -TypeName psobject
            if($Name){$JSoNBody | Add-Member -MemberType NoteProperty -Name vol-id -Value $Name} # Note error in EMC documentation - specified vol-name as parameter but vol-id must be used with string as type
            if($ID){$JSoNBody | Add-Member -MemberType NoteProperty -Name vol-id -Value $ID}
            if($InitiatorGroup){$JSoNBody | Add-Member -MemberType NoteProperty -Name ig-id -Value $InitiatorGroup} # Note error in EMC documentation - specifies name or id can be used but only ID appears to work
            if($HostID){$JSoNBody | Add-Member -MemberType NoteProperty -Name lun -Value $HostID}
            if($TargetGroupID){$JSoNBody | Add-Member -MemberType NoteProperty -Name tg-id -Value $TargetGroupID}
            if($TargetGroupName){$JSoNBody | Add-Member -MemberType NoteProperty -Name tg-name -Value $TargetGroupName}
            Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            
        }


} # New-XIOLunMap

function New-XIOSnapshot{
<#
.SYNOPSIS
    Create New XtremIO Snapshot
    
.DESCRIPTION
    Create New XtremIO Snapshot

.PARAMETER VolName
    Source volume’s name
        
.PARAMETER SnapName
    Snapshot’s name
        
.PARAMETER ParentFolderID
    Destination folder’s name 
        
.EXAMPLE
    New XtremIO snapshot
    New-XIOSnapshot -VolName "DTest01" -SnapName ("DTest01_" + (Get-Date -Format yyyyMMdd-HHmmss)) -FolderID "/DMTest"
    

.NOTES
    


#>
[CmdletBinding()]
param ( [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true, 
                    Position=0)]
        [Alias('n')] 
        [Alias('VolName')]
        [Alias('vn')]
        [string]$Name=$null,
        [Parameter(Mandatory=$true)]
        [Alias('sn')] 
        [string]$SnapName=$null,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias('f')] 
        [string]$FolderID=$null
)

        Begin{

            $UriString = 'snapshots'

        }

        Process{
            
            $JSoNBody = New-Object -TypeName psobject
            if($Name){$JSoNBody | Add-Member -MemberType NoteProperty -Name ancestor-vol-id -Value $Name}
            if($SnapName){$JSoNBody | Add-Member -MemberType NoteProperty -Name snap-vol-name -Value $SnapName}
            if($FolderID){$JSoNBody | Add-Member -MemberType NoteProperty -Name folder-id -Value $FolderID}
            Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
            
        }


} # New-XIOSnapshot

function New-XIOIGFolder{
<#
.SYNOPSIS
    Create new XtremIO initiator group folder
    
.DESCRIPTION
    Create new XtremIO initiator group folder

.PARAMETER Caption
    String for name of new folder
        
.PARAMETER ParentFolderName
    String for folder name of parent folder
        
.EXAMPLE
    Create new top level folder
    New-XIOIGFolder -Caption "Test01" -ParentFolderName "/"
    
.EXAMPLE
    Create new subfolder under "/Test01"
    New-XIOIGFolder -Caption "Test" -ParentFolderName "/Test01"

.NOTES
    


#>
[CmdletBinding()]
param ( [Parameter(Mandatory=$true)]
        [Alias('c')] 
        [string]$Caption=$null,
        [Parameter(Mandatory=$true)]
        [Alias('pn')] 
        [string]$ParentFolderName=$null
)
    
        $UriString = 'ig-folders'
        $JSoNBody = New-Object -TypeName psobject
        $JSoNBody | Add-Member -MemberType NoteProperty -Name caption -Value $Caption
        if($ParentFolderName){$JSoNBody | Add-Member -MemberType NoteProperty -Name parent-folder-id -Value $ParentFolderName}        

        (Invoke-RestMethod -Method Post -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)).Links
        

} # New-XIOIGFolder





# Update functions
function Rename-XIOVolumeFolder{
<#
.SYNOPSIS
    Rename XtremIO volume folder
    
.DESCRIPTION
    Rename XtremIO volume folder

.PARAMETER NewCaption
    String for new name of folder
        
.PARAMETER FolderName
    String for folder name of folder
        
.PARAMETER FolderID
    String for folder ID of folder
        
.EXAMPLE
    Rename top level folder
    Rename-XIOVolumeFolder -Caption "Test01" -FolderID 1
    
.EXAMPLE
    Rename subfolder "/Test"
    Rename-XIOVolumeFolder -Caption "Test01" -FolderName "/Test"

.NOTES
    

#>
[CmdletBinding()]
param ( [Parameter(Mandatory=$true)]
        [Alias('c')] 
        [string]$Caption=$null,
        [Parameter(Mandatory=$true,ParameterSetName='FolderByName')]
        [Alias('fn')] 
        [string]$FolderName=$null,
        [Parameter(Mandatory=$true,ParameterSetName='FolderByID')]
        [Alias('fid')] 
        [string]$FolderID=$null
       )
    

    $UriString = 'volume-folders/'
    $JSoNBody = New-Object -TypeName psobject
    $JSoNBody | Add-Member -MemberType NoteProperty -Name new-caption -Value $Caption
    if($FolderName){$UriString += ('?name=' + $FolderName)}
    if($FolderID){$UriString += $FolderID}

    $ReturnData = Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
    $ReturnData

} # Rename-XIOVolumeFolder

function Update-XIOVolume{
<#
.SYNOPSIS
    Update XtremIO Volume Properties
    
.DESCRIPTION
    Update XtremIO Volume Properties

.PARAMETER VolID
    ID String for Volume Info Query by index
        
.PARAMETER VolName
    Name String for Volume Info Query by name
        
.PARAMETER NewVolName
    Name String for new volume name
        
.PARAMETER NewVolSize
    Size String for new volume size
        
.PARAMETER SmallIOAlerts
    String for state of volume small IO alerts
        
.PARAMETER UnalignedIOAlerts
    String for state of volume unaligned IO alerts
        
.PARAMETER VaaiTpAlerts
    String for state of volume VAAI TP alerts
        
.EXAMPLE
    Update XtremIO Volume Info by index
    Update-XIOVolume -VolID 1 -NewVolName "X01"
    
.EXAMPLE
    Update XtremIO Volume Info by name    
    Update-XIOVolume -VolName "X1" -NewVolName "X01"

.EXAMPLE
    Update XtremIO Volume Info by name    
    Update-XIOVolume -VolName "X1" -VaaiTpAlerts enable


.NOTES
    


#>
[CmdletBinding()]
param ( [Parameter(Mandatory=$true, 
                    ParameterSetName='VolNameUpdateByIndex')]
        [Parameter(ParameterSetName='VolSizeUpdateByIndex')]
        [Parameter(ParameterSetName='SmallIOAlertUpdateByIndex')]
        [Parameter(ParameterSetName='UnalignedIOAlertUpdateByIndex')]
        [Parameter(ParameterSetName='VAAITPAlertUpdateByIndex')]
        [Alias('vid')] 
        [string]$VolID=$null,
        [Parameter(Mandatory=$true, 
                    ParameterSetName='VolNameUpdateByName')]
        [Parameter(ParameterSetName='VolSizeUpdateByName')]
        [Parameter(ParameterSetName='SmallIOAlertUpdateByName')]
        [Parameter(ParameterSetName='UnalignedIOAlertUpdateByName')]
        [Parameter(ParameterSetName='VAAITPAlertUpdateByName')]
        [Alias('vn')] 
        [string]$VolName=$null,
        [Parameter(Mandatory=$false,ParameterSetName='VolNameUpdateByIndex')]
        [Parameter(ParameterSetName='VolNameUpdateByName')]
        [ValidateNotNullOrEmpty()]
        [string]$NewVolName=$null,
        [Parameter(Mandatory=$false,ParameterSetName='VolSizeUpdateByIndex')]
        [Parameter(ParameterSetName='VolSizeUpdateByName')]
        [ValidateNotNullOrEmpty()]
        [string]$NewVolSize=$null,
        [Parameter(Mandatory=$false,ParameterSetName='SmallIOAlertUpdateByIndex')]
        [Parameter(ParameterSetName='SmallIOAlertUpdateByName')]
        [ValidateSet('enable','disable')]
        [ValidateNotNullOrEmpty()]
        [string]$SmallIOAlerts=$null,
        [Parameter(Mandatory=$false,ParameterSetName='UnalignedIOAlertUpdateByIndex')]
        [Parameter(ParameterSetName='UnalignedIOAlertUpdateByName')]
        [ValidateSet('enable','disable')]
        [ValidateNotNullOrEmpty()]
        [string]$UnalignedIOAlerts=$null,
        [Parameter(Mandatory=$false,ParameterSetName='VAAITPAlertUpdateByIndex')]
        [Parameter(ParameterSetName='VAAITPAlertUpdateByName')]
        [ValidateSet('enable','disable')]
        [ValidateNotNullOrEmpty()]
        [string]$VaaiTpAlerts=$null

)
    
    
        
    $UriString = 'volumes/'
    if($VolID){
        $UriString += $VolID
    }
    if($VolName){
        $UriString += ('?name=' + $VolName)
    }

    $JSoNBody = New-Object -TypeName psobject
    if($NewVolName){$JSoNBody | Add-Member -MemberType NoteProperty -Name vol-name -Value $NewVolName}
    if($NewVolSize){$JSoNBody | Add-Member -MemberType NoteProperty -Name vol-size -Value $NewVolSize}
    if($SmallIOAlerts){
            
        switch ($SmallIOAlerts)
        {
            'enable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name small-io-alerts -Value 'enabled'}
            'disable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name small-io-alerts -Value 'disabled'}
        }
    }
    if($UnalignedIOAlerts){
        switch ($UnalignedIOAlerts)
        {
            'enable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name unaligned-io-alerts -Value 'enabled'}
            'disable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name unaligned-io-alerts -Value 'disabled'}
        }
    }
    if($VaaiTpAlerts){
        switch ($VaaiTpAlerts)
        {
            'enable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name vaai-tp-alerts -Value 'enabled'}
            'disable' {$JSoNBody | Add-Member -MemberType NoteProperty -Name vaai-tp-alerts -Value 'disabled'}
        }
    }

    $ReturnData = Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
    $ReturnData

} # Update-XIOVolume

function Rename-XIOIGFolder{
<#
.SYNOPSIS
    Rename XtremIO initiator group folder
    
.DESCRIPTION
    Rename XtremIO initiator group folder

.PARAMETER NewCaption
    String for new name of folder
        
.PARAMETER FolderName
    String for folder name of folder
        
.PARAMETER FolderID
    String for folder ID of folder
        
.EXAMPLE
    Rename top level folder
    Rename-XIOIGFolder -Caption "Test01" -FolderID 1
    
.EXAMPLE
    Rename subfolder "/Test"
    Rename-XIOIGFolder -Caption "Test01" -FolderName "/Test"

.NOTES
    

#>
[CmdletBinding()]
param ( [Parameter(Mandatory=$true)]
        [Alias('c')] 
        [string]$Caption=$null,
        [Parameter(Mandatory=$true,ParameterSetName='FolderByName')]
        [Alias('fn')] 
        [string]$FolderName=$null,
        [Parameter(Mandatory=$true,ParameterSetName='FolderByID')]
        [Alias('fid')] 
        [string]$FolderID=$null
       )
    
    
    $UriString = 'ig-folders/'
    $JSoNBody = New-Object -TypeName psobject
    $JSoNBody | Add-Member -MemberType NoteProperty -Name new-caption -Value $Caption
    if($FolderName){$UriString += ('?name=' + $FolderName)}
    if($FolderID){$UriString += $FolderID}

    $ReturnData = Invoke-RestMethod -Method Put -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders -Body ($JSoNBody | ConvertTo-Json)
    $ReturnData

} # Rename-XIOIGFolder





# Remove Functions
function Remove-XIOVolume{
<#
.SYNOPSIS
    Remove XtremIO Volume
    
.DESCRIPTION
    Remove XtremIO Volume

.PARAMETER VolID
    ID String to Remove Volume by index
        
.PARAMETER VolName
    Name String to Remove Volume by name
        
.EXAMPLE
    Remove XtremIO Volume by index
    Remove-XIOVolume -VolID 1
    
.EXAMPLE
    Remove XtremIO Volume by name    
    Remove-XIOVolume -VolName X1

.NOTES
    


#>
[CmdletBinding()]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='VolByName')]
        [Alias('n')]
        [Alias('vn')] 
        [Alias('VolName')]
        [string]$Name=$null,
        [Parameter(Mandatory=$true, 
                    ParameterSetName='VolByIndex')]
        [Alias('vid')]
        [Alias('i')]
        [Alias('VolID')] 
        [string]$ID=$null
        
)
    
    Process{
        # Remove Volume by Name
        if($Name){
            $UriString = 'volumes/'
            $UriString += ('?name=' + $Name)
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }
        
    }
    End{
        # Remove Volume by ID
        if($ID){
            $UriString = 'volumes/'
            $UriString += $ID
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }
    }

    
} # Remove-XIOVolume

function Remove-XIOVolumeFolder{
<#
.SYNOPSIS
    Remove XtremIO VolumeFolder
    
.DESCRIPTION
    Remove XtremIO VolumeFolder

.PARAMETER FolderID
    ID String to Remove Volume Folder by index
        
.PARAMETER FolderName
    Name String to Remove Volume Folder by name
        
.EXAMPLE
    Remove XtremIO Volume Folder by index
    Remove-XIOVolumeFolder -FolderID 1
    
.EXAMPLE
    Remove XtremIO Volume Folder by name    
    Remove-XIOVolumeFolder -FolderName X1

.NOTES
    


#>
[CmdletBinding()]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='FolderByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true, 
                    ParameterSetName='FolderByIndex')]
        [Alias('i')] 
        [string]$ID=$null
        
)
    
    Process{

        # Remove Volume Folders By Name
        if($Name){
            $UriString = 'volume-folders/'
            $UriString += ('?name=' + $Name)
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }

    }
    End{
        # Remove Volume Folders By ID
        if($ID){
            $UriString = 'volume-folders/'
            $UriString += $ID
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }

    }

    
     
} # Remove-XIOVolumeFolder

function Remove-XIOLunMap{
<#
.SYNOPSIS
    Remove XtremIO Lun Map
    
.DESCRIPTION
    Remove XtremIO Lun Map

.PARAMETER VolName
    Name String to Remove Lun Map by name
        
.PARAMETER ID
    ID String to Remove Lun Map by index
        
.EXAMPLE
    Remove XtremIO Lun Map by index
    Remove-XIOLunMap -ID 1
    
.EXAMPLE
    Remove XtremIO Lun Map by name    
    Remove-XIOLunMap -Name X1

.NOTES
    


#>
[CmdletBinding()]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true,
                    Position=0,
                    ParameterSetName='LMByName')]
        [Alias('n')] 
        [string]$Name=$null,
        [Parameter(Mandatory=$true, 
                    ParameterSetName='LMByIndex')]
        [Alias('i')] 
        [string]$ID=$null
)
    
    Process{
        # Remove LUN Map by Name
        if($Name){
            $UriString = 'lun-maps/'
            $UriString += ('?name=' + $Name)
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }
    }
    End{
        # Remove LUN Map by ID
        if($ID){
            $UriString = 'lun-maps/'
            $UriString += $ID
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }
    } 
    
    
    

} # Remove-XIOLunMap

function Remove-XIOSnapshot{
<#
.SYNOPSIS
    Remove XtremIO Snapshot
    
.DESCRIPTION
    Remove XtremIO Snapshot

.PARAMETER ID
    ID String to Remove Volume/Snapshot by index
        
.PARAMETER Name
    Name String to Remove Volume/Snapshot by name
        
.EXAMPLE
    Remove XtremIO Volume/Snapshot by index
    Remove-XIOSnapshot -VolID 1
    
.EXAMPLE
    Remove XtremIO Volume/Snapshot by name    
    Remove-XIOSnapshot -VolName X1

.NOTES
    


#>
[CmdletBinding()]
param ( [Parameter(Mandatory=$true, 
                    ValueFromPipeline=$true, 
                    Position=0,
                    ParameterSetName='VolByName')]
        [Alias('n')]
        [Alias('vn')] 
        [Alias('VolName')]
        [string]$Name=$null,
        [Parameter(Mandatory=$true,
                    ParameterSetName='VolByIndex')]
        [Alias('i')]
        [Alias('vid')] 
        [Alias('VolId')]
        [string]$ID=$null
        
)
    Process{
        # Remove Snapshot by Name
        if($Name){
            $UriString = 'volumes/'
            $UriString += ('?name=' + $Name)
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }
    
    }
    End{
        # Remove Snapshot by ID
        if($ID){
            $UriString = 'volumes/'
            $UriString += $ID
            Invoke-RestMethod -Method Delete -Uri ($Global:XIOAPIBaseUri + $UriString) -Headers $Global:XIOAPIHeaders
        }
    }
        
} # Remove-XIOSnapshot






Export-ModuleMember -Function New-PasswordFile
Export-ModuleMember -Function Get-PasswordFromFile
Export-ModuleMember -Function Disable-CertificateValidation
Export-ModuleMember -Function Set-XIOAPIConnectionInfo


Export-ModuleMember -Function Get-XIOAPITypes
Export-ModuleMember -Function Get-XIOItem


Export-ModuleMember -Function Get-XIOCluster
Export-ModuleMember -Function Get-XIOBrick
Export-ModuleMember -Function Get-XIOXenvs
Export-ModuleMember -Function Get-XIOVolume
Export-ModuleMember -Function Get-XIOVolumeFolder
Export-ModuleMember -Function Get-XIOStorageController
Export-ModuleMember -Function Get-XIOTargetGroup
Export-ModuleMember -Function Get-XIODataProtectionGroup
Export-ModuleMember -Function Get-XIOSnapshot
Export-ModuleMember -Function Get-XIOInitiator
Export-ModuleMember -Function Get-XIOInitiatorGroup
Export-ModuleMember -Function Get-XIOInitiatorGroupFolder
Export-ModuleMember -Function Get-XIOTarget
Export-ModuleMember -Function Get-XIOTargetGroup
Export-ModuleMember -Function Get-XIOIscsiPortal
Export-ModuleMember -Function Get-XIOIscsiRoute
Export-ModuleMember -Function Get-XIOLunMap
Export-ModuleMember -Function Get-XIOSSD


Export-ModuleMember -Function New-XIOVolume
Export-ModuleMember -Function New-XIOVolumeFolder
Export-ModuleMember -Function New-XIOLunMap
Export-ModuleMember -Function New-XIOSnapshot
Export-ModuleMember -Function New-XIOIGFolder


Export-ModuleMember -Function Rename-XIOVolumeFolder
Export-ModuleMember -Function Update-XIOVolume
Export-ModuleMember -Function Rename-XIOIGFolder


Export-ModuleMember -Function Remove-XIOVolume
Export-ModuleMember -Function Remove-XIOVolumeFolder
Export-ModuleMember -Function Remove-XIOLunMap
Export-ModuleMember -Function Remove-XIOSnapshot