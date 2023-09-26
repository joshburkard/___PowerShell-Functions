#region declaration
    $Scope = 'CurrentUser'
    $Scope = 'AllUsers'
    $ModuleName = 'PSWindowsUpdate'
    $ParentPath = 'C:\Temp'
    $LocalPath = Join-Path -Path $ParentPath -ChildPath $ModuleName
#endregion declaration

#region download module to local path
    if ( -not ( Test-Path -Path $ParentPath ) ) {
        New-Item -Path $ParentPath -ItemType Directory
    }
    if ( Test-Path -Path $LocalPath ) {
        Remove-Item -Path $LocalPath -Recurse -Confirm:$false -Force
    }
    Save-Module PSWindowsUpdate -Path $ParentPath -Force -Confirm:$false
#endregion download module to local path

#region install module from local path
    $UserProfileRequex = $env:USERPROFILE -replace '\\', '\\'
    if ( $Scope -eq 'AllUsers' ) {
        $PSModulePath = @( ( $env:PSModulePath -split ';' ) | Where-Object { $_ -notmatch $UserProfileRequex } )[0]
    }
    else {
        $PSModulePath = @( ( $env:PSModulePath -split ';' ) | Where-Object { $_ -match $UserProfileRequex } )[0]
    }

    Copy-Item -Path $LocalPath -Destination $PSModulePath -Recurse -Force
#endregion install module from local path