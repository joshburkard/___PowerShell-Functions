$Path = 'C:\Users\josh'

$cis = Get-ChildItem -Path $Path -Recurse
$ci = $cis | out-gridview -PassThru
$cise = $cis | Where-Object { $_.Attributes -match 'Encrypted' }
$cise.count
$ci
$acl = Get-Acl -Path $ci.FullName
$ci.Attributes -match 'Encrypted'
$acl.Owner