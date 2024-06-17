Function Convert-SQLDatetime {
    Param (
        $Date = $(Get-Date)
        ,

        [ValidateSet('DateTime-to-SQL', 'SQL-to-DateTime')]
        [string]$ConvertType = 'DateTime-to-SQL'
    )
    switch ( $ConvertType ) {
        'DateTime-to-SQL' {
            # $DT = ( Get-Date -Date $Date ).ToUniversalTime()
            $DT = ( Get-Date -Date $Date )
            $DateTime2 = $DT.Year.ToString()
            $DateTime2 += $DT.Month.ToString().PadLeft(2, '0')
            $DateTime2 += $DT.Day.ToString().PadLeft(2, '0')
            $DateTime2 += $DT.TimeOfDay.ToString() -replace ':', ''
            $DateTime2 += '+000'
            return $DateTime2
        }
        'SQL-to-DateTime' {
            get-date  $date -Format "yyyy-MM-ddTHH\\:mm\\:ss.fffffffzzz"
            $DateArgs = @{
                Year  = $Date.Substring(0,4)
                Month = $Date.Substring(4,2)
                Day   = $Date.Substring(6,2)
                Hour  = $Date.Substring(8,2)
                Minute = $Date.Substring(10,2)
                Second = $Date.Substring(12,2)
                Millisecond = $Date.Substring(15,3)
            }
            $newDate = Get-Date @DateArgs
            return $newDate
        }
    }
}