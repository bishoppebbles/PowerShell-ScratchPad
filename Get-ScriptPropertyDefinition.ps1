(Get-PhysicalDisk | Get-Member | Where-Object Name -eq 'OperationalStatus').Definition

(Get-PhysicalDisk | Get-Member | Where-Object Name -eq 'BusType').Definition
