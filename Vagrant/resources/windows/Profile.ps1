$atomicModule = 'C:\Tools\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1'
if (Test-Path $atomicModule) {
  try {
    Import-Module $atomicModule -Force -ErrorAction Stop
  } catch {
    Write-Verbose ("Invoke-AtomicRedTeam module at {0} failed to load: {1}" -f $atomicModule, $_.Exception.Message)
  }
  $PSDefaultParameterValues['Invoke-AtomicTest:PathToAtomicsFolder'] = 'C:\Tools\AtomicRedTeam\atomics'
}
