@echo off
rem Enable Hyper-V components (required for WSL2, Docker Desktop, etc.)
dism /Online /Enable-Feature:Microsoft-Hyper-V-All /All /NoRestart
dism /Online /Enable-Feature:VirtualMachinePlatform /All /NoRestart
dism /Online /Enable-Feature:Windows-Hypervisor-Platform /All /NoRestart
bcdedit /set hypervisorlaunchtype auto
echo Restarting to complete changes...
shutdown /r /t 0

