@echo off
rem Disable Hyper-V and reclaim VT-x for VirtualBox/VMware
bcdedit /set hypervisorlaunchtype off
dism /Online /Disable-Feature:Microsoft-Hyper-V-All /NoRestart
dism /Online /Disable-Feature:VirtualMachinePlatform /NoRestart
dism /Online /Disable-Feature:Windows-Hypervisor-Platform /NoRestart
echo Restarting to complete changes...
shutdown /r /t 0

