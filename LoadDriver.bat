dsefix.exe
sc create KMMM binPath="C:\Path\To\\KMMM.sys" type=kernel
sc start KMMM
timeout /t 5
dsefix.exe -e
pause
sc stop KMMM
sc delete KMMM
pause