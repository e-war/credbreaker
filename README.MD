# CREDBREAKER
A python program made for linux to extract dumped windows browser cookies / passwords encrypted with AES + DPAPI.
This tool is in the context of a physical penetration test, having dumped an end user's cookie, login data file and the raw byte encryption key from DPAPI.

Rename the paths at the top of the python file for the chrome/edge cookie, login data, and keyfile.
The keyfile should be aquired by the same user as the data belongs to via powershell using the [System.Security.Cryptography.ProtectedData]::Unprotect() and [System.Security.Cryptography.DataProtectionScope]::CurrentUser options on the base64 decoded key from the browsers local state file. Without this decryption is unavaliable. 