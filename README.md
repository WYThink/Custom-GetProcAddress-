# Custom-GetProcAddress()
This is the Custom Implementation of The GetProcAddress() function in Windows API 

# Explanation
For Those who dont know what is GetProcAddress() , let me explain you

GetProcAddress() is a function in Windows-API , which is defined in kernel32.dll file , 
It is used to find the function Address of any functions which is defined in kernel32.dll or any other DLL files
We just need to pass the DLL Handle and the Name of the Function we are looking for 

# Use of GetProcAddress()
All Malwares use there own custom version GetProcAddress() function to hide there function name , using an Custom Implementation of GetProcAddress()
AV Engines look for PE Import Directory , to find and check the Windows-API Function and AV Engines also has a list of Windows-API functions which when
used together it will alert it and mark the file has malicious and remove it (is called Static-Analysis)

So to Bypass AV Engine Static Analysis and to also Hide Windows-API Functions , Malware Developers write there own Custom Implementation of GetProcAddress()
