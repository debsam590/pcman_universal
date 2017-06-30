# pcman_universal
Universal PCManFTPD2 2.0.7 Buffer Overflow Exploit - Metasploit
For Windows 7 64 bit

This Metasploit exploit allows the input of parameters to change the type of FTP command and offset.
This allows any FTP command and any payload to exploit the PCManFTPD2 2.0.7 Buffer Overflow.

The following options can be set: -

FTPCOMMAND
OFFSET

Once the initial offset for the USER command is known, any other command's offset (except PASS) can be calculated as follows: -
     Add 10 bytes to the USER offset.
     Subtract the length of the command.

e.g. The offset for USER is 2000.
     The length of the PUT command is 3 therefore the offset for the PUT command is 2007.
     The length of the RENAME command is 6 therefore the offset for the RENAME command is 2004
     
The PASS command is different in that the offset is 6102 in Windows 7.

The exploit utilises a JMP ESP in SHELL32.dll which is located at '0x75e55d3f'

