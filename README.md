# virustotal
Script Python using API VirusTotal to check file.

## Dependencies

Using the VirusTotal API in Python : 
https://github.com/blacktop/virustotal-api

## Focus

### API Key

The key must be give by a file with the -a or --api argument or api.key in the script directory by default.

### Return codes

Note that the script exit with a return code egal to the positive results.
So if the exit code is not egal to 0, there is a problem :

* 252 : Not know but larger than 32MB.
* 253 : Queued
* 254 : Other ?
* 255 : Other ?

## Examples of use

```bash
root@kali:~# for i in /root/Downloads/*; do virustotal_check.py --file $i; sleep $((60/4)); done
Tested the 2016-04-27 16:41:35. Get 0 positives results on 56 (/root/Downloads/Malware.pdf)
Tested the 2016-05-08 17:22:36. Get 0 positives results on 56 (/root/Downloads/Networks.pdf)
Tested the 2016-04-27 16:41:52. Get 0 positives results on 56 (/root/Downloads/Web.pdf)
/root/Downloads/Webservers.zip
Scan request successfully queued, come back later for the report
For details : https://www.virustotal.com/file/c0c5f31dfd9c9e119e237f70849f5f00cea24df431d40e32db51f320b00c528f/analysis/1466068339/ 
root@kali:~# virustotal_check.py --file /root/Downloads/Webservers.zip 
Scan request successfully queued, come back later for the report
For details : https://www.virustotal.com/file/c0c5f31dfd9c9e119e237f70849f5f00cea24df431d40e32db51f320b00c528f/analysis/1466068339/ 
root@kali:~# sleep $((5*60)); virustotal_check.py --file /root/Downloads/Webservers.zip
Tested the 2016-06-16 09:12:19. Get 2 positives results on 55 (/root/Downloads/Webservers.zip)
For details : https://www.virustotal.com/file/c0c5f31dfd9c9e119e237f70849f5f00cea24df431d40e32db51f320b00c528f/analysis/1466068339/ 
root@kali:~# 
```
