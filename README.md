# Oracle TNS Listener Remote Poisoning
Based on the work published here: http://seclists.org/fulldisclosure/2012/Apr/204

##How to check for this vulnerability

Execute “check_tns_poison.py” with the following command-line arguments:

Target Host: IP address or Hostname of target

Target Port: Port number running Oracle TNS Listener
```
Usage:   python check_tns_poison.py <target_host> <target_port>
Example: python check_tns_poison.py 10.0.0.17 1521
```


##Screenshots

![img3](https://cloud.githubusercontent.com/assets/5358495/16176989/3a6eb6ae-363d-11e6-8a48-8e159fef6a79.png)

![img2](https://cloud.githubusercontent.com/assets/5358495/16176284/33fb8a6e-3628-11e6-9530-af5b72ae4402.png)
