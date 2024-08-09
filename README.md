Generating keys (public.pem and private.pem): 
> C:\Program Files\OpenSSL-Win64\start [Windows Batch File]
> cd into project directory (such as src/main/resources/cert)
> Commands ran:
- openssl genrsa -out keypair.pem 2048
- openssl rsa -in keypair.pem -pubout -out public.pem
- openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out private.pem
