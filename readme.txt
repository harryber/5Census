If on windows, administrator open git bash and run ./gen.sh

Then run: 
keytool -importcert -trustcacerts -cacerts -file server-certificate.crt -alias CS181Sy_server

Default password is changeit



On mac/linux? maybe try: ./gen2.bash
If there's any errors it probably wont work; try modifying the bash script depending on what error you get
Then you need to import the server-certificate.crt onto your JDK cacerts file (Java/jdk22/lib/security/cacerts)
keytool -importcert -trustcacerts -cacerts -file server-certificate.crt -alias CS181Sy_server

If you are getting a "PKIX path building failed", you are potentially either:
1. not properly importing the server-certificate.crt into your cacerts
2. not running with the right java version selected 