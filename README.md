# smbj-sspi-authenticator
GSS-Authentication for smbj using Windows SSPI via JNA.

## Usage
````java
SmbConfig config = SmbConfig.builder()
   .withAuthenticators(new SspiAuthenticator.Factory())
   .build();
              
SMBClient client = new SMBClient(config);
Connection connection = client.connect("SMBSERVER");
      
SspiAuthenticationContext ac = new SspiAuthenticationContext():
Session session = connection.authenticate(ac);
DiskShare share = (DiskShare) session.connectShare("NETLOGON");      
````

## Limitations
* No support for SMB3 encryption yet, only SMB2 signing using the SSPI session key  
