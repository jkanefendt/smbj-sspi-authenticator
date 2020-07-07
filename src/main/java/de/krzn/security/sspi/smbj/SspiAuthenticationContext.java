package de.krzn.security.sspi.smbj;

import java.io.Closeable;
import java.io.IOException;

import com.hierynomus.smbj.auth.AuthenticationContext;
import com.sun.jna.platform.win32.Secur32;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.Sspi.CredHandle;
import com.sun.jna.platform.win32.Sspi.CtxtHandle;
import com.sun.jna.platform.win32.Sspi.TimeStamp;
import com.sun.jna.platform.win32.W32Errors;

public class SspiAuthenticationContext extends AuthenticationContext implements Closeable {

	CredHandle clientCredentials;
	int contextReq;
	CtxtHandle sspiContext = null;
	String spn = null;
	boolean authenticated = false;
	
	public SspiAuthenticationContext(String spn) {
		super("", new char[0], null);
		
		TimeStamp timeStamp = new TimeStamp();
		clientCredentials = new CredHandle();
		int rc = Secur32.INSTANCE.AcquireCredentialsHandle(null, "Kerberos", Sspi.SECPKG_CRED_OUTBOUND, 
				null, null, null, null, clientCredentials, timeStamp);
		
		if (rc != W32Errors.SEC_E_OK)
			throw new RuntimeException("AcquireCredentialsHandle failed with " + rc);
		
		contextReq = Sspi.ISC_REQ_INTEGRITY;
		this.spn = spn;
	}
	
	public SspiAuthenticationContext() {
		this(null);
	}

	public void closeHandles() {
		if (clientCredentials != null) {
			Secur32.INSTANCE.FreeCredentialsHandle(clientCredentials);
			clientCredentials = null;
		}
		if (sspiContext != null) {
			Secur32.INSTANCE.DeleteSecurityContext(sspiContext);
			sspiContext = null;
		}
	}

	public void close() throws IOException {
		closeHandles();
	}
	
}
