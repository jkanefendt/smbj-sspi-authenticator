package de.krzn.security.sspi.smbj;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import com.hierynomus.mssmb2.SMB2Header;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticateResponse;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.auth.Authenticator;
import com.hierynomus.smbj.session.Session;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.Secur32;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.Sspi.CtxtHandle;
import com.sun.jna.platform.win32.Sspi.SecBufferDesc;
import com.sun.jna.platform.win32.Sspi.TimeStamp;
import com.sun.jna.platform.win32.W32Errors;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.W32APITypeMapper;

public class SspiAuthenticator implements Authenticator {

    public static class Factory implements com.hierynomus.protocol.commons.Factory.Named<Authenticator> {
        public SspiAuthenticator create() {
            return new SspiAuthenticator();
        }

		public String getName() {
			 return "1.3.6.1.4.1.311.2.2.30";
		}
    }
    
	public AuthenticateResponse authenticate(AuthenticationContext context, byte[] challenge, Session session) throws IOException {
		SspiAuthenticationContext c = (SspiAuthenticationContext) context;

		if (c.clientCredentials == null)
			return null;
		
		if (c.spn == null) 
			c.spn = "cifs/" + session.getConnection().getRemoteHostname();
		
		SecBufferDesc clientToken = challenge == null || challenge.length == 0 ? null
				: new SecBufferDesc(Sspi.SECBUFFER_TOKEN, challenge);
		
		SecBufferDesc serverToken = new SecBufferDesc(Sspi.SECBUFFER_TOKEN, Sspi.MAX_TOKEN_SIZE);
		TimeStamp timeStamp = new TimeStamp();
		IntByReference pfClientContextAttr = new IntByReference();
		CtxtHandle newSspiContext = new CtxtHandle();

		int rc = Secur32.INSTANCE.InitializeSecurityContext(c.clientCredentials, c.sspiContext, c.spn, c.contextReq, 0,
				Sspi.SECURITY_NATIVE_DREP, clientToken, 0, newSspiContext, serverToken, pfClientContextAttr, timeStamp);		
		
		if (rc != W32Errors.SEC_E_OK && rc != W32Errors.SEC_I_CONTINUE_NEEDED) {
			c.closeHandles();
			throw new RuntimeException(String.format("InitializeSecurityContext failed with 0x%08X", rc));
		}	
		
		if (c.sspiContext != null)
			Secur32.INSTANCE.DeleteSecurityContext(c.sspiContext);
		c.sspiContext = newSspiContext;
		
		AuthenticateResponse response = new AuthenticateResponse(serverToken.getBytes());
		
		if (rc == W32Errors.SEC_E_OK) {
			byte[] sessionKey = getSspiSessionKey(c.sspiContext);
			if (sessionKey.length > SMB2Header.SIGNATURE_SIZE)
				sessionKey = Arrays.copyOfRange(sessionKey, 0, SMB2Header.SIGNATURE_SIZE);
			response.setSigningKey(sessionKey);			
			c.closeHandles();
		}	

		return response;
	}
	
    public static class SecPkgContext_SessionKey extends Structure {

		private static final List<String> fieldOrder = Arrays.asList(new String[] {"SessionKeyLength", "SessionKey"});
    	
        public static class ByReference extends SecPkgContext_SessionKey implements Structure.ByReference {

        }

        /**
         * Size, in bytes, of the session key.
         */
        public int SessionKeyLength;

        /**
         * The session key for the security context.
         */
        public Pointer SessionKey;

        public SecPkgContext_SessionKey() {
            super(W32APITypeMapper.DEFAULT);
        }

        public byte[] getSessionKey() {
            if(SessionKey == null) {
                return null;
            }
            return SessionKey.getByteArray(0, SessionKeyLength);
        }

        public synchronized void free() {
            if(SessionKey != null) {
                Secur32.INSTANCE.FreeContextBuffer(SessionKey);
                SessionKey = null;
            }
        }

		@Override
		protected List<String> getFieldOrder() {
			return fieldOrder;
		}
    }
    
    public static final int SECPKG_ATTR_SESSION_KEY = 9;
	
	private static byte[] getSspiSessionKey(CtxtHandle newSspiContext) {
		SecPkgContext_SessionKey sessionKey = new SecPkgContext_SessionKey();
		int rc = Secur32.INSTANCE.QueryContextAttributes(newSspiContext, SECPKG_ATTR_SESSION_KEY, sessionKey);
		if (rc != W32Errors.SEC_E_OK) {
			throw new RuntimeException(String.format("QueryContextAttributes failed with 0x%08X", rc));
		}
		return sessionKey.getSessionKey();
	}

	public void init(SmbConfig config) {
	}

	public boolean supports(AuthenticationContext context) {
		return context.getClass().equals(SspiAuthenticationContext.class);
	}

}
