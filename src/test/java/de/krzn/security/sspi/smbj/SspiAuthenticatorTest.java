package de.krzn.security.sspi.smbj;

import java.io.IOException;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.hierynomus.msfscc.fileinformation.ShareInfo;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;

public class SspiAuthenticatorTest {
	
	private static String SMB_SERVER;
	
	@BeforeClass
	public static void prepare() {
		SMB_SERVER = System.getenv("LOGONSERVER");
		Assert.assertNotNull("Environment variable LOGONSERVER is not set", SMB_SERVER);
		if (SMB_SERVER.startsWith("\\\\"))
			SMB_SERVER = SMB_SERVER.substring(2);
	}
	
	@Test
	public void test() throws IOException {
	    SmbConfig config = SmbConfig.builder()
	            .withAuthenticators(new SspiAuthenticator.Factory())
	            .build();

	    try (SspiAuthenticationContext ac = new SspiAuthenticationContext()) {
		    try (SMBClient client = new SMBClient(config)) {
			    try (Connection connection = client.connect(SMB_SERVER)) {
			        try (Session session = connection.authenticate(ac)) {
			        	try (DiskShare share = (DiskShare) session.connectShare("NETLOGON")) {
			        		ShareInfo info = share.getShareInformation();
			        		Assert.assertNotNull("Failed to get share info", info);
			        	}
			        }
			    }
		    }
	    }
	}
}
