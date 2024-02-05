package net.jsign.nuget;

import static net.jsign.DigestAlgorithm.SHA256;
import static net.jsign.SignatureAssert.assertNotSigned;
import static net.jsign.SignatureAssert.assertSigned;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.security.KeyStore;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import net.jsign.AuthenticodeSigner;
import net.jsign.KeyStoreBuilder;
import net.jsign.Signable;

public class NugetFileTest {

	private static final String SIGNED_FILE = "target/test-classes/nuget/testcontainers.3.3.0.nupkg";
	private static final String UNSIGNED_FILE = "target/test-classes/nuget/testcontainers_no_sig.3.3.0.nupkg";

	@Test
	public void testGetSignaturesFromUnsignedPackage() throws Exception {
		try (Signable file = new NugetFile(new File(UNSIGNED_FILE))) {
			assertTrue("signature found", file.getSignatures().isEmpty());
		}
	}

	@Test
	public void testGetSignaturesFromSignedPackage() throws Exception {
		try (Signable file = new NugetFile(new File(SIGNED_FILE))) {
			assertFalse("no signature found", file.getSignatures().isEmpty());
		}
	}

	@Test
	public void testRemoveSignature() throws Exception {
		File sourceFile = new File(SIGNED_FILE);
		File targetFile = new File("target/test-classes/nuget/testcontainers_test.3.3.0.nupk");

		FileUtils.copyFile(sourceFile, targetFile);

		KeyStore keystore = new KeyStoreBuilder().keystore("target/test-classes/keystores/keystore.jks")
				.storepass("password").build();
		AuthenticodeSigner signer = new AuthenticodeSigner(keystore, "test", "password").withTimestamping(false);

		try (Signable file = new NugetFile(targetFile)) {
			file.setSignature(null);
			signer.sign(file);
			assertSigned(file, SHA256);
			file.setSignature(null);
			assertNotSigned(file);
		}
	}
}
