/**
 * Copyright 2024 Sebastian Stamm
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.jsign.nuget;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.channels.Channels;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.apache.commons.io.output.NullOutputStream;
import org.apache.poi.util.IOUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.cms.CMSSignedData;

import net.jsign.DigestAlgorithm;
import net.jsign.Signable;
import net.jsign.zip.CentralDirectory;
import net.jsign.zip.ZipFile;

public class NugetFile extends ZipFile implements Signable {

	static final String SIGNATURE_FILE = ".signature.p7s";

	private static final String PROPERTIES_DOC = "Version:1\n\n%s-Hash:%s\n\n";

	public NugetFile(File file) throws IOException {
		super(file);
	}

	@Override
	public byte[] computeDigest(DigestAlgorithm digestAlgorithm) throws IOException {
		MessageDigest digest = digestAlgorithm.getMessageDigest();

		File tmp = File.createTempFile("jsign-zip-central-directory", ".bin");
		tmp.deleteOnExit();
		try (RandomAccessFile raf = new RandomAccessFile(tmp, "rw")) {
			channel.position(0);
			raf.getChannel().transferFrom(channel, 0, channel.size());
			CentralDirectory centralDirectory = new CentralDirectory();
			centralDirectory.read(raf.getChannel());

			if (centralDirectory.entries.containsKey(SIGNATURE_FILE))
				removeEntry(SIGNATURE_FILE);

			raf.getChannel().position(0);
			IOUtils.copy(Channels.newInputStream(raf.getChannel()),
					new DigestOutputStream(NullOutputStream.INSTANCE, digest));
		} finally {
			tmp.delete();
		}
		return String.format(PROPERTIES_DOC, digestAlgorithm.oid, Base64.getEncoder().encodeToString(digest.digest())).getBytes();
	}

	@Override
	public ASN1Object createIndirectData(DigestAlgorithm digestAlgorithm) throws IOException {
		throw new RuntimeException("not applicable");
	}

	@Override
	public List<CMSSignedData> getSignatures() throws IOException {
		List<CMSSignedData> signatures = new ArrayList<>();

		if (centralDirectory.entries.containsKey(SIGNATURE_FILE)) {
			InputStream in = getInputStream(SIGNATURE_FILE, 1024 * 1024 /* 1MB */);
			byte[] signatureBytes = IOUtils.toByteArray(in);

			try {
				CMSSignedData signedData = new CMSSignedData(new ASN1InputStream(signatureBytes));
				signatures.add(signedData);
			} catch (Exception | StackOverflowError e) {
				e.printStackTrace();
			}
		}
		return signatures;
	}

	@Override
	public void setSignature(CMSSignedData signature) throws IOException {
		if (centralDirectory.entries.containsKey(SIGNATURE_FILE)) {
			removeEntry(SIGNATURE_FILE);
		}

		if (signature != null) {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			signature.toASN1Structure().encodeTo(out, "DER");
			addEntry(SIGNATURE_FILE, out.toByteArray(), false);
		}
	}

	@Override
	public void save() throws IOException {
		// nothing to do
	}

	public static boolean isNugetFile(String fileName) {
		return fileName.matches("(?i).*\\.nupkg$");
	}

}
