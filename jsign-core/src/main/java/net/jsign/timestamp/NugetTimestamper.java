package net.jsign.timestamp;

import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;

public class NugetTimestamper extends RFC3161Timestamper {

    public NugetTimestamper() {
        super();
        setEncapsulteSignature(true);
    }

    @Override
    protected Attribute getCounterSignature(CMSSignedData token) {
        return new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, new DERSet(token.toASN1Structure()));
    }

}
