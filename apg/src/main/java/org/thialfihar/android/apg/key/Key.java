/*
 * Copyright (C) 2010 Thialfihar <thi@thialfihar.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.thialfihar.android.apg.key;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Vector;
import java.util.regex.Pattern;

import org.bouncycastle2.bcpg.ArmoredInputStream;
import org.bouncycastle2.bcpg.ArmoredOutputStream;
import org.bouncycastle2.bcpg.BCPGOutputStream;
import org.bouncycastle2.bcpg.CompressionAlgorithmTags;
import org.bouncycastle2.bcpg.HashAlgorithmTags;
import org.bouncycastle2.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle2.bcpg.sig.KeyFlags;
import org.bouncycastle2.jce.provider.BouncyCastleProvider;
import org.bouncycastle2.jce.spec.ElGamalParameterSpec;
import org.bouncycastle2.openpgp.PGPCompressedData;
import org.bouncycastle2.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle2.openpgp.PGPEncryptedData;
import org.bouncycastle2.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle2.openpgp.PGPEncryptedDataList;
import org.bouncycastle2.openpgp.PGPException;
import org.bouncycastle2.openpgp.PGPKeyPair;
import org.bouncycastle2.openpgp.PGPKeyRingGenerator;
import org.bouncycastle2.openpgp.PGPLiteralData;
import org.bouncycastle2.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle2.openpgp.PGPObjectFactory;
import org.bouncycastle2.openpgp.PGPOnePassSignature;
import org.bouncycastle2.openpgp.PGPOnePassSignatureList;
import org.bouncycastle2.openpgp.PGPPBEEncryptedData;
import org.bouncycastle2.openpgp.PGPPrivateKey;
import org.bouncycastle2.openpgp.PGPPublicKey;
import org.bouncycastle2.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle2.openpgp.PGPPublicKeyRing;
import org.bouncycastle2.openpgp.PGPSecretKey;
import org.bouncycastle2.openpgp.PGPSecretKeyRing;
import org.bouncycastle2.openpgp.PGPSignature;
import org.bouncycastle2.openpgp.PGPSignatureGenerator;
import org.bouncycastle2.openpgp.PGPSignatureList;
import org.bouncycastle2.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle2.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle2.openpgp.PGPUtil;
import org.bouncycastle2.openpgp.PGPV3SignatureGenerator;
import org.thialfihar.android.apg.provider.DataProvider;
import org.thialfihar.android.apg.provider.Database;
import org.thialfihar.android.apg.provider.KeyRings;
import org.thialfihar.android.apg.provider.Keys;
import org.thialfihar.android.apg.provider.UserIds;
import org.thialfihar.android.apg.ui.widget.KeyEditor;
import org.thialfihar.android.apg.ui.widget.SectionView;
import org.thialfihar.android.apg.ui.widget.UserIdEditor;
import org.thialfihar.android.apg.utils.IterableIterator;
import org.thialfihar.android.apg.utils.PrngFixes;

public class Key {
    private PGPSecretKey secretKey;
    private PGPPublicKey publicKey;

    public Key(PGPPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public Key(PGPSecretKey secretKey) {
        this.secretKey = secretKey;
        this.publicKey = secretKey.getPublicKey();
    }

    public boolean isPublic() {
        if (secretKey == null) {
            return true;
        }
        return false;
    }

    public boolean isMasterKey() {
        if (secretKey != null) {
            return secretKey.isMasterKey();
        }
        return publicKey.isMasterKey();
    }

    public Date getCreationDate() {
        return publicKey.getCreationTime();
    }

    public Date getExpiryDate() {
        Date creationDate = getCreationDate();
        if (publicKey.getValidDays() == 0) {
            // no expiry
            return null;
        }
        Calendar calendar = GregorianCalendar.getInstance();
        calendar.setTime(creationDate);
        calendar.add(Calendar.DATE, key.getValidDays());
        Date expiryDate = calendar.getTime();

        return expiryDate;
    }

    public boolean isExpired() {
        Date creationDate = getCreationDate();
        Date expiryDate = getExpiryDate();
        Date now = new Date();
        if (now.compareTo(creationDate) >= 0 &&
            (expiryDate == null || now.compareTo(expiryDate) <= 0)) {
            return false;
        }
        return true;
    }

    public String getMainUserId() {
        for (String userId : new IterableIterator<String>(publicKey.getUserIDs())) {
            return userId;
        }
        return null;
    }


    public boolean isEncryptionKey() {
        if (!publicKey.isEncryptionKey()) {
            return false;
        }

        if (publicKey.getVersion() <= 3) {
            return true;
        }

        // special cases
        if (publicKey.getAlgorithm() == PGPPublicKey.ELGAMAL_ENCRYPT) {
            return true;
        }

        if (publicKey.getAlgorithm() == PGPPublicKey.RSA_ENCRYPT) {
            return true;
        }

        for (PGPSignature sig : new IterableIterator<PGPSignature>(publicKey.getSignatures())) {
            if (publicKey.isMasterKey() && sig.getKeyID() != publicKey.getKeyID()) {
                continue;
            }
            PGPSignatureSubpacketVector hashed = sig.getHashedSubPackets();

            if (hashed != null &&(hashed.getKeyFlags() &
                                  (KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE)) != 0) {
                return true;
            }

            PGPSignatureSubpacketVector unhashed = sig.getUnhashedSubPackets();

            if (unhashed != null &&(unhashed.getKeyFlags() &
                                  (KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE)) != 0) {
                return true;
            }
        }
        return false;
    }

    public boolean isSigningKey() {
        if (publicKey.getVersion() <= 3) {
            return true;
        }

        // special case
        if (publicKey.getAlgorithm() == PGPPublicKey.RSA_SIGN) {
            return true;
        }

        for (PGPSignature sig : new IterableIterator<PGPSignature>(publicKey.getSignatures())) {
            if (publicKey.isMasterKey() && sig.getKeyID() != publicKey.getKeyID()) {
                continue;
            }
            PGPSignatureSubpacketVector hashed = sig.getHashedSubPackets();

            if (hashed != null && (hashed.getKeyFlags() & KeyFlags.SIGN_DATA) != 0) {
                return true;
            }

            PGPSignatureSubpacketVector unhashed = sig.getUnhashedSubPackets();

            if (unhashed != null && (unhashed.getKeyFlags() & KeyFlags.SIGN_DATA) != 0) {
                return true;
            }
        }

        return false;
    }

    public String getAlgorithmInfo() {
        int algorithm = publicKey.getAlgorithm();
        int keySize = publicKey.getBitStrength());
        String algorithmStr = null;

        switch (algorithm) {
            case PGPPublicKey.RSA_ENCRYPT:
            case PGPPublicKey.RSA_GENERAL:
            case PGPPublicKey.RSA_SIGN: {
                algorithmStr = "RSA";
                break;
            }

            case PGPPublicKey.DSA: {
                algorithmStr = "DSA";
                break;
            }

            case PGPPublicKey.ELGAMAL_ENCRYPT:
            case PGPPublicKey.ELGAMAL_GENERAL: {
                algorithmStr = "ElGamal";
                break;
            }

            default: {
                algorithmStr = "???";
                break;
            }
        }
        return algorithmStr + ", " + keySize + "bit";
    }

    public String getFingerprint() {
        String fingerprint = "";
        byte fp[] = publicKey.getFingerprint();
        for (int i = 0; i < fp.length; ++i) {
            if (i != 0 && i % 10 == 0) {
                fingerprint += "  ";
            } else if (i != 0 && i % 2 == 0) {
                fingerprint += " ";
            }
            String chunk = Integer.toHexString((fp[i] + 256) % 256).toUpperCase();
            while (chunk.length() < 2) {
                chunk = "0" + chunk;
            }
            fingerprint += chunk;
        }

        return fingerprint;
    }

}
