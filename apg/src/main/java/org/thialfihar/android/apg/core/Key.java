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

package org.thialfihar.android.apg.core;

import org.bouncycastle2.bcpg.sig.KeyFlags;
import org.bouncycastle2.openpgp.PGPException;
import org.bouncycastle2.openpgp.PGPPrivateKey;
import org.bouncycastle2.openpgp.PGPPublicKey;
import org.bouncycastle2.openpgp.PGPSecretKey;
import org.bouncycastle2.openpgp.PGPSignature;
import org.bouncycastle2.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle2.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle2.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import org.thialfihar.android.apg.util.IterableIterator;

import java.io.IOException;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Vector;

public class Key {
    private PGPSecretKey mSecretKey;
    private PGPPublicKey mPublicKey;

    public Key(PGPPublicKey publicKey) {
        mPublicKey = mPublicKey;
    }

    public Key(PGPSecretKey secretKey) {
        mSecretKey = mSecretKey;
        mPublicKey = mSecretKey.getPublicKey();
    }

    public PGPPublicKey getPublicKey() {
        return mPublicKey;
    }

    public PGPSecretKey getSecretKey() {
        return mSecretKey;
    }

    public boolean isPublic() {
        if (mSecretKey == null) {
            return true;
        }
        return false;
    }

    public boolean isMasterKey() {
        if (mSecretKey != null) {
            return mSecretKey.isMasterKey();
        }
        return mPublicKey.isMasterKey();
    }

    public long getKeyId() {
       return mPublicKey.getKeyID();
    }

    public Date getCreationDate() {
        return mPublicKey.getCreationTime();
    }

    public Date getExpiryDate() {
        Date creationDate = getCreationDate();
        if (mPublicKey.getValidDays() == 0) {
            // no expiry
            return null;
        }
        Calendar calendar = GregorianCalendar.getInstance();
        calendar.setTime(creationDate);
        calendar.add(Calendar.DATE, mPublicKey.getValidDays());
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

    public boolean isRevoked() {
        return mPublicKey.isRevoked();
    }

    public Vector<PGPSignature> getSignatures() {
        Vector<PGPSignature> signatures = new Vector<PGPSignature>();
        for (PGPSignature signature : new IterableIterator<PGPSignature>(mPublicKey.getSignatures())) {
            signatures.add(signature);
        }
        return signatures;
    }

    public IterableIterator<String> getUserIds() {
        return new IterableIterator<String>(mPublicKey.getUserIDs());
    }

    public String getMainUserId() {
        for (String userId : getUserIds()) {
            return userId;
        }
        return null;
    }

    public boolean isEncryptionKey() {
        if (!mPublicKey.isEncryptionKey()) {
            return false;
        }

        if (mPublicKey.getVersion() <= 3) {
            return true;
        }

        // special cases
        if (mPublicKey.getAlgorithm() == PGPPublicKey.ELGAMAL_ENCRYPT) {
            return true;
        }

        if (mPublicKey.getAlgorithm() == PGPPublicKey.RSA_ENCRYPT) {
            return true;
        }

        for (PGPSignature sig : new IterableIterator<PGPSignature>(mPublicKey.getSignatures())) {
            if (mPublicKey.isMasterKey() && sig.getKeyID() != mPublicKey.getKeyID()) {
                continue;
            }
            PGPSignatureSubpacketVector hashed = sig.getHashedSubPackets();

            if (hashed != null && (hashed.getKeyFlags() &
                                   (KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE)) != 0) {
                return true;
            }

            PGPSignatureSubpacketVector unhashed = sig.getUnhashedSubPackets();

            if (unhashed != null && (unhashed.getKeyFlags() &
                                     (KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE)) != 0) {
                return true;
            }
        }
        return false;
    }

    public boolean isSigningKey() {
        if (mPublicKey.getVersion() <= 3) {
            return true;
        }

        // special case
        if (mPublicKey.getAlgorithm() == PGPPublicKey.RSA_SIGN) {
            return true;
        }

        for (PGPSignature sig : new IterableIterator<PGPSignature>(mPublicKey.getSignatures())) {
            if (mPublicKey.isMasterKey() && sig.getKeyID() != mPublicKey.getKeyID()) {
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

    public int getAlgorithm() {
        return mPublicKey.getAlgorithm();
    }

    public int getBitStrength() {
        return mPublicKey.getBitStrength();
    }

    public String getAlgorithmInfo() {
        int algorithm = getAlgorithm();
        int keySize = getBitStrength();
        return Key.getAlgorithmInfo(algorithm, keySize);
    }

    public static String getAlgorithmInfo(int algorithm, int keySize) {
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
        byte fp[] = mPublicKey.getFingerprint();
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

    public byte[] getEncoded() throws IOException {
        if (isPublic()) {
            return mPublicKey.getEncoded();
        } else {
            return mSecretKey.getEncoded();
        }
    }

    public PGPPrivateKey extractPrivateKey(String passPhrase) throws PGPException {
        if (isPublic()) {
            return null;
        }
        PBESecretKeyDecryptor keyDecryptor =
            new JcePBESecretKeyDecryptorBuilder().setProvider(
                Constants.BOUNCY_CASTLE_PROVIDER_NAME).build(passPhrase.toCharArray());
        return extractPrivateKey(keyDecryptor);
    }

    public PGPPrivateKey extractPrivateKey(PBESecretKeyDecryptor keyDecryptor) throws PGPException {
        if (isPublic()) {
            return null;
        }
        return mSecretKey.extractPrivateKey(keyDecryptor);
    }
}
