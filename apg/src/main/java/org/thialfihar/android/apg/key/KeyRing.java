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

public class KeyRing {
    private PGPSecretKeyRing secretKeyRing;
    private PGPPublicKeyRing publicKeyRing;

    public KeyRing(PGPPublicKeyRing publicKeyRing) {
        this.publicKeyRing = publicKeyRing;
    }

    public KeyRing(PGPSecretKeyRing secretKeyRing) {
        this.secretKeyRing = secretKeyRing;
    }

    public boolean isPublic() {
        if (publicKeyRing != null) {
            return true;
        }
        return false;
    }

    public Key getMasterKey() {
        if (isPublic()) {
            for (PGPPublicKey key : new IterableIterator<PGPPublicKey>(publicKeyRing.getPublicKeys())) {
                if (key.isMasterKey()) {
                    return Key(key);
                }
            }

            return null;
        } else {
            for (PGPSecretKey key : new IterableIterator<PGPSecretKey>(secretKeyRing.getSecretKeys())) {
                if (key.isMasterKey()) {
                    return Key(key);
                }
            }

            return null;
        }
    }

    public Vector<Key> getEncryptKeys() {
        Vector<Key> encryptKeys = new Vector<Key>();
        if (publicKeyRing == null) {
            return encryptKeys;
        }

        for (PGPPublicKey key : new IterableIterator<PGPPublicKey>(publicKeyRing.getPublicKeys())) {
            if (isEncryptionKey(key)) {
                encryptKeys.add(Key(key));
            }
        }

        return encryptKeys;
    }

    public Vector<Key> getSigningKeys() {
        Vector<Key> signingKeys = new Vector<Key>();
        if (secretKeyRing == null) {
            return signingKeys;
        }

        for (PGPSecretKey key : new IterableIterator<PGPSecretKey>(secretKeyRing.getSecretKeys())) {
            if (isSigningKey(key)) {
                signingKeys.add(Key(key));
            }
        }

        return signingKeys;
    }

    public Vector<Key> getUsableEncryptKeys() {
        Vector<Key> usableKeys = new Vector<Key>();
        Vector<Key> encryptKeys = getEncryptKeys();
        Key masterKey = null;
        for (int i = 0; i < encryptKeys.size(); ++i) {
            Key key = encryptKeys.get(i);
            if (!key.isExpired()) {
                if (key.isMasterKey()) {
                    masterKey = key;
                } else {
                    usableKeys.add(key);
                }
            }
        }
        if (masterKey != null) {
            usableKeys.add(masterKey);
        }
        return usableKeys;
    }

    public Vector<Key> getUsableSigningKeys() {
        Vector<Key> usableKeys = new Vector<Key>();
        Vector<Key> signingKeys = getSigningKeys(keyRing);
        Key masterKey = null;
        for (int i = 0; i < signingKeys.size(); ++i) {
            Key key = signingKeys.get(i);
            if (key.isMasterKey()) {
                masterKey = key;
            } else {
                usableKeys.add(key);
            }
        }
        if (masterKey != null) {
            usableKeys.add(masterKey);
        }
        return usableKeys;
    }
}
