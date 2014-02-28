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

import org.bouncycastle2.openpgp.PGPPublicKey;
import org.bouncycastle2.openpgp.PGPPublicKeyRing;
import org.bouncycastle2.openpgp.PGPSecretKey;
import org.bouncycastle2.openpgp.PGPSecretKeyRing;

import org.thialfihar.android.apg.utils.IterableIterator;

import java.io.IOException;
import java.util.Vector;

public class KeyRing {
    private PGPSecretKeyRing mSecretKeyRing;
    private PGPPublicKeyRing mPublicKeyRing;

    public KeyRing(PGPPublicKeyRing publicKeyRing) {
        mPublicKeyRing = mPublicKeyRing;
    }

    public KeyRing(PGPSecretKeyRing secretKeyRing) {
        mSecretKeyRing = mSecretKeyRing;
    }

    public boolean isPublic() {
        if (mPublicKeyRing != null) {
            return true;
        }
        return false;
    }

    public Key getSecretKey(long keyId) {
        if (isPublic()) {
            return null;
        }
        return new Key(mSecretKeyRing.getSecretKey(keyId));
    }

    public Key getPublicKey(long keyId) {
        return new Key(mPublicKeyRing.getPublicKey(keyId));
    }

    public byte[] getEncoded() throws IOException {
        if (isPublic()) {
            return mPublicKeyRing.getEncoded();
        }
        return mSecretKeyRing.getEncoded();
    }

    public Vector<Key> getPublicKeys() {
        Vector<Key> keys = new Vector<Key>();
        for (PGPPublicKey key : new IterableIterator<PGPPublicKey>(mPublicKeyRing.getPublicKeys())) {
            keys.add(new Key(key));
        }
        return keys;
    }

    public Vector<Key> getSecretKeys() {
        Vector<Key> keys = new Vector<Key>();
        if (isPublic()) {
            return keys;
        }
        for (PGPSecretKey key : new IterableIterator<PGPSecretKey>(mSecretKeyRing.getSecretKeys())) {
            keys.add(new Key(key));
        }
        return keys;
    }

    public Key getMasterKey() {
        if (isPublic()) {
            for (Key key : getPublicKeys()) {
                if (key.isMasterKey()) {
                    return key;
                }
            }

            return null;
        } else {
            for (Key key : getSecretKeys()) {
                if (key.isMasterKey()) {
                    return key;
                }
            }

            return null;
        }
    }

    public Vector<Key> getEncryptKeys() {
        Vector<Key> encryptKeys = new Vector<Key>();
        for (Key key : getPublicKeys()) {
            if (key.isEncryptionKey()) {
                encryptKeys.add(key);
            }
        }

        return encryptKeys;
    }

    public Vector<Key> getSigningKeys() {
        Vector<Key> signingKeys = new Vector<Key>();
        for (Key key : getSecretKeys()) {
            if (key.isSigningKey()) {
                signingKeys.add(key);
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
        Vector<Key> signingKeys = getSigningKeys();
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
