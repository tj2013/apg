/*
 * Copyright (C) 2012-2013 Dominik Schürmann <dominik@dominikschuermann.de>
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

package org.thialfihar.android.apg.provider;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;

import org.thialfihar.android.apg.core.Key;
import org.thialfihar.android.apg.core.KeyProvider;
import org.thialfihar.android.apg.core.KeyRing;
import org.thialfihar.android.apg.provider.KeychainContract.KeyRings;

public class ProviderHelper implements KeyProvider {
    private Context mContext;

    public ProviderHelper(Context context) {
        mContext = context;
    }

    /**
     * Private helper method to get KeyRing from database
     */
    private KeyRing getKeyRing(Uri queryUri) {
        Cursor cursor = mContext.getContentResolver().query(queryUri,
                new String[] {KeyRings._ID, KeyRings.KEY_RING_DATA}, null, null, null);

        KeyRing keyRing = null;
        if (cursor != null && cursor.moveToFirst()) {
            int keyRingDataCol = cursor.getColumnIndex(KeyRings.KEY_RING_DATA);

            byte[] data = cursor.getBlob(keyRingDataCol);
            if (data != null) {
                keyRing = KeyRing.decode(data);
            }
        }

        if (cursor != null) {
            cursor.close();
        }

        return keyRing;
    }

    /**
     * Retrieves the actual KeyRing object from the database blob based on the rowId
     */
    public KeyRing getPublicKeyRingByRowId(long rowId) {
        Uri queryUri = KeyRings.buildPublicKeyRingsUri(Long.toString(rowId));
        return getKeyRing(queryUri);
    }

    /**
     * Retrieves the actual KeyRing object from the database blob based on the maserKeyId
     */
    public KeyRing getPublicKeyRingByMasterKeyId(long masterKeyId) {
        Uri queryUri = KeyRings.buildPublicKeyRingsByMasterKeyIdUri(Long.toString(masterKeyId));
        return getKeyRing(queryUri);
    }

    /**
     * Retrieves the actual KeyRing object from the database blob associated with a key
     * with this keyId
     */
    public KeyRing getPublicKeyRingByKeyId(long keyId) {
        Uri queryUri = KeyRings.buildPublicKeyRingsByKeyIdUri(Long.toString(keyId));
        return getKeyRing(queryUri);
    }

    /**
     * Retrieves the actual Key object from the database blob associated with a key with
     * this keyId
     */
    public Key getPublicKeyByKeyId(long keyId) {
        KeyRing keyRing = getPublicKeyRingByKeyId(keyId);
        if (keyRing == null) {
            return null;
        }

        return keyRing.getPublicKey(keyId);
    }

    /**
     * Retrieves the actual secret KeyRing object from the database blob based on the rowId
     */
    public KeyRing getSecretKeyRingByRowId(long rowId) {
        Uri queryUri = KeyRings.buildSecretKeyRingsUri(Long.toString(rowId));
        return getKeyRing(queryUri);
    }

    /**
     * Retrieves the actual secret KeyRing object from the database blob based on the maserKeyId
     */
    public KeyRing getSecretKeyRingByMasterKeyId(long masterKeyId) {
        Uri queryUri = KeyRings.buildSecretKeyRingsByMasterKeyIdUri(Long.toString(masterKeyId));
        return getKeyRing(queryUri);
    }

    /**
     * Retrieves the actual secret KeyRing object from the database blob associated with a key
     * with this keyId
     */
    public KeyRing getSecretKeyRingByKeyId(long keyId) {
        Uri queryUri = KeyRings.buildSecretKeyRingsByKeyIdUri(Long.toString(keyId));
        return getKeyRing(queryUri);
    }

    /**
     * Retrieves the actual secret Key object from the database blob associated with a key with
     * this keyId
     */
    public Key getSecretKeyByKeyId(long keyId) {
        KeyRing keyRing = getSecretKeyRingByKeyId(keyId);
        if (keyRing == null) {
            return null;
        }

        return keyRing.getSecretKey(keyId);
    }
}
