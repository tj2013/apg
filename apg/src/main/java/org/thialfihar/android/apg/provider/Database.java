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

package org.thialfihar.android.apg.provider;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Log;

import org.bouncycastle2.openpgp.PGPException;
import org.bouncycastle2.openpgp.PGPPublicKeyRing;
import org.bouncycastle2.openpgp.PGPSecretKeyRing;

import org.thialfihar.android.apg.Id;
import org.thialfihar.android.apg.core.Key;
import org.thialfihar.android.apg.core.KeyRing;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Vector;

public class Database extends SQLiteOpenHelper {
    public static class GeneralException extends Exception {
        static final long serialVersionUID = 0xf812773343L;

        public GeneralException(String message) {
            super(message);
        }
    }

    private static final String DATABASE_NAME = "apg";
    private static final int DATABASE_VERSION = 2;

    public static final String AUTHORITY = "org.thialfihar.android.apg.database";

    public static HashMap<String, String> sKeyRingsProjection;
    public static HashMap<String, String> sKeysProjection;
    public static HashMap<String, String> sUserIdsProjection;

    private SQLiteDatabase mDb = null;
    private int mStatus = 0;

    static {
        sKeyRingsProjection = new HashMap<String, String>();
        sKeyRingsProjection.put(KeyRings._ID, KeyRings._ID);
        sKeyRingsProjection.put(KeyRings.MASTER_KEY_ID, KeyRings.MASTER_KEY_ID);
        sKeyRingsProjection.put(KeyRings.TYPE, KeyRings.TYPE);
        sKeyRingsProjection.put(KeyRings.WHO_ID, KeyRings.WHO_ID);
        sKeyRingsProjection.put(KeyRings.KEY_RING_DATA, KeyRings.KEY_RING_DATA);

        sKeysProjection = new HashMap<String, String>();
        sKeysProjection.put(Keys._ID, Keys._ID);
        sKeysProjection.put(Keys.KEY_ID, Keys.KEY_ID);
        sKeysProjection.put(Keys.TYPE, Keys.TYPE);
        sKeysProjection.put(Keys.IS_MASTER_KEY, Keys.IS_MASTER_KEY);
        sKeysProjection.put(Keys.ALGORITHM, Keys.ALGORITHM);
        sKeysProjection.put(Keys.KEY_SIZE, Keys.KEY_SIZE);
        sKeysProjection.put(Keys.CAN_SIGN, Keys.CAN_SIGN);
        sKeysProjection.put(Keys.CAN_ENCRYPT, Keys.CAN_ENCRYPT);
        sKeysProjection.put(Keys.IS_REVOKED, Keys.IS_REVOKED);
        sKeysProjection.put(Keys.CREATION, Keys.CREATION);
        sKeysProjection.put(Keys.EXPIRY, Keys.EXPIRY);
        sKeysProjection.put(Keys.KEY_DATA, Keys.KEY_DATA);
        sKeysProjection.put(Keys.RANK, Keys.RANK);

        sUserIdsProjection = new HashMap<String, String>();
        sUserIdsProjection.put(UserIds._ID, UserIds._ID);
        sUserIdsProjection.put(UserIds.KEY_ID, UserIds.KEY_ID);
        sUserIdsProjection.put(UserIds.USER_ID, UserIds.USER_ID);
        sUserIdsProjection.put(UserIds.RANK, UserIds.RANK);
    }

    public Database(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
        // force upgrade to test things
        //onUpgrade(getWritableDatabase(), 1, 2);
        mDb = getWritableDatabase();
    }

    @Override
    protected void finalize() throws Throwable {
        mDb.close();
        super.finalize();
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE " + KeyRings.TABLE_NAME + " (" +
                   KeyRings._ID + " " + KeyRings._ID_TYPE + "," +
                   KeyRings.MASTER_KEY_ID + " " + KeyRings.MASTER_KEY_ID_TYPE + ", " +
                   KeyRings.TYPE + " " + KeyRings.TYPE_TYPE + ", " +
                   KeyRings.WHO_ID + " " + KeyRings.WHO_ID_TYPE + ", " +
                   KeyRings.KEY_RING_DATA + " " + KeyRings.KEY_RING_DATA_TYPE + ");");

        db.execSQL("CREATE TABLE " + Keys.TABLE_NAME + " (" +
                   Keys._ID + " " + Keys._ID_TYPE + "," +
                   Keys.KEY_ID + " " + Keys.KEY_ID_TYPE + ", " +
                   Keys.TYPE + " " + Keys.TYPE_TYPE + ", " +
                   Keys.IS_MASTER_KEY + " " + Keys.IS_MASTER_KEY_TYPE + ", " +
                   Keys.ALGORITHM + " " + Keys.ALGORITHM_TYPE + ", " +
                   Keys.KEY_SIZE + " " + Keys.KEY_SIZE_TYPE + ", " +
                   Keys.CAN_SIGN + " " + Keys.CAN_SIGN_TYPE + ", " +
                   Keys.CAN_ENCRYPT + " " + Keys.CAN_ENCRYPT_TYPE + ", " +
                   Keys.IS_REVOKED + " " + Keys.IS_REVOKED_TYPE + ", " +
                   Keys.CREATION + " " + Keys.CREATION_TYPE + ", " +
                   Keys.EXPIRY + " " + Keys.EXPIRY_TYPE + ", " +
                   Keys.KEY_RING_ID + " " + Keys.KEY_RING_ID_TYPE + ", " +
                   Keys.KEY_DATA + " " + Keys.KEY_DATA_TYPE +
                   Keys.RANK + " " + Keys.RANK_TYPE + ");");

        db.execSQL("CREATE TABLE " + UserIds.TABLE_NAME + " (" +
                   UserIds._ID + " " + UserIds._ID_TYPE + "," +
                   UserIds.KEY_ID + " " + UserIds.KEY_ID_TYPE + "," +
                   UserIds.USER_ID + " " + UserIds.USER_ID_TYPE + "," +
                   UserIds.RANK + " " + UserIds.RANK_TYPE + ");");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        mDb = db;
        for (int version = oldVersion; version < newVersion; ++version) {
            switch (version) {
                case 1: { // upgrade 1 to 2
                    db.execSQL("DROP TABLE IF EXISTS " + KeyRings.TABLE_NAME + ";");
                    db.execSQL("DROP TABLE IF EXISTS " + Keys.TABLE_NAME + ";");
                    db.execSQL("DROP TABLE IF EXISTS " + UserIds.TABLE_NAME + ";");

                    db.execSQL("CREATE TABLE " + KeyRings.TABLE_NAME + " (" +
                               KeyRings._ID + " " + KeyRings._ID_TYPE + "," +
                               KeyRings.MASTER_KEY_ID + " " + KeyRings.MASTER_KEY_ID_TYPE + ", " +
                               KeyRings.TYPE + " " + KeyRings.TYPE_TYPE + ", " +
                               KeyRings.WHO_ID + " " + KeyRings.WHO_ID_TYPE + ", " +
                               KeyRings.KEY_RING_DATA + " " + KeyRings.KEY_RING_DATA_TYPE + ");");

                    db.execSQL("CREATE TABLE " + Keys.TABLE_NAME + " (" +
                               Keys._ID + " " + Keys._ID_TYPE + "," +
                               Keys.KEY_ID + " " + Keys.KEY_ID_TYPE + ", " +
                               Keys.TYPE + " " + Keys.TYPE_TYPE + ", " +
                               Keys.IS_MASTER_KEY + " " + Keys.IS_MASTER_KEY_TYPE + ", " +
                               Keys.ALGORITHM + " " + Keys.ALGORITHM_TYPE + ", " +
                               Keys.KEY_SIZE + " " + Keys.KEY_SIZE_TYPE + ", " +
                               Keys.CAN_SIGN + " " + Keys.CAN_SIGN_TYPE + ", " +
                               Keys.CAN_ENCRYPT + " " + Keys.CAN_ENCRYPT_TYPE + ", " +
                               Keys.IS_REVOKED + " " + Keys.IS_REVOKED_TYPE + ", " +
                               Keys.CREATION + " " + Keys.CREATION_TYPE + ", " +
                               Keys.EXPIRY + " " + Keys.EXPIRY_TYPE + ", " +
                               Keys.KEY_RING_ID + " " + Keys.KEY_RING_ID_TYPE + ", " +
                               Keys.KEY_DATA + " " + Keys.KEY_DATA_TYPE +
                               Keys.RANK + " " + Keys.RANK_TYPE + ");");

                    db.execSQL("CREATE TABLE " + UserIds.TABLE_NAME + " (" +
                               UserIds._ID + " " + UserIds._ID_TYPE + "," +
                               UserIds.KEY_ID + " " + UserIds.KEY_ID_TYPE + "," +
                               UserIds.USER_ID + " " + UserIds.USER_ID_TYPE + "," +
                               UserIds.RANK + " " + UserIds.RANK_TYPE + ");");

                    Cursor cursor = db.query("public_keys", new String[] { "c_key_data" },
                                             null, null, null, null, null);
                    if (cursor != null && cursor.moveToFirst()) {
                        do {
                            byte[] data = cursor.getBlob(0);
                            try {
                                PGPPublicKeyRing keyRing = new PGPPublicKeyRing(data);
                                saveKeyRing(new KeyRing(keyRing));
                            } catch (IOException e) {
                                Log.e("apg.db.upgrade", "key import failed: " + e);
                            } catch (GeneralException e) {
                                Log.e("apg.db.upgrade", "key import failed: " + e);
                            }
                        } while (cursor.moveToNext());
                    }

                    if (cursor != null) {
                        cursor.close();
                    }

                    cursor = db.query("secret_keys", new String[]{ "c_key_data" },
                                      null, null, null, null, null);
                    if (cursor != null && cursor.moveToFirst()) {
                        do {
                            byte[] data = cursor.getBlob(0);
                            try {
                                PGPSecretKeyRing keyRing = new PGPSecretKeyRing(data);
                                saveKeyRing(new KeyRing(keyRing));
                            } catch (IOException e) {
                                Log.e("apg.db.upgrade", "key import failed: " + e);
                            } catch (PGPException e) {
                                Log.e("apg.db.upgrade", "key import failed: " + e);
                            } catch (GeneralException e) {
                                Log.e("apg.db.upgrade", "key import failed: " + e);
                            }
                        } while (cursor.moveToNext());
                    }

                    if (cursor != null) {
                        cursor.close();
                    }

                    db.execSQL("DROP TABLE IF EXISTS public_keys;");
                    db.execSQL("DROP TABLE IF EXISTS secret_keys;");

                    break;
                }

                default: {
                    break;
                }
            }
        }
        mDb = null;
    }

    public int saveKeyRing(KeyRing keyRing) throws IOException, GeneralException {
        mDb.beginTransaction();
        ContentValues values = new ContentValues();
        Key masterKey = keyRing.getMasterKey();
        long masterKeyId = masterKey.getKeyId();
        int returnValue = mStatus;
        if (keyRing.isPublic()) {
            values.put(KeyRings.MASTER_KEY_ID, masterKeyId);
            values.put(KeyRings.TYPE, Id.database.type_public);
            values.put(KeyRings.KEY_RING_DATA, keyRing.getEncoded());

            long rowId = insertOrUpdateKeyRing(values);

            if (rowId == -1) {
                throw new GeneralException("saving public key ring " + masterKeyId + " failed");
            }

            Vector<Integer> seenIds = new Vector<Integer>();
            int rank = 0;
            for (Key key : keyRing.getPublicKeys()) {
                seenIds.add(saveKey(rowId, key, rank));
                ++rank;
            }

            String seenIdsStr = "";
            for (Integer id : seenIds) {
                if (seenIdsStr.length() > 0) {
                    seenIdsStr += ",";
                }
                seenIdsStr += id;
            }
            mDb.delete(Keys.TABLE_NAME,
                       Keys.KEY_RING_ID + " = ? AND " +
                       Keys._ID + " NOT IN (" + seenIdsStr + ")",
                       new String[] { "" + rowId });
        } else {
            values.put(KeyRings.MASTER_KEY_ID, masterKeyId);
            values.put(KeyRings.TYPE, Id.database.type_secret);
            values.put(KeyRings.KEY_RING_DATA, keyRing.getEncoded());

            long rowId = insertOrUpdateKeyRing(values);

            if (rowId == -1) {
                throw new GeneralException("saving secret key ring " + masterKeyId + " failed");
            }

            Vector<Integer> seenIds = new Vector<Integer>();
            int rank = 0;
            for (Key key : keyRing.getSecretKeys()) {
                seenIds.add(saveKey(rowId, key, rank));
                ++rank;
            }

            String seenIdsStr = "";
            for (Integer id : seenIds) {
                if (seenIdsStr.length() > 0) {
                    seenIdsStr += ",";
                }
                seenIdsStr += id;
            }
            mDb.delete(Keys.TABLE_NAME,
                       Keys.KEY_RING_ID + " = ? AND " +
                       Keys._ID + " NOT IN (" + seenIdsStr + ")",
                       new String[] { "" + rowId });
        }

        mDb.setTransactionSuccessful();
        mDb.endTransaction();
        return returnValue;
    }

    private int saveKey(long keyRingId, Key key, int rank)
            throws IOException, GeneralException {
        ContentValues values = new ContentValues();

        values.put(Keys.KEY_ID, key.getKeyId());
        if (key.isPublic()) {
            values.put(Keys.TYPE, Id.database.type_public);
        } else {
            values.put(Keys.TYPE, Id.database.type_secret);
        }
        values.put(Keys.IS_MASTER_KEY, key.isMasterKey());
        values.put(Keys.ALGORITHM, key.getAlgorithm());
        values.put(Keys.KEY_SIZE, key.getBitStrength());
        values.put(Keys.CAN_SIGN, key.isSigningKey());
        values.put(Keys.CAN_ENCRYPT, key.isEncryptionKey());
        values.put(Keys.IS_REVOKED, key.isRevoked());
        values.put(Keys.CREATION, key.getCreationDate().getTime() / 1000);
        Date expiryDate = key.getExpiryDate();
        if (expiryDate != null) {
            values.put(Keys.EXPIRY, expiryDate.getTime() / 1000);
        }
        values.put(Keys.KEY_RING_ID, keyRingId);
        values.put(Keys.KEY_DATA, key.getEncoded());
        values.put(Keys.RANK, rank);

        long rowId = insertOrUpdateKey(values);

        if (rowId == -1) {
            throw new GeneralException("saving key " + key.getKeyId() + " failed");
        }

        Vector<Integer> seenIds = new Vector<Integer>();
        int userIdRank = 0;
        for (String userId : key.getUserIds()) {
            seenIds.add(saveUserId(rowId, userId, userIdRank));
            ++userIdRank;
        }

        String seenIdsStr = "";
        for (Integer id : seenIds) {
            if (seenIdsStr.length() > 0) {
                seenIdsStr += ",";
            }
            seenIdsStr += id;
        }
        mDb.delete(UserIds.TABLE_NAME,
                   UserIds.KEY_ID + " = ? AND " +
                   UserIds._ID + " NOT IN (" + seenIdsStr + ")",
                   new String[] { "" + rowId });

        return (int) rowId;
    }

    private int saveUserId(long keyId, String userId, int rank) throws GeneralException {
        ContentValues values = new ContentValues();

        values.put(UserIds.KEY_ID, keyId);
        values.put(UserIds.USER_ID, userId);
        values.put(UserIds.RANK, rank);

        long rowId = insertOrUpdateUserId(values);

        if (rowId == -1) {
            throw new GeneralException("saving user id " + userId + " failed");
        }

        return (int) rowId;
    }

    private long insertOrUpdateKeyRing(ContentValues values) {
        Cursor c = mDb.query(KeyRings.TABLE_NAME, new String[] { KeyRings._ID },
                             KeyRings.MASTER_KEY_ID + " = ? AND " + KeyRings.TYPE + " = ?",
                             new String[] {
                                 values.getAsString(KeyRings.MASTER_KEY_ID),
                                 values.getAsString(KeyRings.TYPE),
                             },
                             null, null, null);
        long rowId = -1;
        if (c != null && c.moveToFirst()) {
            rowId = c.getLong(0);
            mDb.update(KeyRings.TABLE_NAME, values,
                       KeyRings._ID + " = ?", new String[] { "" + rowId });
            mStatus = Id.return_value.updated;
        } else {
            rowId = mDb.insert(KeyRings.TABLE_NAME, KeyRings.WHO_ID, values);
            mStatus = Id.return_value.ok;
        }

        if (c != null) {
            c.close();
        }

        return rowId;
    }

    private long insertOrUpdateKey(ContentValues values) {
        Cursor c = mDb.query(Keys.TABLE_NAME, new String[] { Keys._ID },
                             Keys.KEY_ID + " = ? AND " + Keys.TYPE + " = ?",
                             new String[] {
                                 values.getAsString(Keys.KEY_ID),
                                 values.getAsString(Keys.TYPE),
                             },
                             null, null, null);
        long rowId = -1;
        if (c != null && c.moveToFirst()) {
            rowId = c.getLong(0);
            mDb.update(Keys.TABLE_NAME, values,
                       Keys._ID + " = ?", new String[] { "" + rowId });
        } else {
            rowId = mDb.insert(Keys.TABLE_NAME, Keys.KEY_DATA, values);
        }

        if (c != null) {
            c.close();
        }

        return rowId;
    }

    private long insertOrUpdateUserId(ContentValues values) {
        Cursor c = mDb.query(UserIds.TABLE_NAME, new String[] { UserIds._ID },
                             UserIds.KEY_ID + " = ? AND " + UserIds.USER_ID + " = ?",
                             new String[] {
                                 values.getAsString(UserIds.KEY_ID),
                                 values.getAsString(UserIds.USER_ID),
                             },
                             null, null, null);
        long rowId = -1;
        if (c != null && c.moveToFirst()) {
            rowId = c.getLong(0);
            mDb.update(UserIds.TABLE_NAME, values,
                       UserIds._ID + " = ?", new String[] { "" + rowId });
        } else {
            rowId = mDb.insert(UserIds.TABLE_NAME, UserIds.USER_ID, values);
        }

        if (c != null) {
            c.close();
        }

        return rowId;
    }

    public KeyRing getKeyRing(int keyRingId) {
        Cursor c = mDb.query(KeyRings.TABLE_NAME,
                             new String[] { KeyRings.KEY_RING_DATA, KeyRings.TYPE },
                             KeyRings._ID + " = ?",
                             new String[] {
                                 "" + keyRingId,
                             },
                             null, null, null);
        byte[] data = null;
        KeyRing keyRing = null;
        if (c != null && c.moveToFirst()) {
            data = c.getBlob(0);
            if (data != null) {
                try {
                    if (c.getInt(1) == Id.database.type_public) {
                        keyRing = new KeyRing(new PGPPublicKeyRing(data));
                    } else {
                        keyRing = new KeyRing(new PGPSecretKeyRing(data));
                    }
                } catch (IOException e) {
                    // can't load it, then
                } catch (PGPException e) {
                    // can't load it, then
                }
            }
        }

        if (c != null) {
            c.close();
        }

        return keyRing;
    }

    public byte[] getKeyRingDataFromKeyId(int type, long keyId) {
        Cursor c = mDb.query(Keys.TABLE_NAME + " INNER JOIN " + KeyRings.TABLE_NAME + " ON (" +
                             KeyRings.TABLE_NAME + "." + KeyRings._ID + " = " +
                             Keys.TABLE_NAME + "." + Keys.KEY_RING_ID + ")",
                             new String[] { KeyRings.TABLE_NAME + "." + KeyRings.KEY_RING_DATA },
                             Keys.TABLE_NAME + "." + Keys.KEY_ID + " = ? AND " +
                             KeyRings.TABLE_NAME + "." + KeyRings.TYPE + " = ?",
                             new String[] {
                                 "" + keyId,
                                 "" + type,
                             },
                             null, null, null);

        byte[] data = null;
        if (c != null && c.moveToFirst()) {
            data = c.getBlob(0);
        }

        if (c != null) {
            c.close();
        }

        return data;
    }

    public byte[] getKeyDataFromKeyId(int type, long keyId) {
        Cursor c = mDb.query(Keys.TABLE_NAME, new String[] { Keys.KEY_DATA },
                             Keys.KEY_ID + " = ? AND " + Keys.TYPE + " = ?",
                             new String[] {
                                 "" + keyId,
                                 "" + type,
                             },
                             null, null, null);
        byte[] data = null;
        if (c != null && c.moveToFirst()) {
            data = c.getBlob(0);
        }

        if (c != null) {
            c.close();
        }

        return data;
    }

    public void deleteKeyRing(int keyRingId) {
        mDb.beginTransaction();
        mDb.delete(KeyRings.TABLE_NAME,
                   KeyRings._ID + " = ?", new String[] { "" + keyRingId });

        Cursor c = mDb.query(Keys.TABLE_NAME, new String[] { Keys._ID },
                             Keys.KEY_RING_ID + " = ?",
                             new String[] {
                                 "" + keyRingId,
                             },
                                    null, null, null);
        if (c != null && c.moveToFirst()) {
            do {
                int keyId = c.getInt(0);
                deleteKey(keyId);
            } while (c.moveToNext());
        }

        if (c != null) {
            c.close();
        }

        mDb.setTransactionSuccessful();
        mDb.endTransaction();
    }

    private void deleteKey(int keyId) {
        mDb.delete(Keys.TABLE_NAME,
                   Keys._ID + " = ?", new String[] { "" + keyId });

        mDb.delete(UserIds.TABLE_NAME,
                   UserIds.KEY_ID + " = ?", new String[] { "" + keyId });
    }

    public SQLiteDatabase db() {
        return mDb;
    }
}
