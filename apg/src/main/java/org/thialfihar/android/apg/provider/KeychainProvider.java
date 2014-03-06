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

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.UriMatcher;
import android.database.Cursor;
import android.database.DatabaseUtils;
import android.database.sqlite.SQLiteConstraintException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteQueryBuilder;
import android.net.Uri;
import android.provider.BaseColumns;
import android.text.TextUtils;

import org.thialfihar.android.apg.Constants;
import org.thialfihar.android.apg.provider.KeychainContract.KeyRings;
import org.thialfihar.android.apg.provider.KeychainContract.KeyRingsColumns;
import org.thialfihar.android.apg.provider.KeychainContract.Keys;
import org.thialfihar.android.apg.provider.KeychainContract.KeysColumns;
import org.thialfihar.android.apg.provider.KeychainContract.KeyTypes;
import org.thialfihar.android.apg.provider.KeychainContract.UserIds;
import org.thialfihar.android.apg.provider.KeychainContract.UserIdsColumns;
import org.thialfihar.android.apg.provider.KeychainDatabase.Tables;
import org.thialfihar.android.apg.util.Log;

import java.util.Arrays;
import java.util.HashMap;

public class KeychainProvider extends ContentProvider {
    private static final String AUTHORITY = KeychainContract.AUTHORITY;

    private static final int PUBLIC_KEY_RING = 101;
    private static final int PUBLIC_KEY_RING_BY_ROW_ID = 102;
    private static final int PUBLIC_KEY_RING_BY_MASTER_KEY_ID = 103;
    private static final int PUBLIC_KEY_RING_BY_KEY_ID = 104;
    private static final int PUBLIC_KEY_RING_BY_EMAILS = 105;
    private static final int PUBLIC_KEY_RING_BY_LIKE_EMAIL = 106;
    private static final int PUBLIC_KEY_RING_KEY = 111;
    private static final int PUBLIC_KEY_RING_KEY_BY_ROW_ID = 112;
    private static final int PUBLIC_KEY_RING_USER_ID = 121;
    private static final int PUBLIC_KEY_RING_USER_ID_BY_ROW_ID = 122;

    private static final int SECRET_KEY_RING = 201;
    private static final int SECRET_KEY_RING_BY_ROW_ID = 202;
    private static final int SECRET_KEY_RING_BY_MASTER_KEY_ID = 203;
    private static final int SECRET_KEY_RING_BY_KEY_ID = 204;
    private static final int SECRET_KEY_RING_BY_EMAILS = 205;
    private static final int SECRET_KEY_RING_BY_LIKE_EMAIL = 206;
    private static final int SECRET_KEY_RING_KEY = 211;
    private static final int SECRET_KEY_RING_KEY_BY_ROW_ID = 212;
    private static final int SECRET_KEY_RING_USER_ID = 221;
    private static final int SECRET_KEY_RING_USER_ID_BY_ROW_ID = 222;

    private static final int DATA_STREAM = 301;

    private static final UriMatcher sUriMatcher;

    public static HashMap<String, String> sKeyRingsProjection;
    public static HashMap<String, String> sKeysProjection;
    public static HashMap<String, String> sUserIdsProjection;

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
        sKeysProjection.put(Keys.CAN_CERTIFY, Keys.CAN_CERTIFY);
        sKeysProjection.put(Keys.CAN_ENCRYPT, Keys.CAN_ENCRYPT);
        sKeysProjection.put(Keys.IS_REVOKED, Keys.IS_REVOKED);
        sKeysProjection.put(Keys.CREATION, Keys.CREATION);
        sKeysProjection.put(Keys.EXPIRY, Keys.EXPIRY);
        sKeysProjection.put(Keys.KEY_DATA, Keys.KEY_DATA);
        sKeysProjection.put(Keys.RANK, Keys.RANK);

        sUserIdsProjection = new HashMap<String, String>();
        sUserIdsProjection.put(UserIds._ID, UserIds._ID);
        sUserIdsProjection.put(UserIds.KEY_RING_ROW_ID, UserIds.KEY_RING_ROW_ID);
        sUserIdsProjection.put(UserIds.USER_ID, UserIds.USER_ID);
        sUserIdsProjection.put(UserIds.RANK, UserIds.RANK);

        sUriMatcher = new UriMatcher(UriMatcher.NO_MATCH);
        sUriMatcher.addURI(AUTHORITY, "key_rings/public/master_key_id/*", PUBLIC_KEY_RING_BY_MASTER_KEY_ID);
        sUriMatcher.addURI(AUTHORITY, "key_rings/public/key_id/*", PUBLIC_KEY_RING_BY_KEY_ID);
        sUriMatcher.addURI(AUTHORITY, "key_rings/public/emails/*", PUBLIC_KEY_RING_BY_EMAILS);

        sUriMatcher.addURI(AUTHORITY, "key_rings/public/*/keys", PUBLIC_KEY_RING_KEY);
        sUriMatcher.addURI(AUTHORITY, "key_rings/public/*/keys/#", PUBLIC_KEY_RING_KEY_BY_ROW_ID);

        sUriMatcher.addURI(AUTHORITY, "key_rings/public/*/user_ids", PUBLIC_KEY_RING_USER_ID);
        sUriMatcher.addURI(AUTHORITY, "key_rings/public/*/user_ids/#", PUBLIC_KEY_RING_USER_ID_BY_ROW_ID);

        sUriMatcher.addURI(AUTHORITY, "key_rings/public", PUBLIC_KEY_RING);
        sUriMatcher.addURI(AUTHORITY, "key_rings/public/*", PUBLIC_KEY_RING_BY_ROW_ID);

        sUriMatcher.addURI(AUTHORITY, "key_rings/secret/master_key_id/*", SECRET_KEY_RING_BY_MASTER_KEY_ID);
        sUriMatcher.addURI(AUTHORITY, "key_rings/secret/key_id/*", SECRET_KEY_RING_BY_KEY_ID);
        sUriMatcher.addURI(AUTHORITY, "key_rings/secret/emails/*", SECRET_KEY_RING_BY_EMAILS);

        sUriMatcher.addURI(AUTHORITY, "key_rings/secret/*/keys", SECRET_KEY_RING_KEY);
        sUriMatcher.addURI(AUTHORITY, "key_rings/secret/*/keys/#", SECRET_KEY_RING_KEY_BY_ROW_ID);

        sUriMatcher.addURI(AUTHORITY, "key_rings/secret/*/user_ids", SECRET_KEY_RING_USER_ID);
        sUriMatcher.addURI(AUTHORITY, "key_rings/secret/*/user_ids/#", SECRET_KEY_RING_USER_ID_BY_ROW_ID);

        sUriMatcher.addURI(AUTHORITY, "key_rings/secret", SECRET_KEY_RING);
        sUriMatcher.addURI(AUTHORITY, "key_rings/secret/*", SECRET_KEY_RING_BY_ROW_ID);

        sUriMatcher.addURI(AUTHORITY, "data/*", DATA_STREAM);
    }

    private KeychainDatabase mKeychainDatabase;

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean onCreate() {
        mKeychainDatabase = new KeychainDatabase(getContext());
        return true;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getType(Uri uri) {
        final int match = sUriMatcher.match(uri);
        switch (match) {
            case PUBLIC_KEY_RING:
            case PUBLIC_KEY_RING_BY_EMAILS:
            case PUBLIC_KEY_RING_BY_LIKE_EMAIL:
            case SECRET_KEY_RING:
            case SECRET_KEY_RING_BY_EMAILS:
            case SECRET_KEY_RING_BY_LIKE_EMAIL:
                return KeyRings.CONTENT_TYPE;

            case PUBLIC_KEY_RING_BY_ROW_ID:
            case PUBLIC_KEY_RING_BY_MASTER_KEY_ID:
            case PUBLIC_KEY_RING_BY_KEY_ID:
            case SECRET_KEY_RING_BY_ROW_ID:
            case SECRET_KEY_RING_BY_MASTER_KEY_ID:
            case SECRET_KEY_RING_BY_KEY_ID:
                return KeyRings.CONTENT_ITEM_TYPE;

            case PUBLIC_KEY_RING_KEY:
            case SECRET_KEY_RING_KEY:
                return Keys.CONTENT_TYPE;

            case PUBLIC_KEY_RING_KEY_BY_ROW_ID:
            case SECRET_KEY_RING_KEY_BY_ROW_ID:
                return Keys.CONTENT_ITEM_TYPE;

            case PUBLIC_KEY_RING_USER_ID:
            case SECRET_KEY_RING_USER_ID:
                return UserIds.CONTENT_TYPE;

            case PUBLIC_KEY_RING_USER_ID_BY_ROW_ID:
            case SECRET_KEY_RING_USER_ID_BY_ROW_ID:
                return UserIds.CONTENT_ITEM_TYPE;

            default:
                throw new UnsupportedOperationException("Unknown uri: " + uri);
        }
    }

    /**
     * Returns type of the query (secret/public)
     *
     * @param uri
     * @return
     */
    private int getKeyType(int match) {
        int type;
        switch (match) {
            case PUBLIC_KEY_RING:
            case PUBLIC_KEY_RING_BY_ROW_ID:
            case PUBLIC_KEY_RING_BY_MASTER_KEY_ID:
            case PUBLIC_KEY_RING_BY_KEY_ID:
            case PUBLIC_KEY_RING_BY_EMAILS:
            case PUBLIC_KEY_RING_BY_LIKE_EMAIL:
            case PUBLIC_KEY_RING_KEY:
            case PUBLIC_KEY_RING_KEY_BY_ROW_ID:
            case PUBLIC_KEY_RING_USER_ID:
            case PUBLIC_KEY_RING_USER_ID_BY_ROW_ID:
                type = KeyTypes.PUBLIC;
                break;

            case SECRET_KEY_RING:
            case SECRET_KEY_RING_BY_ROW_ID:
            case SECRET_KEY_RING_BY_MASTER_KEY_ID:
            case SECRET_KEY_RING_BY_KEY_ID:
            case SECRET_KEY_RING_BY_EMAILS:
            case SECRET_KEY_RING_BY_LIKE_EMAIL:
            case SECRET_KEY_RING_KEY:
            case SECRET_KEY_RING_KEY_BY_ROW_ID:
            case SECRET_KEY_RING_USER_ID:
            case SECRET_KEY_RING_USER_ID_BY_ROW_ID:
                type = KeyTypes.SECRET;
                break;

            default:
                Log.e(Constants.TAG, "Unknown match " + match);
                type = -1;
                break;
        }

        return type;
    }

    /**
     * Builds default query for keyRings: KeyRings table is joined with UserIds and Keys
     */
    private SQLiteQueryBuilder buildKeyRingQuery(SQLiteQueryBuilder qb, int match) {
        // public or secret keyring
        qb.appendWhere(Tables.KEY_RINGS + "." + KeyRingsColumns.TYPE + " = ");
        qb.appendWhereEscapeString(Integer.toString(getKeyType(match)));

        // join keyrings with keys and userIds
        // Only get user id and key with rank 0 (main user id and main key)
        qb.setTables(Tables.KEY_RINGS + " INNER JOIN " + Tables.KEYS + " ON " + "("
                + Tables.KEY_RINGS + "." + BaseColumns._ID + " = " + Tables.KEYS + "."
                + KeysColumns.KEY_RING_ROW_ID + " AND " + Tables.KEYS + "."
                + KeysColumns.RANK + " = '0') " + " INNER JOIN " + Tables.USER_IDS + " ON "
                + "(" + Tables.KEY_RINGS + "." + BaseColumns._ID + " = " + Tables.USER_IDS + "."
                + UserIdsColumns.KEY_RING_ROW_ID + " AND " + Tables.USER_IDS + "."
                + UserIdsColumns.RANK + " = '0')");

        qb.setProjectionMap(sKeyRingsProjection);

        return qb;
    }

    /**
     * Builds default query for keyRings: KeyRings table is joined with UserIds and Keys
     * <p/>
     * Here only one key should be selected in the query to return a single keyring!
     */
    private SQLiteQueryBuilder buildKeyRingQueryWithSpecificKey(SQLiteQueryBuilder qb, int match) {
        // public or secret keyring
        qb.appendWhere(Tables.KEY_RINGS + "." + KeyRingsColumns.TYPE + " = ");
        qb.appendWhereEscapeString(Integer.toString(getKeyType(match)));

        // join keyrings with keys and userIds to every keyring
        qb.setTables(Tables.KEY_RINGS + " INNER JOIN " + Tables.KEYS + " ON " + "("
                + Tables.KEY_RINGS + "." + BaseColumns._ID + " = " + Tables.KEYS + "."
                + KeysColumns.KEY_RING_ROW_ID + ") " + " INNER JOIN " + Tables.USER_IDS + " ON "
                + "(" + Tables.KEY_RINGS + "." + BaseColumns._ID + " = " + Tables.USER_IDS + "."
                + UserIdsColumns.KEY_RING_ROW_ID + " AND " + Tables.USER_IDS + "."
                + UserIdsColumns.RANK + " = '0')");

        qb.setProjectionMap(sKeyRingsProjection);

        return qb;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
                        String sortOrder) {
        Log.v(Constants.TAG, "query(uri=" + uri + ", proj=" + Arrays.toString(projection) + ")");

        SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
        SQLiteDatabase db = mKeychainDatabase.getReadableDatabase();

        int match = sUriMatcher.match(uri);

        switch (match) {
            case PUBLIC_KEY_RING:
            case SECRET_KEY_RING:
                qb = buildKeyRingQuery(qb, match);

                if (TextUtils.isEmpty(sortOrder)) {
                    sortOrder = Tables.USER_IDS + "." + UserIdsColumns.USER_ID + " ASC";
                }

                break;

            case PUBLIC_KEY_RING_BY_ROW_ID:
            case SECRET_KEY_RING_BY_ROW_ID:
                qb = buildKeyRingQuery(qb, match);

                qb.appendWhere(" AND " + Tables.KEY_RINGS + "." + BaseColumns._ID + " = ");
                qb.appendWhereEscapeString(uri.getLastPathSegment());

                if (TextUtils.isEmpty(sortOrder)) {
                    sortOrder = Tables.USER_IDS + "." + UserIdsColumns.USER_ID + " ASC";
                }

                break;

            case PUBLIC_KEY_RING_BY_MASTER_KEY_ID:
            case SECRET_KEY_RING_BY_MASTER_KEY_ID:
                qb = buildKeyRingQuery(qb, match);

                qb.appendWhere(" AND " + Tables.KEY_RINGS + "." + KeyRingsColumns.MASTER_KEY_ID + " = ");
                qb.appendWhereEscapeString(uri.getLastPathSegment());

                if (TextUtils.isEmpty(sortOrder)) {
                    sortOrder = Tables.USER_IDS + "." + UserIdsColumns.USER_ID + " ASC";
                }

                break;

            case SECRET_KEY_RING_BY_KEY_ID:
            case PUBLIC_KEY_RING_BY_KEY_ID:
                qb = buildKeyRingQueryWithSpecificKey(qb, match);

                qb.appendWhere(" AND " + Tables.KEYS + "." + KeysColumns.KEY_ID + " = ");
                qb.appendWhereEscapeString(uri.getLastPathSegment());

                if (TextUtils.isEmpty(sortOrder)) {
                    sortOrder = Tables.USER_IDS + "." + UserIdsColumns.USER_ID + " ASC";
                }

                break;

            case SECRET_KEY_RING_BY_EMAILS:
            case PUBLIC_KEY_RING_BY_EMAILS:
                qb = buildKeyRingQuery(qb, match);

                String emails = uri.getLastPathSegment();
                String chunks[] = emails.split(" *, *");
                boolean gotCondition = false;
                String emailWhere = "";
                for (int i = 0; i < chunks.length; ++i) {
                    if (chunks[i].length() == 0) {
                        continue;
                    }
                    if (i != 0) {
                        emailWhere += " OR ";
                    }
                    emailWhere += "tmp." + UserIdsColumns.USER_ID + " LIKE ";
                    // match '*<email>', so it has to be at the *end* of the user id
                    emailWhere += DatabaseUtils.sqlEscapeString("%<" + chunks[i] + ">");
                    gotCondition = true;
                }

                if (gotCondition) {
                    qb.appendWhere(" AND EXISTS (SELECT tmp." + BaseColumns._ID + " FROM "
                            + Tables.USER_IDS + " AS tmp WHERE tmp." + UserIdsColumns.KEY_RING_ROW_ID
                            + " = " + Tables.KEY_RINGS + "." + BaseColumns._ID + " AND (" + emailWhere
                            + "))");
                }

                break;

            case SECRET_KEY_RING_BY_LIKE_EMAIL:
            case PUBLIC_KEY_RING_BY_LIKE_EMAIL:
                qb = buildKeyRingQuery(qb, match);

                String likeEmail = uri.getLastPathSegment();

                String likeEmailWhere = "tmp." + UserIdsColumns.USER_ID + " LIKE "
                        + DatabaseUtils.sqlEscapeString("%<%" + likeEmail + "%>");

                qb.appendWhere(" AND EXISTS (SELECT tmp." + BaseColumns._ID + " FROM "
                        + Tables.USER_IDS + " AS tmp WHERE tmp." + UserIdsColumns.KEY_RING_ROW_ID
                        + " = " + Tables.KEY_RINGS + "." + BaseColumns._ID + " AND (" + likeEmailWhere
                        + "))");

                break;

            case PUBLIC_KEY_RING_KEY:
            case SECRET_KEY_RING_KEY:
                qb.setTables(Tables.KEYS);
                qb.appendWhere(KeysColumns.TYPE + " = ");
                qb.appendWhereEscapeString(Integer.toString(getKeyType(match)));

                qb.appendWhere(" AND " + KeysColumns.KEY_RING_ROW_ID + " = ");
                qb.appendWhereEscapeString(uri.getPathSegments().get(2));

                qb.setProjectionMap(sKeysProjection);

                break;

            case PUBLIC_KEY_RING_KEY_BY_ROW_ID:
            case SECRET_KEY_RING_KEY_BY_ROW_ID:
                qb.setTables(Tables.KEYS);
                qb.appendWhere(KeysColumns.TYPE + " = ");
                qb.appendWhereEscapeString(Integer.toString(getKeyType(match)));

                qb.appendWhere(" AND " + KeysColumns.KEY_RING_ROW_ID + " = ");
                qb.appendWhereEscapeString(uri.getPathSegments().get(2));

                qb.appendWhere(" AND " + BaseColumns._ID + " = ");
                qb.appendWhereEscapeString(uri.getLastPathSegment());

                qb.setProjectionMap(sKeysProjection);

                break;

            case PUBLIC_KEY_RING_USER_ID:
            case SECRET_KEY_RING_USER_ID:
                qb.setTables(Tables.USER_IDS);
                qb.appendWhere(UserIdsColumns.KEY_RING_ROW_ID + " = ");
                qb.appendWhereEscapeString(uri.getPathSegments().get(2));

                break;

            case PUBLIC_KEY_RING_USER_ID_BY_ROW_ID:
            case SECRET_KEY_RING_USER_ID_BY_ROW_ID:
                qb.setTables(Tables.USER_IDS);
                qb.appendWhere(UserIdsColumns.KEY_RING_ROW_ID + " = ");
                qb.appendWhereEscapeString(uri.getPathSegments().get(2));

                qb.appendWhere(" AND " + BaseColumns._ID + " = ");
                qb.appendWhereEscapeString(uri.getLastPathSegment());

                break;

            default:
                throw new IllegalArgumentException("Unknown URI " + uri);

        }

        // If no sort order is specified use the default
        String orderBy;
        if (TextUtils.isEmpty(sortOrder)) {
            orderBy = null;
        } else {
            orderBy = sortOrder;
        }

        Cursor c = qb.query(db, projection, selection, selectionArgs, null, null, orderBy);

        // Tell the cursor what uri to watch, so it knows when its source data changes
        c.setNotificationUri(getContext().getContentResolver(), uri);

        if (Constants.DEBUG) {
            Log.d(Constants.TAG,
                    "Query: "
                            + qb.buildQuery(projection, selection, selectionArgs, null, null,
                            orderBy, null));
            Log.d(Constants.TAG, "Cursor: " + DatabaseUtils.dumpCursorToString(c));
        }

        return c;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Uri insert(Uri uri, ContentValues values) {
        Log.d(Constants.TAG, "insert(uri=" + uri + ", values=" + values.toString() + ")");

        final SQLiteDatabase db = mKeychainDatabase.getWritableDatabase();

        Uri rowUri = null;
        long rowId = -1;
        try {
            final int match = sUriMatcher.match(uri);

            switch (match) {
                case PUBLIC_KEY_RING:
                    values.put(KeyRings.TYPE, KeyTypes.PUBLIC);

                    rowId = db.insertOrThrow(Tables.KEY_RINGS, null, values);
                    rowUri = KeyRings.buildPublicKeyRingsUri(Long.toString(rowId));
                    sendBroadcastDatabaseChange(getKeyType(match), getType(uri));

                    break;
                case PUBLIC_KEY_RING_KEY:
                    values.put(Keys.TYPE, KeyTypes.PUBLIC);

                    rowId = db.insertOrThrow(Tables.KEYS, null, values);
                    rowUri = Keys.buildPublicKeysUri(Long.toString(rowId));
                    sendBroadcastDatabaseChange(getKeyType(match), getType(uri));

                    break;
                case PUBLIC_KEY_RING_USER_ID:
                    rowId = db.insertOrThrow(Tables.USER_IDS, null, values);
                    rowUri = UserIds.buildPublicUserIdsUri(Long.toString(rowId));
                    sendBroadcastDatabaseChange(getKeyType(match), getType(uri));

                    break;
                case SECRET_KEY_RING:
                    values.put(KeyRings.TYPE, KeyTypes.SECRET);

                    rowId = db.insertOrThrow(Tables.KEY_RINGS, null, values);
                    rowUri = KeyRings.buildSecretKeyRingsUri(Long.toString(rowId));
                    sendBroadcastDatabaseChange(getKeyType(match), getType(uri));

                    break;
                case SECRET_KEY_RING_KEY:
                    values.put(Keys.TYPE, KeyTypes.SECRET);

                    rowId = db.insertOrThrow(Tables.KEYS, null, values);
                    rowUri = Keys.buildSecretKeysUri(Long.toString(rowId));
                    sendBroadcastDatabaseChange(getKeyType(match), getType(uri));

                    break;
                case SECRET_KEY_RING_USER_ID:
                    rowId = db.insertOrThrow(Tables.USER_IDS, null, values);
                    rowUri = UserIds.buildSecretUserIdsUri(Long.toString(rowId));

                    break;
                default:
                    throw new UnsupportedOperationException("Unknown uri: " + uri);
            }

            // notify of changes in db
            getContext().getContentResolver().notifyChange(uri, null);

        } catch (SQLiteConstraintException e) {
            Log.e(Constants.TAG, "Constraint exception on insert! Entry already existing?");
        }

        return rowUri;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        Log.v(Constants.TAG, "delete(uri=" + uri + ")");

        final SQLiteDatabase db = mKeychainDatabase.getWritableDatabase();

        int count;
        final int match = sUriMatcher.match(uri);

        String defaultSelection = null;
        switch (match) {
            case PUBLIC_KEY_RING_BY_ROW_ID:
            case SECRET_KEY_RING_BY_ROW_ID:
                defaultSelection = BaseColumns._ID + "=" + uri.getLastPathSegment();
                // corresponding keys and userIds are deleted by ON DELETE CASCADE
                count = db.delete(Tables.KEY_RINGS,
                        buildDefaultKeyRingsSelection(defaultSelection, getKeyType(match), selection),
                        selectionArgs);
                sendBroadcastDatabaseChange(getKeyType(match), getType(uri));
                break;
            case PUBLIC_KEY_RING_BY_MASTER_KEY_ID:
            case SECRET_KEY_RING_BY_MASTER_KEY_ID:
                defaultSelection = KeyRings.MASTER_KEY_ID + "=" + uri.getLastPathSegment();
                // corresponding keys and userIds are deleted by ON DELETE CASCADE
                count = db.delete(Tables.KEY_RINGS,
                        buildDefaultKeyRingsSelection(defaultSelection, getKeyType(match), selection),
                        selectionArgs);
                sendBroadcastDatabaseChange(getKeyType(match), getType(uri));
                break;
            case PUBLIC_KEY_RING_KEY_BY_ROW_ID:
            case SECRET_KEY_RING_KEY_BY_ROW_ID:
                count = db.delete(Tables.KEYS,
                        buildDefaultKeysSelection(uri, getKeyType(match), selection), selectionArgs);
                sendBroadcastDatabaseChange(getKeyType(match), getType(uri));
                break;
            case PUBLIC_KEY_RING_USER_ID_BY_ROW_ID:
            case SECRET_KEY_RING_USER_ID_BY_ROW_ID:
                count = db.delete(Tables.KEYS, buildDefaultUserIdsSelection(uri, selection),
                        selectionArgs);
                break;
            default:
                throw new UnsupportedOperationException("Unknown uri: " + uri);
        }

        // notify of changes in db
        getContext().getContentResolver().notifyChange(uri, null);

        return count;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        Log.v(Constants.TAG, "update(uri=" + uri + ", values=" + values.toString() + ")");

        final SQLiteDatabase db = mKeychainDatabase.getWritableDatabase();

        String defaultSelection = null;
        int count = 0;
        try {
            final int match = sUriMatcher.match(uri);
            switch (match) {
                case PUBLIC_KEY_RING_BY_ROW_ID:
                case SECRET_KEY_RING_BY_ROW_ID:
                    defaultSelection = BaseColumns._ID + "=" + uri.getLastPathSegment();

                    count = db.update(
                            Tables.KEY_RINGS,
                            values,
                            buildDefaultKeyRingsSelection(defaultSelection, getKeyType(match),
                                    selection), selectionArgs);
                    sendBroadcastDatabaseChange(getKeyType(match), getType(uri));

                    break;
                case PUBLIC_KEY_RING_BY_MASTER_KEY_ID:
                case SECRET_KEY_RING_BY_MASTER_KEY_ID:
                    defaultSelection = KeyRings.MASTER_KEY_ID + "=" + uri.getLastPathSegment();

                    count = db.update(
                            Tables.KEY_RINGS,
                            values,
                            buildDefaultKeyRingsSelection(defaultSelection, getKeyType(match),
                                    selection), selectionArgs);
                    sendBroadcastDatabaseChange(getKeyType(match), getType(uri));

                    break;
                case PUBLIC_KEY_RING_KEY_BY_ROW_ID:
                case SECRET_KEY_RING_KEY_BY_ROW_ID:
                    count = db
                            .update(Tables.KEYS, values,
                                    buildDefaultKeysSelection(uri, getKeyType(match), selection),
                                    selectionArgs);
                    sendBroadcastDatabaseChange(getKeyType(match), getType(uri));

                    break;
                case PUBLIC_KEY_RING_USER_ID_BY_ROW_ID:
                case SECRET_KEY_RING_USER_ID_BY_ROW_ID:
                    count = db.update(Tables.USER_IDS, values,
                            buildDefaultUserIdsSelection(uri, selection), selectionArgs);
                    break;
                default:
                    throw new UnsupportedOperationException("Unknown uri: " + uri);
            }

            // notify of changes in db
            getContext().getContentResolver().notifyChange(uri, null);

        } catch (SQLiteConstraintException e) {
            Log.e(Constants.TAG, "Constraint exception on update! Entry already existing?");
        }

        return count;
    }

    /**
     * Build default selection statement for KeyRings. If no extra selection is specified only build
     * where clause with rowId
     *
     * @param uri
     * @param selection
     * @return
     */
    private String buildDefaultKeyRingsSelection(String defaultSelection, Integer keyType,
                                                 String selection) {
        String andType = "";
        if (keyType != null) {
            andType = " AND " + KeyRingsColumns.TYPE + "=" + keyType;
        }

        String andSelection = "";
        if (!TextUtils.isEmpty(selection)) {
            andSelection = " AND (" + selection + ")";
        }

        return defaultSelection + andType + andSelection;
    }

    /**
     * Build default selection statement for Keys. If no extra selection is specified only build
     * where clause with rowId
     *
     * @param uri
     * @param selection
     * @return
     */
    private String buildDefaultKeysSelection(Uri uri, Integer keyType, String selection) {
        String rowId = uri.getLastPathSegment();

        String foreignKeyRingRowId = uri.getPathSegments().get(2);
        String andForeignKeyRing = " AND " + KeysColumns.KEY_RING_ROW_ID + " = "
                + foreignKeyRingRowId;

        String andType = "";
        if (keyType != null) {
            andType = " AND " + KeysColumns.TYPE + "=" + keyType;
        }

        String andSelection = "";
        if (!TextUtils.isEmpty(selection)) {
            andSelection = " AND (" + selection + ")";
        }

        return BaseColumns._ID + "=" + rowId + andForeignKeyRing + andType + andSelection;
    }

    /**
     * Build default selection statement for UserIds. If no extra selection is specified only build
     * where clause with rowId
     *
     * @param uri
     * @param selection
     * @return
     */
    private String buildDefaultUserIdsSelection(Uri uri, String selection) {
        String rowId = uri.getLastPathSegment();

        String foreignKeyRingRowId = uri.getPathSegments().get(2);
        String andForeignKeyRing = " AND " + KeysColumns.KEY_RING_ROW_ID + " = "
                + foreignKeyRingRowId;

        String andSelection = "";
        if (!TextUtils.isEmpty(selection)) {
            andSelection = " AND (" + selection + ")";
        }

        return BaseColumns._ID + "=" + rowId + andForeignKeyRing + andSelection;
    }

    private void sendBroadcastDatabaseChange(int keyType, String contentItemType) {
    }
}
