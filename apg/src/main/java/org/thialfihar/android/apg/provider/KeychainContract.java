/*
 * Copyright (C) 2012-2013 Dominik Schürmann <dominik@dominikschuermann.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.thialfihar.android.apg.provider;

import android.net.Uri;
import android.provider.BaseColumns;

import org.thialfihar.android.apg.Constants;

public class KeychainContract {

    interface KeyRingsColumns {
        String MASTER_KEY_ID = "c_master_key_id";
        String TYPE = "c_type";
        String WHO_ID = "c_who_id";
        String KEY_RING_DATA = "c_key_ring_data";
    }

    interface KeysColumns {
        String KEY_ID = "c_key_id";
        String TYPE = "c_type";
        String IS_MASTER_KEY = "c_is_master_key";
        String ALGORITHM = "c_algorithm";
        String KEY_SIZE = "c_key_size";
        String CAN_SIGN = "c_can_sign";
        String CAN_CERTIFY = "c_can_certify";
        String CAN_ENCRYPT = "c_can_encrypt";
        String IS_REVOKED = "c_is_revoked";
        String CREATION = "c_creation";
        String EXPIRY = "c_expiry";
        String KEY_RING_ROW_ID = "c_key_ring_id";
        String KEY_DATA = "c_key_data";
        String RANK = "c_rank";
    }

    interface UserIdsColumns {
        String KEY_RING_ROW_ID = "c_key_id";
        String USER_ID = "c_user_id";
        String RANK = "c_rank";
    }

    public static final class KeyTypes {
        public static final int PUBLIC = 0;
        public static final int SECRET = 1;
    }

    public static final String AUTHORITY = Constants.PACKAGE_NAME + ".provider";

    private static final Uri AUTHORITY_URI = Uri.parse("content://" + AUTHORITY);

    public static final String BASE_KEY_RINGS = "key_rings";
    public static final String BASE_DATA = "data";

    public static final String PATH_PUBLIC = "public";
    public static final String PATH_SECRET = "secret";

    public static final String PATH_BY_MASTER_KEY_ID = "master_key_id";
    public static final String PATH_BY_KEY_ID = "key_id";
    public static final String PATH_BY_EMAILS = "emails";
    public static final String PATH_BY_LIKE_EMAIL = "like_email";

    public static final String PATH_USER_IDS = "user_ids";
    public static final String PATH_KEYS = "keys";

    public static final String PATH_BY_PACKAGE_NAME = "package_name";

    public static class KeyRings implements KeyRingsColumns, BaseColumns {
        public static final Uri CONTENT_URI =
            AUTHORITY_URI.buildUpon().appendPath(BASE_KEY_RINGS).build();

        /** Use if multiple items get returned */
        public static final String CONTENT_TYPE = "vnd.android.cursor.dir/vnd.thialfihar.apg.key_ring";

        /** Use if a single item is returned */
        public static final String CONTENT_ITEM_TYPE = "vnd.android.cursor.item/vnd.thialfihar.apg.key_ring";

        public static Uri buildPublicKeyRingsUri() {
            return CONTENT_URI.buildUpon().appendPath(PATH_PUBLIC).build();
        }

        public static Uri buildPublicKeyRingsUri(String keyRingRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_PUBLIC).appendPath(keyRingRowId).build();
        }

        public static Uri buildPublicKeyRingsByMasterKeyIdUri(String masterKeyId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_PUBLIC)
                    .appendPath(PATH_BY_MASTER_KEY_ID).appendPath(masterKeyId).build();
        }

        public static Uri buildPublicKeyRingsByKeyIdUri(String keyId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_PUBLIC).appendPath(PATH_BY_KEY_ID)
                    .appendPath(keyId).build();
        }

        public static Uri buildPublicKeyRingsByEmailsUri(String emails) {
            return CONTENT_URI.buildUpon().appendPath(PATH_PUBLIC).appendPath(PATH_BY_EMAILS)
                    .appendPath(emails).build();
        }

        public static Uri buildPublicKeyRingsByLikeEmailUri(String emails) {
            return CONTENT_URI.buildUpon().appendPath(PATH_PUBLIC).appendPath(PATH_BY_LIKE_EMAIL)
                    .appendPath(emails).build();
        }

        public static Uri buildSecretKeyRingsUri() {
            return CONTENT_URI.buildUpon().appendPath(PATH_SECRET).build();
        }

        public static Uri buildSecretKeyRingsUri(String keyRingRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_SECRET).appendPath(keyRingRowId).build();
        }

        public static Uri buildSecretKeyRingsByMasterKeyIdUri(String masterKeyId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_SECRET)
                    .appendPath(PATH_BY_MASTER_KEY_ID).appendPath(masterKeyId).build();
        }

        public static Uri buildSecretKeyRingsByKeyIdUri(String keyId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_SECRET).appendPath(PATH_BY_KEY_ID)
                    .appendPath(keyId).build();
        }

        public static Uri buildSecretKeyRingsByEmailsUri(String emails) {
            return CONTENT_URI.buildUpon().appendPath(PATH_SECRET).appendPath(PATH_BY_EMAILS)
                    .appendPath(emails).build();
        }

        public static Uri buildSecretKeyRingsByLikeEmails(String emails) {
            return CONTENT_URI.buildUpon().appendPath(PATH_SECRET).appendPath(PATH_BY_LIKE_EMAIL)
                    .appendPath(emails).build();
        }
    }

    public static class Keys implements KeysColumns, BaseColumns {
        public static final Uri CONTENT_URI = AUTHORITY_URI.buildUpon()
                .appendPath(BASE_KEY_RINGS).build();

        /** Use if multiple items get returned */
        public static final String CONTENT_TYPE = "vnd.android.cursor.dir/vnd.thialfihar.apg.key";

        /** Use if a single item is returned */
        public static final String CONTENT_ITEM_TYPE = "vnd.android.cursor.item/vnd.thialfihar.apg.key";

        public static Uri buildPublicKeysUri(String keyRingRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_PUBLIC).appendPath(keyRingRowId)
                    .appendPath(PATH_KEYS).build();
        }

        public static Uri buildPublicKeysUri(String keyRingRowId, String keyRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_PUBLIC).appendPath(keyRingRowId)
                    .appendPath(PATH_KEYS).appendPath(keyRowId).build();
        }

        public static Uri buildSecretKeysUri(String keyRingRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_SECRET).appendPath(keyRingRowId)
                    .appendPath(PATH_KEYS).build();
        }

        public static Uri buildSecretKeysUri(String keyRingRowId, String keyRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_SECRET).appendPath(keyRingRowId)
                    .appendPath(PATH_KEYS).appendPath(keyRowId).build();
        }

        public static Uri buildKeysUri(Uri keyRingUri) {
            return keyRingUri.buildUpon().appendPath(PATH_KEYS).build();
        }

        public static Uri buildKeysUri(Uri keyRingUri, String keyRowId) {
            return keyRingUri.buildUpon().appendPath(PATH_KEYS).appendPath(keyRowId).build();
        }
    }

    public static class UserIds implements UserIdsColumns, BaseColumns {
        public static final Uri CONTENT_URI = AUTHORITY_URI.buildUpon()
                .appendPath(BASE_KEY_RINGS).build();

        /** Use if multiple items get returned */
        public static final String CONTENT_TYPE = "vnd.android.cursor.dir/vnd.thialfihar.apg.user_id";

        /** Use if a single item is returned */
        public static final String CONTENT_ITEM_TYPE = "vnd.android.cursor.item/vnd.thialfihar.apg.user_id";

        public static Uri buildPublicUserIdsUri(String keyRingRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_PUBLIC).appendPath(keyRingRowId)
                    .appendPath(PATH_USER_IDS).build();
        }

        public static Uri buildPublicUserIdsUri(String keyRingRowId, String userIdRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_PUBLIC).appendPath(keyRingRowId)
                    .appendPath(PATH_USER_IDS).appendPath(userIdRowId).build();
        }

        public static Uri buildSecretUserIdsUri(String keyRingRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_SECRET).appendPath(keyRingRowId)
                    .appendPath(PATH_USER_IDS).build();
        }

        public static Uri buildSecretUserIdsUri(String keyRingRowId, String userIdRowId) {
            return CONTENT_URI.buildUpon().appendPath(PATH_SECRET).appendPath(keyRingRowId)
                    .appendPath(PATH_USER_IDS).appendPath(userIdRowId).build();
        }

        public static Uri buildUserIdsUri(Uri keyRingUri) {
            return keyRingUri.buildUpon().appendPath(PATH_USER_IDS).build();
        }

        public static Uri buildUserIdsUri(Uri keyRingUri, String userIdRowId) {
            return keyRingUri.buildUpon().appendPath(PATH_USER_IDS).appendPath(userIdRowId).build();
        }
    }

    public static class DataStream {
        public static final Uri CONTENT_URI = AUTHORITY_URI.buildUpon()
                .appendPath(BASE_DATA).build();

        public static Uri buildDataStreamUri(String streamFilename) {
            return CONTENT_URI.buildUpon().appendPath(streamFilename).build();
        }
    }

    private KeychainContract() {
    }
}
