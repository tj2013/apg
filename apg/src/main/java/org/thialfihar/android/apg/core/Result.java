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

package org.thialfihar.android.apg.core;

public class Result {
    // keys
    public static final String NEW_KEY = "new_key";
    public static final String NEW_KEY2 = "new_key2";

    // encrypt
    public static final String SIGNATURE_BYTES = "signature_data";
    public static final String SIGNATURE_STRING = "signature_text";
    public static final String ENCRYPTED_STRING = "encrypted_message";
    public static final String ENCRYPTED_BYTES = "encrypted_data";
    public static final String URI = "result_uri";

    // decrypt/verify
    public static final String DECRYPTED_STRING = "decrypted_message";
    public static final String DECRYPTED_BYTES = "decrypted_data";
    public static final String SIGNATURE = "signature";
    public static final String SIGNATURE_KEY_ID = "signature_key_id";
    public static final String SIGNATURE_USER_ID = "signature_user_id";
    public static final String CLEARTEXT_SIGNATURE_ONLY = "signature_only";

    public static final String SIGNATURE_SUCCESS = "signature_success";
    public static final String SIGNATURE_UNKNOWN = "signature_unknown";

    // import
    public static final String IMPORT_ADDED = "added";
    public static final String IMPORT_UPDATED = "updated";
    public static final String IMPORT_BAD = "bad";

    // export
    public static final String EXPORT = "exported";

    // query
    public static final String QUERY_KEY_DATA = "query_key_data";
    public static final String QUERY_KEY_SEARCH_RESULT = "query_key_search_result";
}
