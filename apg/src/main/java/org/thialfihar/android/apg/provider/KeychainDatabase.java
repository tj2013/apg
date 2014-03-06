/*
 * Copyright (C) 2010-2014 Thialfihar <thi@thialfihar.org>
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

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.provider.BaseColumns;

import org.thialfihar.android.apg.Constants;
import org.thialfihar.android.apg.provider.KeychainContract.KeyRingsColumns;
import org.thialfihar.android.apg.provider.KeychainContract.KeysColumns;
import org.thialfihar.android.apg.provider.KeychainContract.UserIdsColumns;
import org.thialfihar.android.apg.util.Log;

public class KeychainDatabase extends SQLiteOpenHelper {
    private static final String DATABASE_NAME = "apg";
    private static final int DATABASE_VERSION = 2;

    public interface Tables {
        String KEY_RINGS = "key_rings";
        String KEYS = "keys";
        String USER_IDS = "user_ids";
    }

    private static final String CREATE_KEY_RINGS =
        "CREATE TABLE IF NOT EXISTS " + Tables.KEY_RINGS +
            " (" +
                BaseColumns._ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                KeyRingsColumns.MASTER_KEY_ID + " INT64, " +
                KeyRingsColumns.TYPE + " INTEGER, " +
                KeyRingsColumns.KEY_RING_DATA + " BLOB " +
            ")";

    private static final String CREATE_KEYS =
        "CREATE TABLE IF NOT EXISTS " + Tables.KEYS +
            " (" +
                BaseColumns._ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                KeysColumns.KEY_ID + " INT64, " +
                KeysColumns.TYPE + " INTEGER, " +
                KeysColumns.IS_MASTER_KEY + " INTEGER, " +
                KeysColumns.ALGORITHM + " INTEGER, " +
                KeysColumns.KEY_SIZE + " INTEGER, " +
                KeysColumns.CAN_SIGN + " INTEGER, " +
                KeysColumns.CAN_CERTIFY + " INTEGER, " +
                KeysColumns.CAN_ENCRYPT + " INTEGER, " +
                KeysColumns.IS_REVOKED + " INTEGER, " +
                KeysColumns.CREATION + " INTEGER, " +
                KeysColumns.EXPIRY + " INTEGER, " +
                KeysColumns.KEY_RING_ROW_ID + " INTEGER, " +
                KeysColumns.KEY_DATA + " BLOB," +
                KeysColumns.RANK + " INTEGER " +
            ")";

    private static final String CREATE_USER_IDS =
        "CREATE TABLE IF NOT EXISTS " + Tables.USER_IDS +
            " (" +
                BaseColumns._ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                UserIdsColumns.KEY_RING_ROW_ID + " INTEGER, " +
                UserIdsColumns.USER_ID + " TEXT, " +
                UserIdsColumns.RANK + " INTEGER " +
            ")";

    KeychainDatabase(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        Log.w(Constants.TAG, "Creating database...");

        db.execSQL(CREATE_KEY_RINGS);
        db.execSQL(CREATE_KEYS);
        db.execSQL(CREATE_USER_IDS);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        Log.w(Constants.TAG, "Upgrading database from version " + oldVersion + " to " + newVersion);

        // Upgrade from oldVersion through all cases to newest one
        for (int version = oldVersion; version < newVersion; ++version) {
            Log.w(Constants.TAG, "Upgrading database to version " + version);

            switch (version) {
                case 3:
                    db.execSQL("ALTER TABLE " + Tables.KEYS + " ADD COLUMN " + KeysColumns.CAN_CERTIFY +
                                    " INTEGER DEFAULT 0;");
                    db.execSQL("UPDATE " + Tables.KEYS + " SET " + KeysColumns.CAN_CERTIFY +
                                    " = 1 WHERE " + KeysColumns.IS_MASTER_KEY + " = 1;");
                    break;
                default:
                    break;
            }
        }
    }

}
