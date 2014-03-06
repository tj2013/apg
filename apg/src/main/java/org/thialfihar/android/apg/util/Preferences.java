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

package org.thialfihar.android.apg.util;

import android.content.Context;
import android.content.SharedPreferences;

import org.bouncycastle2.bcpg.HashAlgorithmTags;
import org.bouncycastle2.openpgp.PGPEncryptedData;

import org.thialfihar.android.apg.Constants;
import org.thialfihar.android.apg.Id;

import java.util.Vector;

public class Preferences {
    private static Preferences sPreferences;
    private SharedPreferences mSharedPreferences;

    public static synchronized Preferences getPreferences(Context context) {
        if (sPreferences == null) {
            sPreferences = new Preferences(context);
        }
        return sPreferences;
    }

    private Preferences(Context context) {
        mSharedPreferences = context.getSharedPreferences("APG.main", Context.MODE_PRIVATE);
    }

    public String getLanguage() {
        return mSharedPreferences.getString(Constants.pref.language, "");
    }

    public void setLanguage(String value) {
        SharedPreferences.Editor editor = mSharedPreferences.edit();
        editor.putString(Constants.pref.language, value);
        editor.commit();
    }

    public int getPassPhraseCacheTtl() {
        int ttl = mSharedPreferences.getInt(Constants.pref.pass_phrase_cache_ttl, 180);
        // fix the value if it was set to "never" in previous versions, which currently is not
        // supported
        if (ttl == 0) {
            ttl = 180;
        }
        return ttl;
    }

    public void setPassPhraseCacheTtl(int value) {
        SharedPreferences.Editor editor = mSharedPreferences.edit();
        editor.putInt(Constants.pref.pass_phrase_cache_ttl, value);
        editor.commit();
    }

    public int getDefaultEncryptionAlgorithm() {
        return mSharedPreferences.getInt(Constants.pref.default_encryption_algorithm,
                                         PGPEncryptedData.AES_256);
    }

    public void setDefaultEncryptionAlgorithm(int value) {
        SharedPreferences.Editor editor = mSharedPreferences.edit();
        editor.putInt(Constants.pref.default_encryption_algorithm, value);
        editor.commit();
    }

    public int getDefaultHashAlgorithm() {
        return mSharedPreferences.getInt(Constants.pref.default_hash_algorithm,
                                         HashAlgorithmTags.SHA256);
    }

    public void setDefaultHashAlgorithm(int value) {
        SharedPreferences.Editor editor = mSharedPreferences.edit();
        editor.putInt(Constants.pref.default_hash_algorithm, value);
        editor.commit();
    }

    public int getDefaultMessageCompression() {
        return mSharedPreferences.getInt(Constants.pref.default_message_compression,
                                         Id.choice.compression.zlib);
    }

    public void setDefaultMessageCompression(int value) {
        SharedPreferences.Editor editor = mSharedPreferences.edit();
        editor.putInt(Constants.pref.default_message_compression, value);
        editor.commit();
    }

    public int getDefaultFileCompression() {
        return mSharedPreferences.getInt(Constants.pref.default_file_compression,
                                         Id.choice.compression.none);
    }

    public void setDefaultFileCompression(int value) {
        SharedPreferences.Editor editor = mSharedPreferences.edit();
        editor.putInt(Constants.pref.default_file_compression, value);
        editor.commit();
    }

    public boolean getDefaultAsciiArmor() {
        return mSharedPreferences.getBoolean(Constants.pref.default_ascii_armor, false);
    }

    public void setDefaultAsciiArmor(boolean value) {
        SharedPreferences.Editor editor = mSharedPreferences.edit();
        editor.putBoolean(Constants.pref.default_ascii_armor, value);
        editor.commit();
    }

    public boolean getForceV3Signatures() {
        return mSharedPreferences.getBoolean(Constants.pref.force_v3_signatures, false);
    }

    public void setForceV3Signatures(boolean value) {
        SharedPreferences.Editor editor = mSharedPreferences.edit();
        editor.putBoolean(Constants.pref.force_v3_signatures, value);
        editor.commit();
    }

    public boolean hasSeenChangeLog(String version) {
        return mSharedPreferences.getBoolean(Constants.pref.has_seen_change_log + version,
                                       false);
    }

    public void setHasSeenChangeLog(String version, boolean value) {
        SharedPreferences.Editor editor = mSharedPreferences.edit();
        editor.putBoolean(Constants.pref.has_seen_change_log + version, value);
        editor.commit();
    }

    public boolean hasSeenHelp() {
        return mSharedPreferences.getBoolean(Constants.pref.has_seen_help, false);
    }

    public void setHasSeenHelp(boolean value) {
        SharedPreferences.Editor editor = mSharedPreferences.edit();
        editor.putBoolean(Constants.pref.has_seen_help, value);
        editor.commit();
    }

    public String[] getKeyServers() {
        String rawData = mSharedPreferences.getString(Constants.pref.key_servers,
                                                      Constants.defaults.key_servers);
        Vector<String> servers = new Vector<String>();
        String chunks[] = rawData.split(",");
        for (int i = 0; i < chunks.length; ++i) {
            String tmp = chunks[i].trim();
            if (tmp.length() > 0) {
                servers.add(tmp);
            }
        }
        return servers.toArray(chunks);
    }

    public void setKeyServers(String[] value) {
        SharedPreferences.Editor editor = mSharedPreferences.edit();
        String rawData = "";
        for (int i = 0; i < value.length; ++i) {
            String tmp = value[i].trim();
            if (tmp.length() == 0) {
                continue;
            }
            if (!"".equals(rawData)) {
                rawData += ",";
            }
            rawData += tmp;
        }
        editor.putString(Constants.pref.key_servers, rawData);
        editor.commit();
    }
}
