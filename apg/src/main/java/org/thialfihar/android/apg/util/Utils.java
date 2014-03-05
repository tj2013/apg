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
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager.NameNotFoundException;

import org.thialfihar.android.apg.Constants;

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

public class Utils {

    public static long getNumDaysBetween(Date first, GregorianCalendar second) {
        GregorianCalendar tmp = new GregorianCalendar();
        tmp.setTime(first);
        return getNumDaysBetween(tmp, second);
    }

    public static long getNumDaysBetween(GregorianCalendar first, GregorianCalendar second) {
        // TODO: this probably can be done more elegantly
        GregorianCalendar tmp = new GregorianCalendar();
        tmp.setTime(first.getTime());
        long numDays = (second.getTimeInMillis() - first.getTimeInMillis()) / 1000 / 86400;
        tmp.add(Calendar.DAY_OF_MONTH, (int) numDays);
        while (tmp.before(second)) {
            tmp.add(Calendar.DAY_OF_MONTH, 1);
            ++numDays;
        }
        return numDays;
    }

    public static String toHexString(long keyId, int length) {
        String s = Long.toHexString(keyId).toUpperCase();
        while (s.length() < length) {
            s = "0" + s;
        }
        if (s.length() > length) {
            s = s.substring(0, length);
        }
        return s;
    }

    public static String generateRandomString(int length) {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[length];
        random.nextBytes(bytes);
        String result = "";
        for (int i = 0; i < length; ++i) {
            int v = (bytes[i] + 256) % 64;
            if (v < 10) {
                result += (char) ('0' + v);
            } else if (v < 36) {
                result += (char) ('A' + v - 10);
            } else if (v < 62) {
                result += (char) ('a' + v - 36);
            } else if (v == 62) {
                result += '_';
            } else if (v == 63) {
                result += '.';
            }
        }
        return result;
    }

    public static long getLengthOfStream(InputStream in) throws IOException {
        long size = 0;
        long n = 0;
        byte dummy[] = new byte[0x10000];
        while ((n = in.read(dummy)) > 0) {
            size += n;
        }
        return size;
    }

    public static boolean isReleaseVersion(Context context) {
        try {
            PackageInfo pi = context.getPackageManager().getPackageInfo(Constants.PACKAGE_NAME, 0);
            if (pi.versionCode % 100 == 99) {
                return true;
            } else {
                return false;
            }
        } catch (NameNotFoundException e) {
            // unpossible!
            return false;
        }
    }

    public static String getVersion(Context context) {
        try {
            PackageInfo pi = context.getPackageManager().getPackageInfo(Constants.PACKAGE_NAME, 0);
            return pi.versionName;
        } catch (NameNotFoundException e) {
            // unpossible!
            return "0.0.0";
        }
    }

    public static String getFullVersion(Context context) {
        return "APG v" + getVersion(context);
    }
}
