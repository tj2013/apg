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

package org.thialfihar.android.apg;

import android.app.Application;
import android.os.Environment;

import org.bouncycastle2.jce.provider.BouncyCastleProvider;
import org.thialfihar.android.apg.util.PrngFixes;

import java.io.File;
import java.security.Security;

public class ApgApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();

        Security.insertProviderAt(new BouncyCastleProvider(), 1);

        // fix random number generator for Android <= SDK 17
        PrngFixes.apply();

        // Create APG directory on sdcard if not existing
        if (Environment.getExternalStorageState().equals(Environment.MEDIA_MOUNTED)) {
            File dir = new File(Constants.path.app_dir);
            if (!dir.exists() && !dir.mkdirs()) {
                // ignore this for now, it's not crucial
                // that the directory doesn't exist at this point
            }
        }
    }
}
