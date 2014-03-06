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

package org.thialfihar.android.apg.core;

import java.util.regex.Pattern;

public final class Constants {
    public static final String TAG = "APG";

    public static final Pattern PGP_MESSAGE =
        Pattern.compile(".*?(-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----).*",
                        Pattern.DOTALL);

    public static final Pattern PGP_SIGNED_MESSAGE =
        Pattern.compile(".*?(-----BEGIN PGP SIGNED MESSAGE-----.*?-----BEGIN PGP SIGNATURE-----" +
                            ".*?-----END PGP SIGNATURE-----).*",
                        Pattern.DOTALL);

    public static final Pattern PGP_PUBLIC_KEY =
        Pattern.compile(".*?(-----BEGIN PGP PUBLIC KEY BLOCK-----" +
                            ".*?-----END PGP PUBLIC KEY BLOCK-----).*",
                        Pattern.DOTALL);

}
