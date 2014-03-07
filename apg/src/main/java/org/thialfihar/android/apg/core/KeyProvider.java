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

public interface KeyProvider {
    public KeyRing getPublicKeyRingByRowId(long rowId);
    public KeyRing getPublicKeyRingByMasterKeyId(long masterKeyId);
    public KeyRing getPublicKeyRingByKeyId(long keyId);
    public KeyRing getSecretKeyRingByRowId(long rowId);
    public KeyRing getSecretKeyRingByMasterKeyId(long masterKeyId);
    public KeyRing getSecretKeyRingByKeyId(long keyId);
    public Key getPublicKeyByKeyId(long keyId);
    public Key getSecretKeyByKeyId(long keyId);
}
