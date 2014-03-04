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

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Vector;

public abstract class KeyServer {
    public static class QueryException extends Exception {
        private static final long serialVersionUID = 2703768928624654512L;
        public QueryException(String message) {
            super(message);
        }
    }
    public static class TooManyResponses extends Exception {
        private static final long serialVersionUID = 2703768928624654513L;
    }
    public static class InsufficientQuery extends Exception {
        private static final long serialVersionUID = 2703768928624654514L;
    }
    public static class KeyInfo implements Serializable {
        private static final long serialVersionUID = -7797972113284992662L;
        public Vector<String> userIds;
        public String revoked;
        public Date date;
        public String fingerPrint;
        public long keyId;
        public int size;
        public String algorithm;
    }
    abstract List<KeyInfo> search(String query) throws QueryException, TooManyResponses, InsufficientQuery;
    abstract String get(long keyId) throws QueryException;
}
