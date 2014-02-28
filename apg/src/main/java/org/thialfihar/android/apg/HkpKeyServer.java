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

import android.text.Html;

import org.thialfihar.android.apg.util.Utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HkpKeyServer extends KeyServer {
    private static class HttpError extends Exception {
        private static final long serialVersionUID = 1718783705229428893L;
        private int mCode;
        private String mData;

        public HttpError(int code, String data) {
            super("" + code + ": " + data);
            mCode = code;
            mData = data;
        }

        public int getCode() {
            return mCode;
        }

        public String getData() {
            return mData;
        }
    }
    private String mHost;
    private short mPort = 11371;

    public static final Pattern PUB_KEY_LINE =
        Pattern.compile(
            "pub +([0-9]+)([a-z]+)/.*?0x([0-9a-z]+).*? +([0-9-]+) +(.+)[\n\r]+((?:    +.+[\n\r]+)*)",
            Pattern.CASE_INSENSITIVE);
    public static final Pattern USER_ID_LINE =
        Pattern.compile("^   +(.+)$", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);

    public static long keyIdFromHex(String data) {
        return Long.parseLong(data, 16);
    }

    public HkpKeyServer(String host) {
        mHost = host;
    }

    public HkpKeyServer(String host, short port) {
        mHost = host;
        mPort = port;
    }

    private static String readAll(InputStream in, String encoding) throws IOException {
        ByteArrayOutputStream raw = new ByteArrayOutputStream();

        byte buffer[] = new byte[1 << 16];
        int n = 0;
        while ((n = in.read(buffer)) != -1) {
            raw.write(buffer, 0, n);
        }

        if (encoding == null) {
            encoding = "utf8";
        }
        return raw.toString(encoding);
    }

    private String query(String request)
            throws QueryException, HttpError {
        InetAddress ips[];
        try {
            ips = InetAddress.getAllByName(mHost);
        } catch (UnknownHostException e) {
            throw new QueryException(e.toString());
        }
        for (int i = 0; i < ips.length; ++i) {
            try {
                String url = "http://" + ips[i].getHostAddress() + ":" + mPort + request;
                URL realUrl = new URL(url);
                HttpURLConnection conn = (HttpURLConnection) realUrl.openConnection();
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(25000);
                conn.connect();
                int response = conn.getResponseCode();
                if (response >= 200 && response < 300) {
                    return readAll(conn.getInputStream(), conn.getContentEncoding());
                } else {
                    String data = readAll(conn.getErrorStream(), conn.getContentEncoding());
                    throw new HttpError(response, data);
                }
            } catch (MalformedURLException e) {
                // nothing to do, try next IP
            } catch (IOException e) {
                // nothing to do, try next IP
            }
        }

        throw new QueryException("querying server(s) for '" + mHost + "' failed");
    }

    @Override
    List<KeyInfo> search(String query)
            throws QueryException, TooManyResponses, InsufficientQuery {
        Vector<KeyInfo> results = new Vector<KeyInfo>();

        if (query.length() < 3) {
            throw new InsufficientQuery();
        }

        String encodedQuery;
        try {
            encodedQuery = URLEncoder.encode(query, "utf8");
        } catch (UnsupportedEncodingException e) {
            return null;
        }
        String request = "/pks/lookup?op=index&search=" + encodedQuery;

        String data = null;
        try {
            data = query(request);
        } catch (HttpError e) {
            if (e.getCode() == 404) {
                return results;
            } else {
                if (e.getData().toLowerCase().contains("no keys found")) {
                    return results;
                } else if (e.getData().toLowerCase().contains("too many")) {
                    throw new TooManyResponses();
                } else if (e.getData().toLowerCase().contains("insufficient")) {
                    throw new InsufficientQuery();
                }
            }
            throw new QueryException("querying server(s) for '" + mHost + "' failed");
        }

        Matcher matcher = PUB_KEY_LINE.matcher(data);
        while (matcher.find()) {
            KeyInfo info = new KeyInfo();
            info.size = Integer.parseInt(matcher.group(1));
            info.algorithm = matcher.group(2);
            info.keyId = keyIdFromHex(matcher.group(3));
            info.fingerPrint = Utils.toHexString(info.keyId, 8);
            String chunks[] = matcher.group(4).split("-");
            info.date = new GregorianCalendar(Integer.parseInt(chunks[0]),
                                              Integer.parseInt(chunks[1]),
                                              Integer.parseInt(chunks[2])).getTime();
            info.userIds = new Vector<String>();
            if (matcher.group(5).startsWith("*** KEY")) {
                info.revoked = matcher.group(5);
            } else {
                String tmp = matcher.group(5).replaceAll("<.*?>", "");
                tmp = Html.fromHtml(tmp).toString();
                info.userIds.add(tmp);
            }
            if (matcher.group(6).length() > 0) {
                Matcher matcher2 = USER_ID_LINE.matcher(matcher.group(6));
                while (matcher2.find()) {
                    String tmp = matcher2.group(1).replaceAll("<.*?>", "");
                    tmp = Html.fromHtml(tmp).toString();
                    info.userIds.add(tmp);
                }
            }
            results.add(info);
        }

        return results;
    }

    @Override
    String get(long keyId)
            throws QueryException {
        String request = "/pks/lookup?op=get&search=0x" + Utils.toHexString(keyId, 8);

        String data = null;
        try {
            data = query(request);
        } catch (HttpError e) {
            throw new QueryException("not found");
        }
        Matcher matcher = Apg.PGP_PUBLIC_KEY.matcher(data);
        if (matcher.find()) {
            return matcher.group(1);
        }

        return null;
    }
}
