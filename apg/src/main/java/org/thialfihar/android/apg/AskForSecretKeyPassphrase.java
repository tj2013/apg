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

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import org.bouncycastle2.openpgp.PGPException;
import org.bouncycastle2.openpgp.PGPPrivateKey;

import org.thialfihar.android.apg.core.Key;

public class AskForSecretKeyPassphrase {
    public static interface PassphraseCallbackInterface {
        void passphraseCallback(long keyId, String passphrase);
    }

    public static Dialog createDialog(Activity context, long secretKeyId,
                                      PassphraseCallbackInterface callback) {
        AlertDialog.Builder alert = new AlertDialog.Builder(context);

        alert.setTitle(R.string.title_authentication);

        final Key secretKey;
        final Activity activity = context;

        if (secretKeyId == Id.key.symmetric || secretKeyId == Id.key.none) {
            secretKey = null;
            alert.setMessage(context.getString(R.string.passphrase_for_symmetric_encryption));
        } else {
            secretKey = Apg.getSecretKeyRing(secretKeyId).getMasterKey();
            if (secretKey == null) {
                alert.setTitle(R.string.title_key_not_found);
                alert.setMessage(context.getString(R.string.key_not_found, secretKeyId));
                alert.setPositiveButton(android.R.string.ok, new OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        activity.removeDialog(Id.dialog.passphrase);
                    }
                });
                alert.setCancelable(false);
                return alert.create();
            }
            String userId = Apg.getMainUserIdSafe(context, secretKey);
            alert.setMessage(context.getString(R.string.passphrase_for, userId));
        }

        LayoutInflater inflater =
            (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
        View view = inflater.inflate(R.layout.passphrase, null);
        final EditText input = (EditText) view.findViewById(R.id.passphrase);
        final EditText inputNotUsed = (EditText) view.findViewById(R.id.passphraseAgain);
        inputNotUsed.setVisibility(View.GONE);

        alert.setView(view);

        final PassphraseCallbackInterface cb = callback;
        alert.setPositiveButton(android.R.string.ok,
                new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int id) {
                        activity.removeDialog(Id.dialog.passphrase);
                        String passphrase = "" + input.getText();
                        long keyId;
                        if (secretKey != null) {
                            try {
                                PGPPrivateKey testKey = secretKey.extractPrivateKey(passphrase);
                                if (testKey == null) {
                                    Toast.makeText(activity,
                                                   R.string.error_could_not_extract_private_key,
                                                   Toast.LENGTH_SHORT).show();
                                    return;
                                }
                            } catch (PGPException e) {
                                Toast.makeText(activity,
                                               R.string.wrong_passphrase,
                                               Toast.LENGTH_SHORT).show();
                                return;
                            }
                            keyId = secretKey.getKeyId();
                        } else {
                            keyId = Id.key.symmetric;
                        }
                        cb.passphraseCallback(keyId, passphrase);
                    }
                });

        alert.setNegativeButton(android.R.string.cancel,
                                new DialogInterface.OnClickListener() {
                                    public void onClick(DialogInterface dialog, int id) {
                                        activity.removeDialog(Id.dialog.passphrase);
                                    }
                                });

        return alert.create();
    }
}