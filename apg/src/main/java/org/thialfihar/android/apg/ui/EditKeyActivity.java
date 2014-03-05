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

package org.thialfihar.android.apg.ui;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.os.Message;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Toast;

import org.bouncycastle2.openpgp.PGPException;

import org.thialfihar.android.apg.Apg;
import org.thialfihar.android.apg.Constants;
import org.thialfihar.android.apg.Id;
import org.thialfihar.android.apg.R;
import org.thialfihar.android.apg.core.Key;
import org.thialfihar.android.apg.core.KeyRing;
import org.thialfihar.android.apg.provider.Database;
import org.thialfihar.android.apg.service.PassphraseCacheService;
import org.thialfihar.android.apg.ui.widget.KeyEditor;
import org.thialfihar.android.apg.ui.widget.SectionView;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Vector;

public class EditKeyActivity extends BaseActivity implements OnClickListener {

    private KeyRing mKeyRing = null;

    private SectionView mUserIds;
    private SectionView mKeys;

    private Button mSaveButton;
    private Button mDiscardButton;

    private String mCurrentPassPhrase = null;
    private String mNewPassPhrase = null;

    private Button mChangePassPhrase;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.edit_key);

        Vector<String> userIds = new Vector<String>();
        Vector<Key> keys = new Vector<Key>();

        Intent intent = getIntent();
        long keyId = 0;
        if (intent.getExtras() != null) {
            keyId = intent.getExtras().getLong(Apg.EXTRA_KEY_ID);
        }

        if (keyId != 0) {
            Key masterKey = null;
            mKeyRing = Apg.getSecretKeyRing(keyId);
            if (mKeyRing != null) {
                masterKey = mKeyRing.getMasterKey();
                for (Key key : mKeyRing.getSecretKeys()) {
                    keys.add(key);
                }
            }
            if (masterKey != null) {
                for (String userId : masterKey.getUserIds()) {
                    userIds.add(userId);
                }
            }
        }

        mChangePassPhrase = (Button) findViewById(R.id.btn_change_pass_phrase);
        mChangePassPhrase.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                showDialog(Id.dialog.new_pass_phrase);
            }
        });

        mSaveButton = (Button) findViewById(R.id.btn_save);
        mDiscardButton = (Button) findViewById(R.id.btn_discard);

        mSaveButton.setOnClickListener(this);
        mDiscardButton.setOnClickListener(this);

        LayoutInflater inflater =
                (LayoutInflater) getSystemService(Context.LAYOUT_INFLATER_SERVICE);

        LinearLayout container = (LinearLayout) findViewById(R.id.container);
        mUserIds = (SectionView) inflater.inflate(R.layout.edit_key_section, container, false);
        mUserIds.setType(Id.type.user_id);
        mUserIds.setUserIds(userIds);
        container.addView(mUserIds);
        mKeys = (SectionView) inflater.inflate(R.layout.edit_key_section, container, false);
        mKeys.setType(Id.type.key);
        mKeys.setKeys(keys);
        container.addView(mKeys);

        mCurrentPassPhrase = Apg.getEditPassPhrase();
        if (mCurrentPassPhrase == null) {
            mCurrentPassPhrase = "";
        }

        updatePassPhraseButtonText();

        Toast.makeText(this, getString(R.string.warning_message, getString(R.string.key_editing_is_beta)),
                       Toast.LENGTH_LONG).show();
    }

    private long getMasterKeyId() {
        if (mKeys.getEditors().getChildCount() == 0) {
            return 0;
        }
        return ((KeyEditor) mKeys.getEditors().getChildAt(0)).getValue().getKeyId();
    }

    public boolean havePassPhrase() {
        return (!mCurrentPassPhrase.equals("")) ||
               (mNewPassPhrase != null && !mNewPassPhrase.equals(""));
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        menu.add(0, Id.menu.option.preferences, 0, R.string.menu_preferences)
                .setIcon(android.R.drawable.ic_menu_preferences);
        menu.add(0, Id.menu.option.about, 1, R.string.menu_about)
                .setIcon(android.R.drawable.ic_menu_info_details);
        return true;
    }

    @Override
    protected Dialog onCreateDialog(int id) {
        switch (id) {
            case Id.dialog.new_pass_phrase: {
                AlertDialog.Builder alert = new AlertDialog.Builder(this);

                if (havePassPhrase()) {
                    alert.setTitle(R.string.title_change_pass_phrase);
                } else {
                    alert.setTitle(R.string.title_set_pass_phrase);
                }
                alert.setMessage(R.string.enter_pass_phrase_twice);

                LayoutInflater inflater =
                    (LayoutInflater) getSystemService(Context.LAYOUT_INFLATER_SERVICE);
                View view = inflater.inflate(R.layout.pass_phrase, null);
                final EditText input1 = (EditText) view.findViewById(R.id.passPhrase);
                final EditText input2 = (EditText) view.findViewById(R.id.passPhraseAgain);

                alert.setView(view);

                alert.setPositiveButton(android.R.string.ok,
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int id) {
                                                removeDialog(Id.dialog.new_pass_phrase);

                                                String passPhrase1 = "" + input1.getText();
                                                String passPhrase2 = "" + input2.getText();
                                                if (!passPhrase1.equals(passPhrase2)) {
                                                    showDialog(Id.dialog.pass_phrases_do_not_match);
                                                    return;
                                                }

                                                if (passPhrase1.equals("")) {
                                                    showDialog(Id.dialog.no_pass_phrase);
                                                    return;
                                                }

                                                mNewPassPhrase = passPhrase1;
                                                updatePassPhraseButtonText();
                                            }
                                        });

                alert.setNegativeButton(android.R.string.cancel,
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int id) {
                                                removeDialog(Id.dialog.new_pass_phrase);
                                            }
                                        });

                return alert.create();
            }

            default: {
                return super.onCreateDialog(id);
            }
        }
    }

    public void onClick(View v) {
        if (v == mSaveButton) {
            // TODO: some warning
            saveClicked();
        } else if (v == mDiscardButton) {
            finish();
        }
    }

    private void saveClicked() {
        if (!havePassPhrase()) {
            Toast.makeText(this, R.string.set_a_pass_phrase, Toast.LENGTH_SHORT).show();
            return;
        }
        showDialog(Id.dialog.saving);
        startThread();
    }

    @Override
    public void run() {
        String error = null;
        Bundle data = new Bundle();
        Message msg = new Message();

        try {
            String oldPassPhrase = mCurrentPassPhrase;
            String newPassPhrase = mNewPassPhrase;
            if (newPassPhrase == null) {
                newPassPhrase = oldPassPhrase;
            }
            Apg.buildSecretKey(this, mUserIds, mKeys, oldPassPhrase, newPassPhrase, this);
            PassphraseCacheService.addCachedPassphrase(this, getMasterKeyId(), newPassPhrase);
        } catch (NoSuchProviderException e) {
            error = "" + e;
        } catch (NoSuchAlgorithmException e) {
            error = "" + e;
        } catch (PGPException e) {
            error = "" + e;
        } catch (SignatureException e) {
            error = "" + e;
        } catch (Apg.GeneralException e) {
            error = "" + e;
        } catch (Database.GeneralException e) {
            error = "" + e;
        } catch (IOException e) {
            error = "" + e;
        }

        data.putInt(Constants.extras.status, Id.message.done);

        if (error != null) {
            data.putString(Apg.EXTRA_ERROR, error);
        }

        msg.setData(data);
        sendMessage(msg);
    }

    @Override
    public void doneCallback(Message msg) {
        super.doneCallback(msg);

        Bundle data = msg.getData();
        removeDialog(Id.dialog.saving);

        String error = data.getString(Apg.EXTRA_ERROR);
        if (error != null) {
            Toast.makeText(EditKeyActivity.this,
                           getString(R.string.error_message, error), Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(EditKeyActivity.this, R.string.key_saved, Toast.LENGTH_SHORT).show();
            setResult(RESULT_OK);
            finish();
        }
    }

    private void updatePassPhraseButtonText() {
        mChangePassPhrase.setText(
                havePassPhrase() ? R.string.btn_change_pass_phrase : R.string.btn_set_pass_phrase);
    }
}
