/*
 * Copyright (C) 2014 Dominik Schürmann <dominik@dominikschuermann.de>
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

package org.thialfihar.android.apg.ui;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.TextView;

import com.beardedhen.androidbootstrap.BootstrapButton;

import org.bouncycastle2.openpgp.PGPSecretKey;
import org.bouncycastle2.openpgp.PGPSecretKeyRing;

import org.thialfihar.android.apg.Id;
import org.thialfihar.android.apg.R;
//import org.thialfihar.android.apg.pgp.PgpKeyHelper;
//import org.thialfihar.android.apg.provider.ProviderHelper;

public class SelectSecretKeyLayoutFragment extends Fragment {

    private TextView mKeyUserId;
    private TextView mKeyUserIdRest;
    private BootstrapButton mSelectKeyButton;
    private Boolean mFilterCertify;

    private SelectSecretKeyCallback mCallback;

    private static final int REQUEST_CODE_SELECT_KEY = 8882;

    public interface SelectSecretKeyCallback {
        void onKeySelected(long secretKeyId);
    }

    public void setCallback(SelectSecretKeyCallback callback) {
        mCallback = callback;
    }

    public void setFilterCertify(Boolean filterCertify) {
        mFilterCertify = filterCertify;
    }

    public void selectKey(long secretKeyId) {
        if (secretKeyId == Id.key.none) {
            mKeyUserId.setText(R.string.api_settings_no_key);
            mKeyUserIdRest.setText("");
        } else {
            String uid = getResources().getString(R.string.user_id_no_name);
            String uidExtra = "";
            PGPSecretKeyRing keyRing = null;//ProviderHelper.getPGPSecretKeyRingByMasterKeyId(
                    //getActivity(), secretKeyId);
            if (keyRing != null) {
                PGPSecretKey key = null;//PgpKeyHelper.getMasterKey(keyRing);
                if (key != null) {
                    String userId = "";//PgpKeyHelper.getMainUserIdSafe(getActivity(), key);
                    String chunks[] = userId.split(" <", 2);
                    uid = chunks[0];
                    if (chunks.length > 1) {
                        uidExtra = "<" + chunks[1];
                    }
                }
            }
            mKeyUserId.setText(uid);
            mKeyUserIdRest.setText(uidExtra);
        }
    }

    public void setError(String error) {
        mKeyUserId.requestFocus();
        mKeyUserId.setError(error);
    }

    /**
     * Inflate the layout for this fragment
     */
    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.select_secret_key_layout_fragment, container, false);

        mKeyUserId = (TextView) view.findViewById(R.id.select_secret_key_user_id);
        mKeyUserIdRest = (TextView) view.findViewById(R.id.select_secret_key_user_id_rest);
        mSelectKeyButton = (BootstrapButton) view
                .findViewById(R.id.select_secret_key_select_key_button);
        mFilterCertify = false;
        mSelectKeyButton.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                startSelectKeyActivity();
            }
        });

        return view;
    }

    private void startSelectKeyActivity() {
        Intent intent = new Intent(getActivity(), SelectSecretKeyActivity.class);
        intent.putExtra(SelectSecretKeyActivity.EXTRA_FILTER_CERTIFY, mFilterCertify);
        startActivityForResult(intent, REQUEST_CODE_SELECT_KEY);
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        switch (requestCode & 0xFFFF) {
        case REQUEST_CODE_SELECT_KEY: {
            long secretKeyId;
            if (resultCode == Activity.RESULT_OK) {
                Bundle bundle = data.getExtras();
                secretKeyId = bundle.getLong(SelectSecretKeyActivity.RESULT_EXTRA_MASTER_KEY_ID);

                selectKey(secretKeyId);

                // remove displayed errors
                mKeyUserId.setError(null);

                // give value back to callback
                mCallback.onKeySelected(secretKeyId);
            }
            break;
        }

        default:
            super.onActivityResult(requestCode, resultCode, data);

            break;
        }
    }
}
