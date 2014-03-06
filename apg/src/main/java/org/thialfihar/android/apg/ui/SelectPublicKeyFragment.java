/*
 * Copyright (C) 2012-2013 Dominik Schürmann <dominik@dominikschuermann.de>
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

import android.app.Activity;
import android.database.Cursor;
import android.database.DatabaseUtils;
import android.net.Uri;
import android.os.Bundle;
import android.support.v4.app.LoaderManager;
import android.support.v4.content.CursorLoader;
import android.support.v4.content.Loader;
import android.widget.ListView;

import org.thialfihar.android.apg.Id;
import org.thialfihar.android.apg.R;
import org.thialfihar.android.apg.compatibility.ListFragmentWorkaround;
import org.thialfihar.android.apg.provider.KeychainContract.KeyRings;
import org.thialfihar.android.apg.provider.KeychainContract.Keys;
import org.thialfihar.android.apg.provider.KeychainContract.UserIds;
import org.thialfihar.android.apg.provider.KeychainDatabase;
import org.thialfihar.android.apg.provider.KeychainDatabase.Tables;
import org.thialfihar.android.apg.ui.adapter.SelectKeyCursorAdapter;

import java.util.Date;
import java.util.Vector;

public class SelectPublicKeyFragment extends ListFragmentWorkaround implements
        LoaderManager.LoaderCallbacks<Cursor> {
    public static final String ARG_PRESELECTED_KEY_IDS = "preselected_key_ids";

    private Activity mActivity;
    private SelectKeyCursorAdapter mAdapter;
    private ListView mListView;

    private long mSelectedMasterKeyIds[];

    /**
     * Creates new instance of this fragment
     */
    public static SelectPublicKeyFragment newInstance(long[] preselectedKeyIds) {
        SelectPublicKeyFragment frag = new SelectPublicKeyFragment();
        Bundle args = new Bundle();

        args.putLongArray(ARG_PRESELECTED_KEY_IDS, preselectedKeyIds);

        frag.setArguments(args);

        return frag;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mSelectedMasterKeyIds = getArguments().getLongArray(ARG_PRESELECTED_KEY_IDS);
    }

    /**
     * Define Adapter and Loader on create of Activity
     */
    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);

        mActivity = getActivity();
        mListView = getListView();

        mListView.setChoiceMode(ListView.CHOICE_MODE_MULTIPLE);

        // Give some text to display if there is no data. In a real
        // application this would come from a resource.
        setEmptyText(getString(R.string.list_empty));

        mAdapter = new SelectKeyCursorAdapter(mActivity, null, 0, mListView, Id.type.public_key);

        setListAdapter(mAdapter);

        // Start out with a progress indicator.
        setListShown(false);

        // Prepare the loader. Either re-connect with an existing one,
        // or start a new one.
        getLoaderManager().initLoader(0, null, this);
    }

    /**
     * Selects items based on master key ids in list view
     *
     * @param masterKeyIds
     */
    private void preselectMasterKeyIds(long[] masterKeyIds) {
        if (masterKeyIds != null) {
            for (int i = 0; i < mListView.getCount(); ++i) {
                long keyId = mAdapter.getMasterKeyId(i);
                for (int j = 0; j < masterKeyIds.length; ++j) {
                    if (keyId == masterKeyIds[j]) {
                        mListView.setItemChecked(i, true);
                        break;
                    }
                }
            }
        }
    }

    /**
     * Returns all selected master key ids
     *
     * @return
     */
    public long[] getSelectedMasterKeyIds() {
        // mListView.getCheckedItemIds() would give the row ids of the KeyRings not the master key
        // ids!
        Vector<Long> vector = new Vector<Long>();
        for (int i = 0; i < mListView.getCount(); ++i) {
            if (mListView.isItemChecked(i)) {
                vector.add(mAdapter.getMasterKeyId(i));
            }
        }

        // convert to long array
        long[] selectedMasterKeyIds = new long[vector.size()];
        for (int i = 0; i < vector.size(); ++i) {
            selectedMasterKeyIds[i] = vector.get(i);
        }

        return selectedMasterKeyIds;
    }

    /**
     * Returns all selected user ids
     *
     * @return
     */
    public String[] getSelectedUserIds() {
        Vector<String> userIds = new Vector<String>();
        for (int i = 0; i < mListView.getCount(); ++i) {
            if (mListView.isItemChecked(i)) {
                userIds.add((String) mAdapter.getUserId(i));
            }
        }

        // make empty array to not return null
        String userIdArray[] = new String[0];
        return userIds.toArray(userIdArray);
    }

    @Override
    public Loader<Cursor> onCreateLoader(int id, Bundle args) {
        // This is called when a new Loader needs to be created. This
        // sample only has one Loader, so we don't care about the ID.
        Uri baseUri = KeyRings.buildPublicKeyRingsUri();

        // These are the rows that we will retrieve.
        long now = new Date().getTime() / 1000;
        String[] projection = new String[] {
                KeyRings._ID,
                KeyRings.MASTER_KEY_ID,
                UserIds.USER_ID,
                "(SELECT COUNT(available_keys." + Keys._ID + ") FROM " + Tables.KEYS
                        + " AS available_keys WHERE available_keys." + Keys.KEY_RING_ROW_ID + " = "
                        + KeychainDatabase.Tables.KEY_RINGS + "." + KeyRings._ID
                        + " AND available_keys." + Keys.IS_REVOKED + " = '0' AND  available_keys."
                        + Keys.CAN_ENCRYPT + " = '1') AS "
                        + SelectKeyCursorAdapter.PROJECTION_ROW_AVAILABLE,
                "(SELECT COUNT(valid_keys." + Keys._ID + ") FROM " + Tables.KEYS
                        + " AS valid_keys WHERE valid_keys." + Keys.KEY_RING_ROW_ID + " = "
                        + KeychainDatabase.Tables.KEY_RINGS + "." + KeyRings._ID
                        + " AND valid_keys." + Keys.IS_REVOKED + " = '0' AND valid_keys."
                        + Keys.CAN_ENCRYPT + " = '1' AND valid_keys." + Keys.CREATION + " <= '"
                        + now + "' AND " + "(valid_keys." + Keys.EXPIRY + " IS NULL OR valid_keys."
                        + Keys.EXPIRY + " >= '" + now + "')) AS "
                        + SelectKeyCursorAdapter.PROJECTION_ROW_VALID, };

        String inMasterKeyList = null;
        if (mSelectedMasterKeyIds != null && mSelectedMasterKeyIds.length > 0) {
            inMasterKeyList = KeyRings.MASTER_KEY_ID + " IN (";
            for (int i = 0; i < mSelectedMasterKeyIds.length; ++i) {
                if (i != 0) {
                    inMasterKeyList += ", ";
                }
                inMasterKeyList += DatabaseUtils.sqlEscapeString("" + mSelectedMasterKeyIds[i]);
            }
            inMasterKeyList += ")";
        }

        // if (searchString != null && searchString.trim().length() > 0) {
        // String[] chunks = searchString.trim().split(" +");
        // qb.appendWhere("(EXISTS (SELECT tmp." + UserIds._ID + " FROM " + UserIds.TABLE_NAME
        // + " AS tmp WHERE " + "tmp." + UserIds.KEY_ID + " = " + Keys.TABLE_NAME + "."
        // + Keys._ID);
        // for (int i = 0; i < chunks.length; ++i) {
        // qb.appendWhere(" AND tmp." + UserIds.USER_ID + " LIKE ");
        // qb.appendWhereEscapeString("%" + chunks[i] + "%");
        // }
        // qb.appendWhere("))");
        //
        // if (inIdList != null) {
        // qb.appendWhere(" OR (" + inIdList + ")");
        // }
        // }

        String orderBy = UserIds.USER_ID + " ASC";
        if (inMasterKeyList != null) {
            // sort by selected master keys
            orderBy = inMasterKeyList + " DESC, " + orderBy;
        }

        // Now create and return a CursorLoader that will take care of
        // creating a Cursor for the data being displayed.
        return new CursorLoader(getActivity(), baseUri, projection, null, null, orderBy);
    }

    @Override
    public void onLoadFinished(Loader<Cursor> loader, Cursor data) {
        // Swap the new cursor in. (The framework will take care of closing the
        // old cursor once we return.)
        mAdapter.swapCursor(data);

        // The list should now be shown.
        if (isResumed()) {
            setListShown(true);
        } else {
            setListShownNoAnimation(true);
        }

        // preselect given master keys
        preselectMasterKeyIds(mSelectedMasterKeyIds);
    }

    @Override
    public void onLoaderReset(Loader<Cursor> loader) {
        // This is called when the last Cursor provided to onLoadFinished()
        // above is about to be closed. We need to make sure we are no
        // longer using it.
        mAdapter.swapCursor(null);
    }
}
