/*
 * Copyright (C) 2013 Dominik Schürmann <dominik@dominikschuermann.de>
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

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.Messenger;
import android.support.v4.app.Fragment;
import android.support.v4.app.LoaderManager;
import android.support.v4.content.CursorLoader;
import android.support.v4.content.Loader;
import android.view.ActionMode;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.AbsListView.MultiChoiceModeListener;
import android.widget.AdapterView;
import android.widget.ListView;
import android.widget.Toast;

import com.beardedhen.androidbootstrap.BootstrapButton;

import org.thialfihar.android.apg.Id;
import org.thialfihar.android.apg.R;
import org.thialfihar.android.apg.provider.KeychainContract;
import org.thialfihar.android.apg.provider.KeychainContract.KeyRings;
import org.thialfihar.android.apg.provider.KeychainContract.UserIds;
import org.thialfihar.android.apg.provider.ProviderHelper;
import org.thialfihar.android.apg.ui.adapter.PublicKeyListAdapter;
import org.thialfihar.android.apg.ui.dialog.DeleteKeyDialogFragment;

import se.emilsjolander.stickylistheaders.ApiLevelTooLowException;
import se.emilsjolander.stickylistheaders.StickyListHeadersListView;

import java.util.ArrayList;
import java.util.Set;

/**
 * Public key list with sticky list headers. It does _not_ extend ListFragment because it uses
 * StickyListHeaders library which does not extend upon ListView.
 */
public class PublicKeyListFragment extends Fragment implements AdapterView.OnItemClickListener,
        LoaderManager.LoaderCallbacks<Cursor> {

    private PublicKeyListAdapter mAdapter;
    private StickyListHeadersListView mStickyList;

    // empty list layout
    private BootstrapButton mButtonEmptyCreate;
    private BootstrapButton mButtonEmptyImport;

    /**
     * Load custom layout with StickyListView from library
     */
    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.public_key_list_fragment, container, false);

        mButtonEmptyCreate = (BootstrapButton) view.findViewById(R.id.key_list_empty_button_create);
        mButtonEmptyCreate.setOnClickListener(new OnClickListener() {

            @Override
            public void onClick(View v) {
                Intent intent = new Intent(getActivity(), EditKeyActivity.class);
                intent.setAction(EditKeyActivity.ACTION_CREATE_KEY);
                intent.putExtra(EditKeyActivity.EXTRA_GENERATE_DEFAULT_KEYS, true);
                intent.putExtra(EditKeyActivity.EXTRA_USER_IDS, ""); // show user id view
                startActivityForResult(intent, 0);
            }
        });

        mButtonEmptyImport = (BootstrapButton) view.findViewById(R.id.key_list_empty_button_import);
        mButtonEmptyImport.setOnClickListener(new OnClickListener() {

            @Override
            public void onClick(View v) {
                //Intent intent = new Intent(getActivity(), ImportKeysActivity.class);
                //intent.setAction(ImportKeysActivity.ACTION_IMPORT_KEY_FROM_FILE);
                //startActivityForResult(intent, 0);
            }
        });

        return view;
    }

    /**
     * Define Adapter and Loader on create of Activity
     */
    @SuppressLint("NewApi")
    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);

        mStickyList = (StickyListHeadersListView) getActivity().findViewById(R.id.list);

        mStickyList.setOnItemClickListener(this);
        mStickyList.setAreHeadersSticky(true);
        mStickyList.setDrawingListUnderStickyHeader(false);
        mStickyList.setFastScrollEnabled(true);
        try {
            mStickyList.setFastScrollAlwaysVisible(true);
        } catch (ApiLevelTooLowException e) {
        }

        // this view is made visible if no data is available
        mStickyList.setEmptyView(getActivity().findViewById(R.id.empty));

        /*
         * ActionBarSherlock does not support MultiChoiceModeListener. Thus multi-selection is only
         * available for Android >= 3.0
         */
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB) {
            mStickyList.setChoiceMode(ListView.CHOICE_MODE_MULTIPLE_MODAL);
            mStickyList.getWrappedList().setMultiChoiceModeListener(new MultiChoiceModeListener() {

                private int count = 0;

                @Override
                public boolean onCreateActionMode(ActionMode mode, Menu menu) {
                    android.view.MenuInflater inflater = getActivity().getMenuInflater();
                    inflater.inflate(R.menu.public_key_list_multi, menu);
                    return true;
                }

                @Override
                public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
                    return false;
                }

                @Override
                public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
                    Set<Integer> positions = mAdapter.getCurrentCheckedPosition();

                    // get IDs for checked positions as long array
                    long[] ids = new long[positions.size()];
                    int i = 0;
                    for (int pos : positions) {
                        ids[i] = mAdapter.getItemId(pos);
                        i++;
                    }

                    switch (item.getItemId()) {
                        case R.id.menu_public_key_list_multi_encrypt: {
                            encrypt(mode, ids);
                            break;
                        }
                        case R.id.menu_public_key_list_multi_delete: {
                            showDeleteKeyDialog(mode, ids);
                            break;
                        }
                    }
                    return true;
                }

                @Override
                public void onDestroyActionMode(ActionMode mode) {
                    count = 0;
                    mAdapter.clearSelection();
                }

                @Override
                public void onItemCheckedStateChanged(ActionMode mode, int position, long id,
                                                      boolean checked) {
                    if (checked) {
                        count++;
                        mAdapter.setNewSelection(position, checked);
                    } else {
                        count--;
                        mAdapter.removeSelection(position);
                    }

                    String keysSelected = getResources().getQuantityString(
                            R.plurals.key_list_selected_keys, count, count);
                    mode.setTitle(keysSelected);
                }

            });
        }

        // NOTE: Not supported by StickyListHeader, thus no indicator is shown while loading
        // Start out with a progress indicator.
        // setListShown(false);

        // Create an empty adapter we will use to display the loaded data.
        mAdapter = new PublicKeyListAdapter(getActivity(), null, Id.type.public_key, USER_ID_INDEX);
        mStickyList.setAdapter(mAdapter);

        // Prepare the loader. Either re-connect with an existing one,
        // or start a new one.
        getLoaderManager().initLoader(0, null, this);
    }

    // These are the rows that we will retrieve.
    static final String[] PROJECTION = new String[]{
            KeychainContract.KeyRings._ID,
            KeychainContract.KeyRings.MASTER_KEY_ID,
            KeychainContract.UserIds.USER_ID,
            KeychainContract.Keys.IS_REVOKED
    };

    static final int USER_ID_INDEX = 2;

    static final String SORT_ORDER = UserIds.USER_ID + " ASC";

    @Override
    public Loader<Cursor> onCreateLoader(int id, Bundle args) {
        // This is called when a new Loader needs to be created. This
        // sample only has one Loader, so we don't care about the ID.
        Uri baseUri = KeyRings.buildPublicKeyRingsUri();

        // Now create and return a CursorLoader that will take care of
        // creating a Cursor for the data being displayed.
        return new CursorLoader(getActivity(), baseUri, PROJECTION, null, null, SORT_ORDER);
    }

    @Override
    public void onLoadFinished(Loader<Cursor> loader, Cursor data) {
        // Swap the new cursor in. (The framework will take care of closing the
        // old cursor once we return.)
        mAdapter.swapCursor(data);

        mStickyList.setAdapter(mAdapter);

        // NOTE: Not supported by StickyListHeader, thus no indicator is shown while loading
        // The list should now be shown.
        // if (isResumed()) {
        // setListShown(true);
        // } else {
        // setListShownNoAnimation(true);
        // }
    }

    @Override
    public void onLoaderReset(Loader<Cursor> loader) {
        // This is called when the last Cursor provided to onLoadFinished()
        // above is about to be closed. We need to make sure we are no
        // longer using it.
        mAdapter.swapCursor(null);
    }

    /**
     * On click on item, start key view activity
     */
    @Override
    public void onItemClick(AdapterView<?> adapterView, View view, int position, long id) {
        Intent viewIntent = null;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN) {
            viewIntent = new Intent(getActivity(), ViewKeyActivity.class);
        } else {
            viewIntent = new Intent(getActivity(), ViewKeyActivityJellyBean.class);
        }
        viewIntent.setData(KeychainContract.KeyRings.buildPublicKeyRingsUri(Long.toString(id)));
        startActivity(viewIntent);
    }

    @TargetApi(11)
    public void encrypt(ActionMode mode, long[] keyRingRowIds) {
        // get master key ids from row ids
        long[] keyRingIds = new long[keyRingRowIds.length];
        for (int i = 0; i < keyRingRowIds.length; i++) {
            keyRingIds[i] = ProviderHelper.getPublicMasterKeyId(getActivity(), keyRingRowIds[i]);
        }

        Intent intent = new Intent(getActivity(), EncryptActivity.class);
        intent.setAction(EncryptActivity.ACTION_ENCRYPT);
        intent.putExtra(EncryptActivity.EXTRA_ENCRYPTION_KEY_IDS, keyRingIds);
        // used instead of startActivity set actionbar based on callingPackage
        startActivityForResult(intent, 0);

        mode.finish();
    }

    /**
     * Show dialog to delete key
     *
     * @param keyRingRowIds
     */
    @TargetApi(11)
    public void showDeleteKeyDialog(final ActionMode mode, long[] keyRingRowIds) {
        // Message is received after key is deleted
        Handler returnHandler = new Handler() {
            @Override
            public void handleMessage(Message message) {
                if (message.what == DeleteKeyDialogFragment.MESSAGE_OKAY) {
                    Bundle returnData = message.getData();
                    if (returnData != null
                            && returnData.containsKey(DeleteKeyDialogFragment.MESSAGE_NOT_DELETED)) {
                        ArrayList<String> notDeleted =
                                returnData.getStringArrayList(DeleteKeyDialogFragment.MESSAGE_NOT_DELETED);
                        String notDeletedMsg = "";
                        for (String userId : notDeleted) {
                            notDeletedMsg += userId + "\n";
                        }
                        Toast.makeText(getActivity(), getString(R.string.error_can_not_delete_contacts, notDeletedMsg)
                                + getResources().getQuantityString(R.plurals.error_can_not_delete_info, notDeleted.size()),
                                Toast.LENGTH_LONG).show();

                        mode.finish();
                    }
                }
            }
        };

        // Create a new Messenger for the communication back
        Messenger messenger = new Messenger(returnHandler);

        DeleteKeyDialogFragment deleteKeyDialog = DeleteKeyDialogFragment.newInstance(messenger,
                keyRingRowIds, Id.type.public_key);

        deleteKeyDialog.show(getActivity().getSupportFragmentManager(), "deleteKeyDialog");
    }

}
