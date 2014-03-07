/*
 * Copyright (C) 2012-2014 Dominik Schürmann <dominik@dominikschuermann.de>
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

import android.content.Intent;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;

import org.thialfihar.android.apg.R;
//import org.thialfihar.android.apg.helper.ExportHelper;

public class PublicKeyListActivity extends DrawerActivity {

    //ExportHelper mExportHelper;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        //mExportHelper = new ExportHelper(this);

        setContentView(R.layout.public_key_list_activity);

        // now setup navigation drawer in DrawerActivity...
        setupDrawerNavigation(savedInstanceState);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        super.onCreateOptionsMenu(menu);
        getMenuInflater().inflate(R.menu.public_key_list, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
        case R.id.menu_public_key_list_import:
            //Intent intentImport = new Intent(this, ImportKeysActivity.class);
            //startActivityForResult(intentImport, 0);

            return true;
        case R.id.menu_public_key_list_export:
            //mExportHelper.showExportKeysDialog(null, Id.type.public_key, Constants.path.APP_DIR
            //        + "/pubexport.asc");

            return true;
        default:
            return super.onOptionsItemSelected(item);
        }
    }

}
