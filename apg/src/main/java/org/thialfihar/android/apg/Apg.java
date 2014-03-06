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
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.os.Message;
import android.view.ViewGroup;

import org.bouncycastle2.bcpg.ArmoredInputStream;
import org.bouncycastle2.bcpg.ArmoredOutputStream;
import org.bouncycastle2.bcpg.BCPGOutputStream;
import org.bouncycastle2.bcpg.CompressionAlgorithmTags;
import org.bouncycastle2.bcpg.HashAlgorithmTags;
import org.bouncycastle2.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle2.bcpg.sig.KeyFlags;
import org.bouncycastle2.jce.provider.BouncyCastleProvider;
import org.bouncycastle2.jce.spec.ElGamalParameterSpec;
import org.bouncycastle2.openpgp.PGPCompressedData;
import org.bouncycastle2.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle2.openpgp.PGPEncryptedData;
import org.bouncycastle2.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle2.openpgp.PGPEncryptedDataList;
import org.bouncycastle2.openpgp.PGPException;
import org.bouncycastle2.openpgp.PGPKeyPair;
import org.bouncycastle2.openpgp.PGPKeyRingGenerator;
import org.bouncycastle2.openpgp.PGPLiteralData;
import org.bouncycastle2.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle2.openpgp.PGPObjectFactory;
import org.bouncycastle2.openpgp.PGPOnePassSignature;
import org.bouncycastle2.openpgp.PGPOnePassSignatureList;
import org.bouncycastle2.openpgp.PGPPBEEncryptedData;
import org.bouncycastle2.openpgp.PGPPrivateKey;
import org.bouncycastle2.openpgp.PGPPublicKey;
import org.bouncycastle2.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle2.openpgp.PGPPublicKeyRing;
import org.bouncycastle2.openpgp.PGPSecretKey;
import org.bouncycastle2.openpgp.PGPSecretKeyRing;
import org.bouncycastle2.openpgp.PGPSignature;
import org.bouncycastle2.openpgp.PGPSignatureGenerator;
import org.bouncycastle2.openpgp.PGPSignatureList;
import org.bouncycastle2.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle2.openpgp.PGPUtil;
import org.bouncycastle2.openpgp.PGPV3SignatureGenerator;

import org.thialfihar.android.apg.core.Key;
import org.thialfihar.android.apg.core.KeyRing;
import org.thialfihar.android.apg.core.Progressable;
import org.thialfihar.android.apg.provider.DataProvider;
import org.thialfihar.android.apg.provider.Database;
import org.thialfihar.android.apg.provider.KeyRings;
import org.thialfihar.android.apg.provider.Keys;
import org.thialfihar.android.apg.provider.UserIds;
import org.thialfihar.android.apg.ui.BaseActivity;
import org.thialfihar.android.apg.ui.widget.KeyEditor;
import org.thialfihar.android.apg.ui.widget.SectionView;
import org.thialfihar.android.apg.ui.widget.UserIdEditor;
import org.thialfihar.android.apg.util.InputData;
import org.thialfihar.android.apg.util.PositionAwareInputStream;
import org.thialfihar.android.apg.util.Utils;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;
import java.util.Vector;

public class Apg {
    public static class Intent {
        public static final String DECRYPT = "org.thialfihar.android.apg.intent.DECRYPT";
        public static final String ENCRYPT = "org.thialfihar.android.apg.intent.ENCRYPT";
        public static final String DECRYPT_FILE = "org.thialfihar.android.apg.intent.DECRYPT_FILE";
        public static final String ENCRYPT_FILE = "org.thialfihar.android.apg.intent.ENCRYPT_FILE";
        public static final String DECRYPT_AND_RETURN = "org.thialfihar.android.apg.intent.DECRYPT_AND_RETURN";
        public static final String ENCRYPT_AND_RETURN = "org.thialfihar.android.apg.intent.ENCRYPT_AND_RETURN";
        public static final String SELECT_PUBLIC_KEYS = "org.thialfihar.android.apg.intent.SELECT_PUBLIC_KEYS";
        public static final String SELECT_SECRET_KEY = "org.thialfihar.android.apg.intent.SELECT_SECRET_KEY";
        public static final String IMPORT = "org.thialfihar.android.apg.intent.IMPORT";
        public static final String LOOK_UP_KEY_ID = "org.thialfihar.android.apg.intent.LOOK_UP_KEY_ID";
        public static final String LOOK_UP_KEY_ID_AND_RETURN = "org.thialfihar.android.apg.intent.LOOK_UP_KEY_ID_AND_RETURN";
        public static final String GENERATE_SIGNATURE = "org.thialfihar.android.apg.intent.GENERATE_SIGNATURE";
    }

    public static final String EXTRA_TEXT = "text";
    public static final String EXTRA_DATA = "data";
    public static final String EXTRA_ERROR = "error";
    public static final String EXTRA_DECRYPTED_MESSAGE = "decryptedMessage";
    public static final String EXTRA_DECRYPTED_DATA = "decryptedData";
    public static final String EXTRA_ENCRYPTED_MESSAGE = "encryptedMessage";
    public static final String EXTRA_ENCRYPTED_DATA = "encryptedData";
    public static final String EXTRA_RESULT_URI = "resultUri";
    public static final String EXTRA_SIGNATURE = "signature";
    public static final String EXTRA_SIGNATURE_KEY_ID = "signatureKeyId";
    public static final String EXTRA_SIGNATURE_USER_ID = "signatureUserId";
    public static final String EXTRA_SIGNATURE_SUCCESS = "signatureSuccess";
    public static final String EXTRA_SIGNATURE_UNKNOWN = "signatureUnknown";
    public static final String EXTRA_SIGNATURE_DATA = "signatureData";
    public static final String EXTRA_SIGNATURE_TEXT = "signatureText";
    public static final String EXTRA_USER_ID = "userId";
    public static final String EXTRA_USER_IDS = "userIds";
    public static final String EXTRA_KEY_ID = "keyId";
    public static final String EXTRA_REPLY_TO = "replyTo";
    public static final String EXTRA_SEND_TO = "sendTo";
    public static final String EXTRA_SUBJECT = "subject";
    public static final String EXTRA_ENCRYPTION_KEY_IDS = "encryptionKeyIds";
    public static final String EXTRA_SELECTION = "selection";
    public static final String EXTRA_ASCII_ARMOUR = "asciiArmor";
    public static final String EXTRA_BINARY = "binary";
    public static final String EXTRA_KEY_SERVERS = "keyServers";

    public static final String AUTHORITY = DataProvider.AUTHORITY;

    public static final Uri CONTENT_URI_SECRET_KEY_RINGS =
            Uri.parse("content://" + AUTHORITY + "/key_rings/secret/");
    public static final Uri CONTENT_URI_SECRET_KEY_RING_BY_KEY_ID =
            Uri.parse("content://" + AUTHORITY + "/key_rings/secret/key_id/");
    public static final Uri CONTENT_URI_SECRET_KEY_RING_BY_EMAILS =
            Uri.parse("content://" + AUTHORITY + "/key_rings/secret/emails/");

    public static final Uri CONTENT_URI_PUBLIC_KEY_RINGS =
            Uri.parse("content://" + AUTHORITY + "/key_rings/public/");
    public static final Uri CONTENT_URI_PUBLIC_KEY_RING_BY_KEY_ID =
            Uri.parse("content://" + AUTHORITY + "/key_rings/public/key_id/");
    public static final Uri CONTENT_URI_PUBLIC_KEY_RING_BY_EMAILS =
            Uri.parse("content://" + AUTHORITY + "/key_rings/public/emails/");

    private static final int[] PREFERRED_SYMMETRIC_ALGORITHMS =
            new int[] {
                    SymmetricKeyAlgorithmTags.AES_256,
                    SymmetricKeyAlgorithmTags.AES_192,
                    SymmetricKeyAlgorithmTags.AES_128,
                    SymmetricKeyAlgorithmTags.CAST5,
                    SymmetricKeyAlgorithmTags.TRIPLE_DES };
    private static final int[] PREFERRED_HASH_ALGORITHMS =
            new int[] {
                    HashAlgorithmTags.SHA1,
                    HashAlgorithmTags.SHA256,
                    HashAlgorithmTags.RIPEMD160 };
    private static final int[] PREFERRED_COMPRESSION_ALGORITHMS =
            new int[] {
                    CompressionAlgorithmTags.ZLIB,
                    CompressionAlgorithmTags.BZIP2,
                    CompressionAlgorithmTags.ZIP };

    private static String sEditPassPhrase = null;
    private static Database sDatabase = null;

    public static class GeneralException extends Exception {
        static final long serialVersionUID = 0xf812773342L;

        public GeneralException(String message) {
            super(message);
        }
    }

    public static class NoAsymmetricEncryptionException extends Exception {
        static final long serialVersionUID = 0xf812773343L;

        public NoAsymmetricEncryptionException() {
            super();
        }
    }

    public static void initialize(Context context) {
        if (sDatabase == null) {
            sDatabase = new Database(context);
        }
    }

    public static Database getDatabase() {
        return sDatabase;
    }

    public static void setEditPassPhrase(String passPhrase) {
        sEditPassPhrase = passPhrase;
    }

    public static String getEditPassPhrase() {
        return sEditPassPhrase;
    }
    public static Key createKey(Context context,
                                int algorithmChoice, int keySize, String passPhrase,
                                Key masterKey)
                  throws NoSuchAlgorithmException, PGPException, NoSuchProviderException,
                  GeneralException, InvalidAlgorithmParameterException {

        if (keySize < 512) {
            throw new GeneralException(context.getString(R.string.error_key_size_minimum_512bit));
        }

        Security.addProvider(new BouncyCastleProvider());

        if (passPhrase == null) {
            passPhrase = "";
        }

        int algorithm = 0;
        KeyPairGenerator keyGen = null;

        switch (algorithmChoice) {
            case Id.choice.algorithm.dsa: {
                keyGen = KeyPairGenerator.getInstance("DSA", new BouncyCastleProvider());
                keyGen.initialize(keySize, new SecureRandom());
                algorithm = PGPPublicKey.DSA;
                break;
            }

            case Id.choice.algorithm.elgamal: {
                if (masterKey == null) {
                    throw new GeneralException(context.getString(R.string.error_master_key_must_not_be_el_gamal));
                }
                keyGen = KeyPairGenerator.getInstance("ELGAMAL", new BouncyCastleProvider());
                BigInteger p = Primes.getBestPrime(keySize);
                BigInteger g = new BigInteger("2");

                ElGamalParameterSpec elParams = new ElGamalParameterSpec(p, g);

                keyGen.initialize(elParams);
                algorithm = PGPPublicKey.ELGAMAL_ENCRYPT;
                break;
            }

            case Id.choice.algorithm.rsa: {
                keyGen = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
                keyGen.initialize(keySize, new SecureRandom());

                algorithm = PGPPublicKey.RSA_GENERAL;
                break;
            }

            default: {
                throw new GeneralException(context.getString(R.string.error_unknown_algorithm_choice));
            }
        }

        PGPKeyPair keyPair = new PGPKeyPair(algorithm, keyGen.generateKeyPair(), new Date());

        PGPSecretKey secretKey = null;
        if (masterKey == null) {
            // enough for now, as we assemble the key again later anyway
            secretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, keyPair, "",
                                         PGPEncryptedData.CAST5, passPhrase.toCharArray(),
                                         null, null,
                                         new SecureRandom(), new BouncyCastleProvider().getName());

        } else {
            PGPPublicKey tmpKey = masterKey.getPublicKey();
            PGPPublicKey masterPublicKey =
                new PGPPublicKey(tmpKey.getAlgorithm(),
                                 tmpKey.getKey(new BouncyCastleProvider()),
                                 tmpKey.getCreationTime());
            PGPPrivateKey masterPrivateKey = masterKey.extractPrivateKey(passPhrase);

            PGPKeyPair masterKeyPair = new PGPKeyPair(masterPublicKey, masterPrivateKey);
            PGPKeyRingGenerator ringGen =
                new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION,
                                        masterKeyPair, "",
                                        PGPEncryptedData.CAST5, passPhrase.toCharArray(),
                                        null, null,
                                        new SecureRandom(), new BouncyCastleProvider().getName());
            ringGen.addSubKey(keyPair);
            PGPSecretKeyRing secKeyRing = ringGen.generateSecretKeyRing();
            Iterator<PGPSecretKey> it = secKeyRing.getSecretKeys();
            // first one is the master key
            it.next();
            secretKey = it.next();
        }

        return new Key(secretKey);
    }

    public static void buildSecretKey(Activity context,
                                      SectionView userIdsView, SectionView keysView,
                                      String oldPassPhrase, String newPassPhrase,
                                      Progressable progress)
            throws Apg.GeneralException, NoSuchProviderException, PGPException,
            NoSuchAlgorithmException, SignatureException, IOException, Database.GeneralException {

        progress.setProgress(R.string.progress_building_key, 0, 100);

        Security.addProvider(new BouncyCastleProvider());

        if (oldPassPhrase == null || oldPassPhrase.equals("")) {
            oldPassPhrase = "";
        }

        if (newPassPhrase == null || newPassPhrase.equals("")) {
            newPassPhrase = "";
        }

        Vector<String> userIds = new Vector<String>();
        Vector<Key> keys = new Vector<Key>();

        ViewGroup userIdEditors = userIdsView.getEditors();
        ViewGroup keyEditors = keysView.getEditors();

        boolean gotMainUserId = false;
        for (int i = 0; i < userIdEditors.getChildCount(); ++i) {
            UserIdEditor editor = (UserIdEditor) userIdEditors.getChildAt(i);
            String userId = null;
            try {
                userId = editor.getValue();
            } catch (UserIdEditor.NoNameException e) {
                throw new Apg.GeneralException(context.getString(R.string.error_user_id_needs_a_name));
            } catch (UserIdEditor.NoEmailException e) {
                throw new Apg.GeneralException(context.getString(R.string.error_user_id_needs_an_email_address));
            } catch (UserIdEditor.InvalidEmailException e) {
                throw new Apg.GeneralException("" + e);
            }

            if (userId.equals("")) {
                continue;
            }

            if (editor.isMainUserId()) {
                userIds.insertElementAt(userId, 0);
                gotMainUserId = true;
            } else {
                userIds.add(userId);
            }
        }

        if (userIds.size() == 0) {
            throw new Apg.GeneralException(context.getString(R.string.error_key_needs_a_user_id));
        }

        if (!gotMainUserId) {
            throw new Apg.GeneralException(context.getString(R.string.error_main_user_id_must_not_be_empty));
        }

        if (keyEditors.getChildCount() == 0) {
            throw new Apg.GeneralException(context.getString(R.string.error_key_needs_master_key));
        }

        for (int i = 0; i < keyEditors.getChildCount(); ++i) {
            KeyEditor editor = (KeyEditor) keyEditors.getChildAt(i);
            keys.add(editor.getValue());
        }

        progress.setProgress(R.string.progress_preparing_master_key, 10, 100);
        KeyEditor keyEditor = (KeyEditor) keyEditors.getChildAt(0);
        int usageId = keyEditor.getUsage();
        boolean canSign = (usageId == Id.choice.usage.sign_only ||
                           usageId == Id.choice.usage.sign_and_encrypt);
        boolean canEncrypt = (usageId == Id.choice.usage.encrypt_only ||
                              usageId == Id.choice.usage.sign_and_encrypt);

        String mainUserId = userIds.get(0);

        Key masterKey = keys.get(0);
        PGPPublicKey tmpKey = masterKey.getPublicKey();
        PGPPublicKey masterPublicKey =
            new PGPPublicKey(tmpKey.getAlgorithm(),
                             tmpKey.getKey(new BouncyCastleProvider()),
                             tmpKey.getCreationTime());
        PGPPrivateKey masterPrivateKey = masterKey.extractPrivateKey(oldPassPhrase);

        progress.setProgress(R.string.progress_certifying_master_key, 20, 100);
        for (int i = 0; i < userIds.size(); ++i) {
            String userId = userIds.get(i);

            PGPSignatureGenerator sGen =
                    new PGPSignatureGenerator(masterPublicKey.getAlgorithm(),
                                              HashAlgorithmTags.SHA1, new BouncyCastleProvider());

            sGen.initSign(PGPSignature.POSITIVE_CERTIFICATION, masterPrivateKey);

            PGPSignature certification = sGen.generateCertification(userId, masterPublicKey);

            masterPublicKey = PGPPublicKey.addCertification(masterPublicKey, userId, certification);
        }

        // TODO: cross-certify the master key with every sub key

        PGPKeyPair masterKeyPair = new PGPKeyPair(masterPublicKey, masterPrivateKey);

        PGPSignatureSubpacketGenerator hashedPacketsGen = new PGPSignatureSubpacketGenerator();
        PGPSignatureSubpacketGenerator unhashedPacketsGen = new PGPSignatureSubpacketGenerator();

        int keyFlags = KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA;
        if (canEncrypt) {
            keyFlags |= KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE;
        }
        hashedPacketsGen.setKeyFlags(true, keyFlags);

        hashedPacketsGen.setPreferredSymmetricAlgorithms(true, PREFERRED_SYMMETRIC_ALGORITHMS);
        hashedPacketsGen.setPreferredHashAlgorithms(true, PREFERRED_HASH_ALGORITHMS);
        hashedPacketsGen.setPreferredCompressionAlgorithms(true, PREFERRED_COMPRESSION_ALGORITHMS);

        // TODO: this doesn't work quite right yet
        if (keyEditor.getExpiryDate() != null) {
            long numDays = Utils.getNumDaysBetween(masterKey.getCreationDate(), keyEditor.getExpiryDate());
            if (numDays <= 0) {
                throw new GeneralException(context.getString(R.string.error_expiry_must_come_after_creation));
            }
            hashedPacketsGen.setKeyExpirationTime(true, numDays * 86400);
        }

        progress.setProgress(R.string.progress_building_master_key_ring, 30, 100);
        PGPKeyRingGenerator keyGen =
                new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION,
                                        masterKeyPair, mainUserId,
                                        PGPEncryptedData.CAST5, newPassPhrase.toCharArray(),
                                        hashedPacketsGen.generate(), unhashedPacketsGen.generate(),
                                        new SecureRandom(), new BouncyCastleProvider().getName());

        progress.setProgress(R.string.progress_adding_sub_keys, 40, 100);
        for (int i = 1; i < keys.size(); ++i) {
            progress.setProgress(40 + 50 * (i - 1) / (keys.size() - 1), 100);
            Key subKey = keys.get(i);
            keyEditor = (KeyEditor) keyEditors.getChildAt(i);
            PGPPublicKey subPublicKey = subKey.getPublicKey();
            PGPPrivateKey subPrivateKey = subKey.extractPrivateKey(oldPassPhrase);
            PGPKeyPair subKeyPair =
                new PGPKeyPair(subPublicKey.getAlgorithm(),
                               subPublicKey.getKey(new BouncyCastleProvider()),
                               subPrivateKey.getKey(),
                               subPublicKey.getCreationTime());

            hashedPacketsGen = new PGPSignatureSubpacketGenerator();
            unhashedPacketsGen = new PGPSignatureSubpacketGenerator();

            keyFlags = 0;
            usageId = keyEditor.getUsage();
            canSign = (usageId == Id.choice.usage.sign_only ||
                       usageId == Id.choice.usage.sign_and_encrypt);
            canEncrypt = (usageId == Id.choice.usage.encrypt_only ||
                          usageId == Id.choice.usage.sign_and_encrypt);
            if (canSign) {
                keyFlags |= KeyFlags.SIGN_DATA;
            }
            if (canEncrypt) {
                keyFlags |= KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE;
            }
            hashedPacketsGen.setKeyFlags(true, keyFlags);

            // TODO: this doesn't work quite right yet
            if (keyEditor.getExpiryDate() != null) {
                long numDays = Utils.getNumDaysBetween(masterKey.getCreationDate(), keyEditor.getExpiryDate());
                if (numDays <= 0) {
                    throw new GeneralException(context.getString(R.string.error_expiry_must_come_after_creation));
                }
                hashedPacketsGen.setKeyExpirationTime(true, numDays * 86400);
            }

            keyGen.addSubKey(subKeyPair,
                             hashedPacketsGen.generate(), unhashedPacketsGen.generate());
        }

        PGPSecretKeyRing secretKeyRing = keyGen.generateSecretKeyRing();
        PGPPublicKeyRing publicKeyRing = keyGen.generatePublicKeyRing();

        progress.setProgress(R.string.progress_saving_key_ring, 90, 100);
        sDatabase.saveKeyRing(new KeyRing(secretKeyRing));
        sDatabase.saveKeyRing(new KeyRing(publicKeyRing));

        progress.setProgress(R.string.progress_done, 100, 100);
    }

    public static Bundle importKeyRings(Activity context, int type,
                                        InputData data,
                                        Progressable progress)
            throws GeneralException, FileNotFoundException, PGPException, IOException {
        Bundle returnData = new Bundle();

        if (type == Id.type.secret_key) {
            progress.setProgress(R.string.progress_importing_secret_keys, 0, 100);
        } else {
            progress.setProgress(R.string.progress_importing_public_keys, 0, 100);
        }

        if (!Environment.getExternalStorageState().equals(Environment.MEDIA_MOUNTED)) {
            throw new GeneralException(context.getString(R.string.error_external_storage_not_ready));
        }

        PositionAwareInputStream progressIn = new PositionAwareInputStream(data.getInputStream());
        // need to have access to the bufferedInput, so we can reuse it for the possible
        // PGPObject chunks after the first one, e.g. files with several consecutive ASCII
        // armor blocks
        BufferedInputStream bufferedInput = new BufferedInputStream(progressIn);
        int newKeys = 0;
        int oldKeys = 0;
        int badKeys = 0;
        try {
            while (true) {
                InputStream in = PGPUtil.getDecoderStream(bufferedInput);
                PGPObjectFactory objectFactory = new PGPObjectFactory(in);
                Object obj = objectFactory.nextObject();
                // if the first is already a null object, then we can stop trying
                if (obj == null) {
                    break;
                }
                while (obj != null) {
                    PGPPublicKeyRing publicKeyRing;
                    PGPSecretKeyRing secretKeyRing;
                    // a return value that doesn't match any Id.return_value.* values, in case
                    // saveKeyRing is never called
                    int retValue = 2107;

                    try {
                        if (type == Id.type.secret_key && obj instanceof PGPSecretKeyRing) {
                            secretKeyRing = (PGPSecretKeyRing) obj;
                            boolean save = true;
                            try {
                                PGPPrivateKey testKey = secretKeyRing.getSecretKey()
                                    .extractPrivateKey(new char[] {},
                                                       new BouncyCastleProvider());
                                if (testKey == null) {
                                    // this is bad, something is very wrong... likely a
                                    // --export-secret-subkeys export
                                    retValue = Id.return_value.bad;
                                    save = false;
                                }
                            } catch (PGPException e) {
                                // all good if this fails, we likely didn't use the right password
                            }
                            if (save) {
                                retValue = sDatabase.saveKeyRing(new KeyRing(secretKeyRing));
                            }
                        } else if (type == Id.type.public_key && obj instanceof PGPPublicKeyRing) {
                            publicKeyRing = (PGPPublicKeyRing) obj;
                            retValue = sDatabase.saveKeyRing(new KeyRing(publicKeyRing));
                        }
                    } catch (IOException e) {
                        retValue = Id.return_value.error;
                    } catch (Database.GeneralException e) {
                        retValue = Id.return_value.error;
                    }

                    if (retValue == Id.return_value.error) {
                        throw new GeneralException(context.getString(R.string.error_saving_keys));
                    }

                    if (retValue == Id.return_value.updated) {
                        ++oldKeys;
                    } else if (retValue == Id.return_value.ok) {
                        ++newKeys;
                    } else if (retValue == Id.return_value.bad) {
                        ++badKeys;
                    }
                    progress.setProgress((int) (100 * progressIn.position() / data.getSize()), 100);
                    obj = objectFactory.nextObject();
                }
            }
        } catch (EOFException e) {
            // nothing to do, we are done
        }

        returnData.putInt("added", newKeys);
        returnData.putInt("updated", oldKeys);
        returnData.putInt("bad", badKeys);

        progress.setProgress(R.string.progress_done, 100, 100);

        return returnData;
    }

    public static Bundle exportKeyRings(Activity context, Vector<Integer> keyRingIds,
                                        OutputStream outStream,
                                        Progressable progress)
            throws GeneralException, FileNotFoundException, PGPException, IOException {
        Bundle returnData = new Bundle();

        if (keyRingIds.size() == 1) {
            progress.setProgress(R.string.progress_exporting_key, 0, 100);
        } else {
            progress.setProgress(R.string.progress_exporting_keys, 0, 100);
        }

        if (!Environment.getExternalStorageState().equals(Environment.MEDIA_MOUNTED)) {
            throw new GeneralException(context.getString(R.string.error_external_storage_not_ready));
        }
        ArmoredOutputStream out = new ArmoredOutputStream(outStream);

        int numKeys = 0;
        for (int i = 0; i < keyRingIds.size(); ++i) {
            progress.setProgress(i * 100 / keyRingIds.size(), 100);
            Object obj = sDatabase.getKeyRing(keyRingIds.get(i));
            PGPPublicKeyRing publicKeyRing;
            PGPSecretKeyRing secretKeyRing;

            if (obj instanceof PGPSecretKeyRing) {
                secretKeyRing = (PGPSecretKeyRing) obj;
                secretKeyRing.encode(out);
            } else if (obj instanceof PGPPublicKeyRing) {
                publicKeyRing = (PGPPublicKeyRing) obj;
                publicKeyRing.encode(out);
            } else {
                continue;
            }
            ++numKeys;
        }
        out.close();
        returnData.putInt("exported", numKeys);

        progress.setProgress(R.string.progress_done, 100, 100);

        return returnData;
    }

    // TODO: this surely belongs in KeyRing
    public static Key getEncryptKey(long masterKeyId) {
        KeyRing keyRing = sDatabase.getPublicKeyRing(masterKeyId);
        if (keyRing == null) {
            return null;
        }
        Vector<Key> encryptKeys = keyRing.getUsableEncryptKeys();
        if (encryptKeys.size() == 0) {
            return null;
        }
        return encryptKeys.get(0);
    }

    // TODO: this surely belongs in KeyRing
    public static Key getSigningKey(long masterKeyId) {
        KeyRing keyRing = sDatabase.getSecretKeyRing(masterKeyId);
        if (keyRing == null) {
            return null;
        }
        Vector<Key> signingKeys = keyRing.getUsableSigningKeys();
        if (signingKeys.size() == 0) {
            return null;
        }
        return signingKeys.get(0);
    }

    public static String getMainUserIdSafe(Context context, Key key) {
        String userId = key.getMainUserId();
        if (userId == null) {
            userId = context.getResources().getString(R.string.user_id_no_name);
        }
        return userId;
    }

    public static void deleteKey(int keyRingId) {
        sDatabase.deleteKeyRing(keyRingId);
    }

    public static KeyRing getKeyRing(int keyRingId) {
        return sDatabase.getKeyRing(keyRingId);
    }

    public static KeyRing getSecretKeyRing(long keyId) {
        return sDatabase.getSecretKeyRing(keyId);
    }

    public static KeyRing getPublicKeyRing(long keyId) {
        return sDatabase.getPublicKeyRing(keyId);
    }

    public static Key getSecretKey(long keyId) {
        return sDatabase.getSecretKey(keyId);
    }

    public static Key getPublicKey(long keyId) {
        return sDatabase.getPublicKey(keyId);
    }

    public static Vector<Integer> getKeyRingIds(int type) {
        SQLiteDatabase db = sDatabase.db();
        Vector<Integer> keyIds = new Vector<Integer>();
        Cursor c = db.query(KeyRings.TABLE_NAME,
                            new String[] { KeyRings._ID },
                            KeyRings.TYPE + " = ?", new String[] { "" + type },
                            null, null, null);
        if (c != null && c.moveToFirst()) {
            do {
                keyIds.add(c.getInt(0));
            } while (c.moveToNext());
        }

        if (c != null) {
            c.close();
        }

        return keyIds;
    }

    public static String getMainUserId(long keyId, int type) {
        SQLiteDatabase db = sDatabase.db();
        Cursor c = db.query(Keys.TABLE_NAME + " INNER JOIN " + KeyRings.TABLE_NAME + " ON (" +
                            KeyRings.TABLE_NAME + "." + KeyRings._ID + " = " +
                            Keys.TABLE_NAME + "." + Keys.KEY_RING_ID + ") " +
                            " INNER JOIN " + Keys.TABLE_NAME + " AS masterKey ON (" +
                            KeyRings.TABLE_NAME + "." + KeyRings._ID + " = " +
                            "masterKey." + Keys.KEY_RING_ID + " AND " +
                            "masterKey." + Keys.IS_MASTER_KEY + " = '1') " +
                            " INNER JOIN " + UserIds.TABLE_NAME + " ON (" +
                            UserIds.TABLE_NAME + "." + UserIds.KEY_ID + " = " +
                            "masterKey." + Keys._ID + " AND " +
                            UserIds.TABLE_NAME + "." + UserIds.RANK + " = '0')",
                            new String[] { UserIds.USER_ID },
                             Keys.TABLE_NAME + "." + Keys.KEY_ID + " = ? AND " +
                             KeyRings.TABLE_NAME + "." + KeyRings.TYPE + " = ?",
                             new String[] {
                                 "" + keyId,
                                 "" + type,
                             },
                             null, null, null);
        String userId = "";
        if (c != null && c.moveToFirst()) {
            do {
                userId = c.getString(0);
            } while (c.moveToNext());
        }

        if (c != null) {
            c.close();
        }

        return userId;
    }

    public static void encrypt(Context context,
                               InputData data, OutputStream outStream,
                               boolean armored,
                               long encryptionKeyIds[], long signatureKeyId,
                               String signaturePassPhrase,
                               Progressable progress,
                               int symmetricAlgorithm, int hashAlgorithm, int compression,
                               boolean forceV3Signature,
                               String passPhrase)
            throws IOException, GeneralException, PGPException, NoSuchProviderException,
            NoSuchAlgorithmException, SignatureException {
        Security.addProvider(new BouncyCastleProvider());

        if (encryptionKeyIds == null) {
            encryptionKeyIds = new long[0];
        }

        ArmoredOutputStream armorOut = null;
        OutputStream out = null;
        OutputStream encryptOut = null;
        if (armored) {
            armorOut = new ArmoredOutputStream(outStream);
            armorOut.setHeader("Version", Utils.getFullVersion(context));
            out = armorOut;
        } else {
            out = outStream;
        }
        Key signingKey = null;
        KeyRing signingKeyRing = null;
        PGPPrivateKey signaturePrivateKey = null;

        if (encryptionKeyIds.length == 0 && passPhrase == null) {
            throw new GeneralException(context.getString(R.string.error_no_encryption_keys_or_pass_phrase));
        }

        if (signatureKeyId != 0) {
            signingKeyRing = sDatabase.getSecretKeyRing(signatureKeyId);
            signingKey = signingKeyRing.getUsableSigningKeys().get(0);
            if (signingKey == null) {
                throw new GeneralException(context.getString(R.string.error_signature_failed));
            }

            if (signaturePassPhrase == null) {
                throw new GeneralException(context.getString(R.string.error_no_signature_pass_phrase));
            }
            progress.setProgress(R.string.progress_extracting_signature_key, 0, 100);
            signaturePrivateKey = signingKey.extractPrivateKey(signaturePassPhrase);
            if (signaturePrivateKey == null) {
                throw new GeneralException(context.getString(R.string.error_could_not_extract_private_key));
            }
        }
        progress.setProgress(R.string.progress_preparing_streams, 5, 100);
        // encrypt and compress input file content
        PGPEncryptedDataGenerator cPk =
                new PGPEncryptedDataGenerator(symmetricAlgorithm, true, new SecureRandom(),
                                              new BouncyCastleProvider());

        if (encryptionKeyIds.length == 0) {
            // symmetric encryption
            cPk.addMethod(passPhrase.toCharArray());
        }
        for (int i = 0; i < encryptionKeyIds.length; ++i) {
            Key key = getEncryptKey(encryptionKeyIds[i]);
            if (key != null) {
                cPk.addMethod(key.getPublicKey());
            }
        }
        encryptOut = cPk.open(out, new byte[1 << 16]);

        PGPSignatureGenerator signatureGenerator = null;
        PGPV3SignatureGenerator signatureV3Generator = null;

        if (signatureKeyId != 0) {
            progress.setProgress(R.string.progress_preparing_signature, 10, 100);
            if (forceV3Signature) {
                signatureV3Generator =
                    new PGPV3SignatureGenerator(signingKey.getAlgorithm(),
                                                hashAlgorithm,
                                                new BouncyCastleProvider());
                signatureV3Generator.initSign(PGPSignature.BINARY_DOCUMENT, signaturePrivateKey);
            } else {
                signatureGenerator =
                        new PGPSignatureGenerator(signingKey.getAlgorithm(),
                                                  hashAlgorithm,
                                                  new BouncyCastleProvider());
                signatureGenerator.initSign(PGPSignature.BINARY_DOCUMENT, signaturePrivateKey);

                String userId = signingKeyRing.getMasterKey().getMainUserId();
                PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
                spGen.setSignerUserID(false, userId);
                signatureGenerator.setHashedSubpackets(spGen.generate());
            }
        }

        PGPCompressedDataGenerator compressGen = null;
        BCPGOutputStream bcpgOut = null;
        if (compression == Id.choice.compression.none) {
            bcpgOut = new BCPGOutputStream(encryptOut);
        } else {
            compressGen = new PGPCompressedDataGenerator(compression);
            bcpgOut = new BCPGOutputStream(compressGen.open(encryptOut));
        }
        if (signatureKeyId != 0) {
            if (forceV3Signature) {
                signatureV3Generator.generateOnePassVersion(false).encode(bcpgOut);
            } else {
                signatureGenerator.generateOnePassVersion(false).encode(bcpgOut);
            }
        }

        PGPLiteralDataGenerator literalGen = new PGPLiteralDataGenerator();
        // file name not needed, so empty string
        OutputStream pOut = literalGen.open(bcpgOut, PGPLiteralData.BINARY, "",
                                            new Date(), new byte[1 << 16]);
        progress.setProgress(R.string.progress_encrypting, 20, 100);
        long done = 0;
        int n = 0;
        byte[] buffer = new byte[1 << 16];
        InputStream in = data.getInputStream();
        while ((n = in.read(buffer)) > 0) {
            pOut.write(buffer, 0, n);
            if (signatureKeyId != 0) {
                if (forceV3Signature) {
                    signatureV3Generator.update(buffer, 0, n);
                } else {
                    signatureGenerator.update(buffer, 0, n);
                }
            }
            done += n;
            if (data.getSize() != 0) {
                progress.setProgress((int) (20 + (95 - 20) * done / data.getSize()), 100);
            }
        }

        literalGen.close();

        if (signatureKeyId != 0) {
            progress.setProgress(R.string.progress_generating_signature, 95, 100);
            if (forceV3Signature) {
                signatureV3Generator.generate().encode(pOut);
            } else {
                signatureGenerator.generate().encode(pOut);
            }
        }
        if (compressGen != null) {
            compressGen.close();
        }
        encryptOut.close();
        if (armored) {
            armorOut.close();
        }

        progress.setProgress(R.string.progress_done, 100, 100);
    }

    public static void signText(Context context,
                                InputData data, OutputStream outStream,
                                long signatureKeyId, String signaturePassPhrase,
                                int hashAlgorithm,
                                boolean forceV3Signature,
                                Progressable progress)
            throws GeneralException, PGPException, IOException, NoSuchAlgorithmException,
            SignatureException {
        Security.addProvider(new BouncyCastleProvider());

        ArmoredOutputStream armorOut = new ArmoredOutputStream(outStream);
        armorOut.setHeader("Version", Utils.getFullVersion(context));

        Key signingKey = null;
        KeyRing signingKeyRing = null;
        PGPPrivateKey signaturePrivateKey = null;

        if (signatureKeyId == 0) {
            throw new GeneralException(context.getString(R.string.error_no_signature_key));
        }

        signingKeyRing = sDatabase.getSecretKeyRing(signatureKeyId);
        signingKey = getSigningKey(signatureKeyId);
        if (signingKey == null) {
            throw new GeneralException(context.getString(R.string.error_signature_failed));
        }

        if (signaturePassPhrase == null) {
            throw new GeneralException(context.getString(R.string.error_no_signature_pass_phrase));
        }
        signaturePrivateKey = signingKey.extractPrivateKey(signaturePassPhrase);
        if (signaturePrivateKey == null) {
            throw new GeneralException(context.getString(R.string.error_could_not_extract_private_key));
        }
        progress.setProgress(R.string.progress_preparing_streams, 0, 100);

        progress.setProgress(R.string.progress_preparing_signature, 30, 100);

        PGPSignatureGenerator signatureGenerator = null;
        PGPV3SignatureGenerator signatureV3Generator = null;

        if (forceV3Signature) {
            signatureV3Generator =
                new PGPV3SignatureGenerator(signingKey.getAlgorithm(),
                                            hashAlgorithm,
                                            new BouncyCastleProvider());
            signatureV3Generator.initSign(PGPSignature.CANONICAL_TEXT_DOCUMENT, signaturePrivateKey);
        } else {
            signatureGenerator =
                    new PGPSignatureGenerator(signingKey.getAlgorithm(),
                                              hashAlgorithm,
                                              new BouncyCastleProvider());
            signatureGenerator.initSign(PGPSignature.CANONICAL_TEXT_DOCUMENT, signaturePrivateKey);

            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            String userId = signingKeyRing.getMasterKey().getMainUserId();
            spGen.setSignerUserID(false, userId);
            signatureGenerator.setHashedSubpackets(spGen.generate());
        }

        progress.setProgress(R.string.progress_signing, 40, 100);

        armorOut.beginClearText(hashAlgorithm);

        InputStream inStream = data.getInputStream();
        final BufferedReader reader = new BufferedReader(new InputStreamReader(inStream));

        final byte[] newline = "\r\n".getBytes("UTF-8");

        if (forceV3Signature) {
            processLine(reader.readLine(), armorOut, signatureV3Generator);
        } else {
            processLine(reader.readLine(), armorOut, signatureGenerator);
        }

        while (true) {
            final String line = reader.readLine();

            if (line == null) {
                armorOut.write(newline);
                break;
            }

            armorOut.write(newline);
            if (forceV3Signature) {
                signatureV3Generator.update(newline);
                processLine(line, armorOut, signatureV3Generator);
            } else {
                signatureGenerator.update(newline);
                processLine(line, armorOut, signatureGenerator);
            }
        }

        armorOut.endClearText();

        BCPGOutputStream bOut = new BCPGOutputStream(armorOut);
        if (forceV3Signature) {
            signatureV3Generator.generate().encode(bOut);
        } else {
            signatureGenerator.generate().encode(bOut);
        }
        armorOut.close();

        progress.setProgress(R.string.progress_done, 100, 100);
    }

    public static void generateSignature(Context context,
                                         InputData data, OutputStream outStream,
                                         boolean armored, boolean binary,
                                         long signatureKeyId, String signaturePassPhrase,
                                         int hashAlgorithm,
                                         boolean forceV3Signature,
                                         Progressable progress)
            throws GeneralException, PGPException, IOException, NoSuchAlgorithmException,
            SignatureException {
        Security.addProvider(new BouncyCastleProvider());

        ArmoredOutputStream armorOut = null;
        OutputStream out = null;
        if (armored) {
            armorOut = new ArmoredOutputStream(outStream);
            armorOut.setHeader("Version", Utils.getFullVersion(context));
            out = armorOut;
        } else {
            out = outStream;
        }

        Key signingKey = null;
        KeyRing signingKeyRing = null;
        PGPPrivateKey signaturePrivateKey = null;

        if (signatureKeyId == 0) {
            throw new GeneralException(context.getString(R.string.error_no_signature_key));
        }

        signingKeyRing = sDatabase.getSecretKeyRing(signatureKeyId);
        signingKey = getSigningKey(signatureKeyId);
        if (signingKey == null) {
            throw new GeneralException(context.getString(R.string.error_signature_failed));
        }

        if (signaturePassPhrase == null) {
            throw new GeneralException(context.getString(R.string.error_no_signature_pass_phrase));
        }
        signaturePrivateKey = signingKey.extractPrivateKey(signaturePassPhrase);
        if (signaturePrivateKey == null) {
            throw new GeneralException(context.getString(R.string.error_could_not_extract_private_key));
        }
        progress.setProgress(R.string.progress_preparing_streams, 0, 100);

        progress.setProgress(R.string.progress_preparing_signature, 30, 100);

        PGPSignatureGenerator signatureGenerator = null;
        PGPV3SignatureGenerator signatureV3Generator = null;

        int type = PGPSignature.CANONICAL_TEXT_DOCUMENT;
        if (binary) {
            type = PGPSignature.BINARY_DOCUMENT;
        }

        if (forceV3Signature) {
            signatureV3Generator =
                new PGPV3SignatureGenerator(signingKey.getPublicKey().getAlgorithm(),
                                            hashAlgorithm,
                                            new BouncyCastleProvider());
            signatureV3Generator.initSign(type, signaturePrivateKey);
        } else {
            signatureGenerator =
                    new PGPSignatureGenerator(signingKey.getPublicKey().getAlgorithm(),
                                              hashAlgorithm,
                                              new BouncyCastleProvider());
            signatureGenerator.initSign(type, signaturePrivateKey);

            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            String userId = signingKeyRing.getMasterKey().getMainUserId();
            spGen.setSignerUserID(false, userId);
            signatureGenerator.setHashedSubpackets(spGen.generate());
        }

        progress.setProgress(R.string.progress_signing, 40, 100);

        InputStream inStream = data.getInputStream();
        if (binary) {
            byte[] buffer = new byte[1 << 16];
            int n = 0;
            while ((n = inStream.read(buffer)) > 0) {
                if (forceV3Signature) {
                    signatureV3Generator.update(buffer, 0, n);
                } else {
                    signatureGenerator.update(buffer, 0, n);
                }
            }
        } else {
            final BufferedReader reader = new BufferedReader(new InputStreamReader(inStream));
            final byte[] newline = "\r\n".getBytes("UTF-8");

            while (true) {
                final String line = reader.readLine();

                if (line == null) {
                    break;
                }

                if (forceV3Signature) {
                    processLine(line, null, signatureV3Generator);
                    signatureV3Generator.update(newline);
                } else {
                    processLine(line, null, signatureGenerator);
                    signatureGenerator.update(newline);
                }
            }
        }

        BCPGOutputStream bOut = new BCPGOutputStream(out);
        if (forceV3Signature) {
            signatureV3Generator.generate().encode(bOut);
        } else {
            signatureGenerator.generate().encode(bOut);
        }
        out.close();
        outStream.close();

        progress.setProgress(R.string.progress_done, 100, 100);
    }

    public static long getDecryptionKeyId(Context context, InputData data)
            throws GeneralException, NoAsymmetricEncryptionException, IOException {
        InputStream in = PGPUtil.getDecoderStream(data.getInputStream());
        PGPObjectFactory pgpF = new PGPObjectFactory(in);
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();

        // the first object might be a PGP marker packet.
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        if (enc == null) {
            throw new GeneralException(context.getString(R.string.error_invalid_data));
        }

        // TODO: currently we always only look at the first known key
        // find the secret key
        Key secretKey = null;
        Iterator<?> it = enc.getEncryptedDataObjects();
        boolean gotAsymmetricEncryption = false;
        while (it.hasNext()) {
            Object obj = it.next();
            if (obj instanceof PGPPublicKeyEncryptedData) {
                gotAsymmetricEncryption = true;
                PGPPublicKeyEncryptedData pbe = (PGPPublicKeyEncryptedData) obj;
                secretKey = sDatabase.getSecretKey(pbe.getKeyID());
                if (secretKey != null) {
                    break;
                }
            }
        }

        if (!gotAsymmetricEncryption) {
            throw new NoAsymmetricEncryptionException();
        }

        if (secretKey == null) {
            return Id.key.none;
        }

        return secretKey.getKeyId();
    }

    public static boolean hasSymmetricEncryption(Context context, InputData data)
            throws GeneralException, IOException {
        InputStream in = PGPUtil.getDecoderStream(data.getInputStream());
        PGPObjectFactory pgpF = new PGPObjectFactory(in);
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();

        // the first object might be a PGP marker packet.
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        if (enc == null) {
            throw new GeneralException(context.getString(R.string.error_invalid_data));
        }

        Iterator<?> it = enc.getEncryptedDataObjects();
        while (it.hasNext()) {
            Object obj = it.next();
            if (obj instanceof PGPPBEEncryptedData) {
                return true;
            }
        }

        return false;
    }

    public static Bundle decrypt(Context context,
                                 InputData data, OutputStream outStream,
                                 String passPhrase, Progressable progress,
                                 boolean assumeSymmetric)
            throws IOException, GeneralException, PGPException, SignatureException {
        if (passPhrase == null) {
            passPhrase = "";
        }
        Bundle returnData = new Bundle();
        InputStream in = PGPUtil.getDecoderStream(data.getInputStream());
        PGPObjectFactory pgpF = new PGPObjectFactory(in);
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();
        long signatureKeyId = 0;

        int currentProgress = 0;
        progress.setProgress(R.string.progress_reading_data, currentProgress, 100);

        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        if (enc == null) {
            throw new GeneralException(context.getString(R.string.error_invalid_data));
        }

        InputStream clear = null;
        PGPEncryptedData encryptedData = null;

        currentProgress += 5;

        // TODO: currently we always only look at the first known key or symmetric encryption,
        // there might be more...
        if (assumeSymmetric) {
            PGPPBEEncryptedData pbe = null;
            Iterator<?> it = enc.getEncryptedDataObjects();
            // find secret key
            while (it.hasNext()) {
                Object obj = it.next();
                if (obj instanceof PGPPBEEncryptedData) {
                    pbe = (PGPPBEEncryptedData) obj;
                    break;
                }
            }

            if (pbe == null) {
                throw new GeneralException(context.getString(R.string.error_no_symmetric_encryption_packet));
            }

            progress.setProgress(R.string.progress_preparing_streams, currentProgress, 100);
            clear = pbe.getDataStream(passPhrase.toCharArray(), new BouncyCastleProvider());
            encryptedData = pbe;
            currentProgress += 5;
        } else {
            progress.setProgress(R.string.progress_finding_key, currentProgress, 100);
            PGPPublicKeyEncryptedData pbe = null;
            Key secretKey = null;
            Iterator<?> it = enc.getEncryptedDataObjects();
            // find secret key
            while (it.hasNext()) {
                Object obj = it.next();
                if (obj instanceof PGPPublicKeyEncryptedData) {
                    PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) obj;
                    secretKey = sDatabase.getSecretKey(encData.getKeyID());
                    if (secretKey != null) {
                        pbe = encData;
                        break;
                    }
                }
            }

            if (secretKey == null) {
                throw new GeneralException(context.getString(R.string.error_no_secret_key_found));
            }

            currentProgress += 5;
            progress.setProgress(R.string.progress_extracting_key, currentProgress, 100);
            PGPPrivateKey privateKey = null;
            try {
                privateKey = secretKey.extractPrivateKey(passPhrase);
            } catch (PGPException e) {
                throw new PGPException(context.getString(R.string.error_wrong_pass_phrase));
            }
            if (privateKey == null) {
                throw new GeneralException(context.getString(R.string.error_could_not_extract_private_key));
            }
            currentProgress += 5;
            progress.setProgress(R.string.progress_preparing_streams, currentProgress, 100);
            clear = pbe.getDataStream(privateKey, new BouncyCastleProvider());
            encryptedData = pbe;
            currentProgress += 5;
        }

        PGPObjectFactory plainFact = new PGPObjectFactory(clear);
        Object dataChunk = plainFact.nextObject();
        PGPOnePassSignature signature = null;
        Key signatureKey = null;
        int signatureIndex = -1;

        if (dataChunk instanceof PGPCompressedData) {
            progress.setProgress(R.string.progress_decompressing_data, currentProgress, 100);
            PGPObjectFactory fact =
                    new PGPObjectFactory(((PGPCompressedData) dataChunk).getDataStream());
            dataChunk = fact.nextObject();
            plainFact = fact;
            currentProgress += 10;
        }

        if (dataChunk instanceof PGPOnePassSignatureList) {
            progress.setProgress(R.string.progress_processing_signature, currentProgress, 100);
            returnData.putBoolean(EXTRA_SIGNATURE, true);
            PGPOnePassSignatureList sigList = (PGPOnePassSignatureList) dataChunk;
            for (int i = 0; i < sigList.size(); ++i) {
                signature = sigList.get(i);
                signatureKey = sDatabase.getPublicKey(signature.getKeyID());
                if (signatureKeyId == 0) {
                    signatureKeyId = signature.getKeyID();
                }
                if (signatureKey == null) {
                    signature = null;
                } else {
                    signatureIndex = i;
                    signatureKeyId = signature.getKeyID();
                    String userId = null;
                    KeyRing sigKeyRing = sDatabase.getPublicKeyRing(signatureKeyId);
                    if (sigKeyRing != null) {
                        userId = sigKeyRing.getMasterKey().getMainUserId();
                    }
                    returnData.putString(EXTRA_SIGNATURE_USER_ID, userId);
                    break;
                }
            }

            returnData.putLong(EXTRA_SIGNATURE_KEY_ID, signatureKeyId);

            if (signature != null) {
                signature.initVerify(signatureKey.getPublicKey(), new BouncyCastleProvider());
            } else {
                returnData.putBoolean(EXTRA_SIGNATURE_UNKNOWN, true);
            }

            dataChunk = plainFact.nextObject();
            currentProgress += 10;
        }

        if (dataChunk instanceof PGPLiteralData) {
            progress.setProgress(R.string.progress_decrypting, currentProgress, 100);
            PGPLiteralData literalData = (PGPLiteralData) dataChunk;
            OutputStream out = outStream;

            byte[] buffer = new byte[1 << 16];
            InputStream dataIn = literalData.getInputStream();

            int startProgress = currentProgress;
            int endProgress = 100;
            if (signature != null) {
                endProgress = 90;
            } else if (encryptedData.isIntegrityProtected()) {
                endProgress = 95;
            }
            int n = 0;
            int done = 0;
            long startPos = data.getStreamPosition();
            while ((n = dataIn.read(buffer)) > 0) {
                out.write(buffer, 0, n);
                done += n;
                if (signature != null) {
                    try {
                        signature.update(buffer, 0, n);
                    } catch (SignatureException e) {
                        returnData.putBoolean(EXTRA_SIGNATURE_SUCCESS, false);
                        signature = null;
                    }
                }
                // unknown size, but try to at least have a moving, slowing down progress bar
                currentProgress =
                    startProgress + (endProgress - startProgress) * done / (done + 100000);
                if (data.getSize() - startPos == 0) {
                    currentProgress = endProgress;
                } else {
                    currentProgress = (int) (startProgress + (endProgress - startProgress) *
                            (data.getStreamPosition() - startPos) / (data.getSize() - startPos));
                }
                progress.setProgress(currentProgress, 100);
            }

            if (signature != null) {
                progress.setProgress(R.string.progress_verifying_signature, 90, 100);
                PGPSignatureList signatureList = (PGPSignatureList) plainFact.nextObject();
                PGPSignature messageSignature = signatureList.get(signatureIndex);
                if (signature.verify(messageSignature)) {
                    returnData.putBoolean(EXTRA_SIGNATURE_SUCCESS, true);
                } else {
                    returnData.putBoolean(EXTRA_SIGNATURE_SUCCESS, false);
                }
            }
        }

        // TODO: add integrity somewhere
        if (encryptedData.isIntegrityProtected()) {
            progress.setProgress(R.string.progress_verifying_integrity, 95, 100);
            if (encryptedData.verify()) {
                // passed
            } else {
                // failed
            }
        } else {
            // no integrity check
        }

        progress.setProgress(R.string.progress_done, 100, 100);
        return returnData;
    }

    public static Bundle verifyText(BaseActivity context,
                                    InputData data, OutputStream outStream,
                                    Progressable progress)
            throws IOException, GeneralException, PGPException, SignatureException {
        Bundle returnData = new Bundle();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredInputStream aIn = new ArmoredInputStream(data.getInputStream());

        progress.setProgress(R.string.progress_done, 0, 100);

        // mostly taken from ClearSignedFileProcessor
        ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
        int lookAhead = readInputLine(lineOut, aIn);
        byte[] lineSep = getLineSeparator();

        byte[] line = lineOut.toByteArray();
        out.write(line, 0, getLengthWithoutSeparator(line));
        out.write(lineSep);

        while (lookAhead != -1 && aIn.isClearText()) {
            lookAhead = readInputLine(lineOut, lookAhead, aIn);
            line = lineOut.toByteArray();
            out.write(line, 0, getLengthWithoutSeparator(line));
            out.write(lineSep);
        }

        out.close();

        byte[] clearText = out.toByteArray();
        outStream.write(clearText);

        returnData.putBoolean(EXTRA_SIGNATURE, true);

        progress.setProgress(R.string.progress_processing_signature, 60, 100);
        PGPObjectFactory pgpFact = new PGPObjectFactory(aIn);

        PGPSignatureList sigList = (PGPSignatureList) pgpFact.nextObject();
        if (sigList == null) {
            throw new GeneralException(context.getString(R.string.error_corrupt_data));
        }
        PGPSignature signature = null;
        long signatureKeyId = 0;
        Key signatureKey = null;
        for (int i = 0; i < sigList.size(); ++i) {
            signature = sigList.get(i);
            signatureKey = sDatabase.getPublicKey(signature.getKeyID());
            if (signatureKeyId == 0) {
                signatureKeyId = signature.getKeyID();
            }
            if (signatureKey == null) {
                Bundle pauseData = new Bundle();
                pauseData.putInt(Constants.extras.status, Id.message.unknown_signature_key);
                pauseData.putLong(Constants.extras.key_id, signatureKeyId);
                Message msg = new Message();
                msg.setData(pauseData);
                context.sendMessage(msg);
                // pause here
                context.getRunningThread().pause();
                // see whether the key was found in the meantime
                signatureKey = sDatabase.getPublicKey(signature.getKeyID());
            }

            if (signatureKey == null) {
                signature = null;
            } else {
                signatureKeyId = signature.getKeyID();
                String userId = null;
                KeyRing sigKeyRing = sDatabase.getPublicKeyRing(signatureKeyId);
                if (sigKeyRing != null) {
                    userId = sigKeyRing.getMasterKey().getMainUserId();
                }
                returnData.putString(EXTRA_SIGNATURE_USER_ID, userId);
                break;
            }
        }

        returnData.putLong(EXTRA_SIGNATURE_KEY_ID, signatureKeyId);

        if (signature == null) {
            returnData.putBoolean(EXTRA_SIGNATURE_UNKNOWN, true);
            progress.setProgress(R.string.progress_done, 100, 100);
            return returnData;
        }

        signature.initVerify(signatureKey.getPublicKey(), new BouncyCastleProvider());

        InputStream sigIn = new BufferedInputStream(new ByteArrayInputStream(clearText));

        lookAhead = readInputLine(lineOut, sigIn);

        processLine(signature, lineOut.toByteArray());

        if (lookAhead != -1) {
            do {
                lookAhead = readInputLine(lineOut, lookAhead, sigIn);

                signature.update((byte) '\r');
                signature.update((byte) '\n');

                processLine(signature, lineOut.toByteArray());
            }
            while (lookAhead != -1);
        }

        returnData.putBoolean(EXTRA_SIGNATURE_SUCCESS, signature.verify());

        progress.setProgress(R.string.progress_done, 100, 100);
        return returnData;
    }

    public static int getStreamContent(Context context, InputStream inStream)
            throws IOException {
        InputStream in = PGPUtil.getDecoderStream(inStream);
        PGPObjectFactory pgpF = new PGPObjectFactory(in);
        Object object = pgpF.nextObject();
        while (object != null) {
            if (object instanceof PGPPublicKeyRing ||
                object instanceof PGPSecretKeyRing) {
                return Id.content.keys;
            } else if (object instanceof PGPEncryptedDataList) {
                return Id.content.encrypted_data;
            }
            object = pgpF.nextObject();
        }

        return Id.content.unknown;
    }

    private static void processLine(final String pLine,
                                    final ArmoredOutputStream pArmoredOutput,
                                    final PGPSignatureGenerator pSignatureGenerator)
            throws IOException, SignatureException {

        if (pLine == null) {
            return;
        }

        final char[] chars = pLine.toCharArray();
        int len = chars.length;

        while (len > 0) {
            if (!Character.isWhitespace(chars[len - 1])) {
                break;
            }
            len--;
        }

        final byte[] data = pLine.substring(0, len).getBytes("UTF-8");

        if (pArmoredOutput != null) {
            pArmoredOutput.write(data);
        }
        pSignatureGenerator.update(data);
    }

    private static void processLine(final String pLine,
                                    final ArmoredOutputStream pArmoredOutput,
                                    final PGPV3SignatureGenerator pSignatureGenerator)
            throws IOException, SignatureException {

        if (pLine == null) {
            return;
        }

        final char[] chars = pLine.toCharArray();
        int len = chars.length;

        while (len > 0) {
            if (!Character.isWhitespace(chars[len - 1])) {
                break;
            }
            len--;
        }

        final byte[] data = pLine.substring(0, len).getBytes("UTF-8");

        if (pArmoredOutput != null) {
            pArmoredOutput.write(data);
        }
        pSignatureGenerator.update(data);
    }

    // taken from ClearSignedFileProcessor in BC
    private static void processLine(PGPSignature sig, byte[] line)
        throws SignatureException, IOException {
        int length = getLengthWithoutWhiteSpace(line);
        if (length > 0) {
            sig.update(line, 0, length);
        }
    }

    private static int readInputLine(ByteArrayOutputStream bOut, InputStream fIn)
        throws IOException {
        bOut.reset();

        int lookAhead = -1;
        int ch;

        while ((ch = fIn.read()) >= 0) {
            bOut.write(ch);
            if (ch == '\r' || ch == '\n') {
                lookAhead = readPassedEOL(bOut, ch, fIn);
                break;
            }
        }

        return lookAhead;
    }

    private static int readInputLine(ByteArrayOutputStream bOut, int lookAhead, InputStream fIn)
        throws IOException {
        bOut.reset();

        int ch = lookAhead;

        do {
            bOut.write(ch);
            if (ch == '\r' || ch == '\n') {
                lookAhead = readPassedEOL(bOut, ch, fIn);
                break;
            }
        }
        while ((ch = fIn.read()) >= 0);

        if (ch < 0) {
            lookAhead = -1;
        }

        return lookAhead;
    }

    private static int readPassedEOL(ByteArrayOutputStream bOut, int lastCh, InputStream fIn)
        throws IOException {
        int lookAhead = fIn.read();

        if (lastCh == '\r' && lookAhead == '\n') {
            bOut.write(lookAhead);
            lookAhead = fIn.read();
        }

        return lookAhead;
    }

    private static int getLengthWithoutSeparator(byte[] line) {
        int end = line.length - 1;

        while (end >= 0 && isLineEnding(line[end])) {
            end--;
        }

        return end + 1;
    }

    private static boolean isLineEnding(byte b) {
        return b == '\r' || b == '\n';
    }

    private static int getLengthWithoutWhiteSpace(byte[] line) {
        int end = line.length - 1;

        while (end >= 0 && isWhiteSpace(line[end])) {
            end--;
        }

        return end + 1;
    }

    private static boolean isWhiteSpace(byte b) {
        return b == '\r' || b == '\n' || b == '\t' || b == ' ';
    }

    private static byte[] getLineSeparator() {
        String nl = System.getProperty("line.separator");
        byte[] nlBytes = new byte[nl.length()];

        for (int i = 0; i != nlBytes.length; i++) {
            nlBytes[i] = (byte) nl.charAt(i);
        }

        return nlBytes;
    }


}
