/*
 * Copyright (C) 2012-2014 Dominik Schürmann <dominik@dominikschuermann.de>
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

import android.content.Context;
import android.os.Bundle;

import org.bouncycastle2.bcpg.ArmoredInputStream;
import org.bouncycastle2.bcpg.BCPGInputStream;
import org.bouncycastle2.bcpg.SignaturePacket;
import org.bouncycastle2.bcpg.SignatureSubpacket;
import org.bouncycastle2.bcpg.SignatureSubpacketTags;
import org.bouncycastle2.openpgp.PGPCompressedData;
import org.bouncycastle2.openpgp.PGPEncryptedData;
import org.bouncycastle2.openpgp.PGPEncryptedDataList;
import org.bouncycastle2.openpgp.PGPException;
import org.bouncycastle2.openpgp.PGPLiteralData;
import org.bouncycastle2.openpgp.PGPObjectFactory;
import org.bouncycastle2.openpgp.PGPOnePassSignature;
import org.bouncycastle2.openpgp.PGPOnePassSignatureList;
import org.bouncycastle2.openpgp.PGPPBEEncryptedData;
import org.bouncycastle2.openpgp.PGPPrivateKey;
import org.bouncycastle2.openpgp.PGPPublicKey;
import org.bouncycastle2.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle2.openpgp.PGPPublicKeyRing;
import org.bouncycastle2.openpgp.PGPSecretKey;
import org.bouncycastle2.openpgp.PGPSignature;
import org.bouncycastle2.openpgp.PGPSignatureList;
import org.bouncycastle2.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle2.openpgp.PGPUtil;
import org.bouncycastle2.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle2.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle2.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle2.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle2.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle2.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle2.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

import org.thialfihar.android.apg.R;
import org.thialfihar.android.apg.core.exception.PgpGeneralException;
import org.thialfihar.android.apg.core.Result;
import org.thialfihar.android.apg.util.InputData;
import org.thialfihar.android.apg.util.Log;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Iterator;

/**
 * This class uses a Builder pattern!
 */
public class DecryptVerify {
    private Context mContext;
    private InputData mInputData;
    private OutputStream mOutputStream;
    private KeyProvider mKeyProvider;

    private Progressable mProgress;
    private boolean mAssumeSymmetric;
    private String mPassphrase;

    private DecryptVerify(Builder builder) {
        // private Constructor can only be called from Builder
        this.mContext = builder.context;
        this.mInputData = builder.inputData;
        this.mOutputStream = builder.outputStream;
        this.mKeyProvider = builder.keyProvider;

        this.mProgress = builder.progress;
        this.mAssumeSymmetric = builder.assumeSymmetric;
        this.mPassphrase = builder.passphrase;
    }

    public static class Builder {
        // mandatory parameter
        public Context context;
        public InputData inputData;
        public OutputStream outputStream;
        public KeyProvider keyProvider;

        // optional
        public Progressable progress = null;
        public boolean assumeSymmetric = false;
        public String passphrase = "";

        public Builder(Context context, InputData inputData, OutputStream outputStream,
                       KeyProvider keyProvider) {
            this.context = context;
            this.inputData = inputData;
            this.outputStream = outputStream;
            this.keyProvider = keyProvider;
        }

        public Builder setProgress(Progressable progress) {
            this.progress = progress;
            return this;
        }

        public Builder setAssumeSymmetric(boolean assumeSymmetric) {
            this.assumeSymmetric = assumeSymmetric;
            return this;
        }

        public Builder setPassphrase(String passphrase) {
            this.passphrase = passphrase;
            return this;
        }

        public DecryptVerify build() {
            return new DecryptVerify(this);
        }
    }

    public void updateProgress(int message, int current, int total) {
        if (mProgress != null) {
            mProgress.setProgress(message, current, total);
        }
    }

    public void updateProgress(int current, int total) {
        if (mProgress != null) {
            mProgress.setProgress(current, total);
        }
    }

    public static boolean hasSymmetricEncryption(Context context, InputStream inputStream)
            throws PgpGeneralException, IOException {
        InputStream in = PGPUtil.getDecoderStream(inputStream);
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
            throw new PgpGeneralException(context.getString(R.string.error_invalid_data));
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

    /**
     * Decrypts and/or verifies data based on parameters of class
     *
     * @return
     * @throws IOException
     * @throws PgpGeneralException
     * @throws PGPException
     * @throws SignatureException
     */
    public Bundle execute()
            throws IOException, PgpGeneralException, PGPException, SignatureException {

        // automatically works with ascii armor input and binary
        InputStream in = PGPUtil.getDecoderStream(mInputData.getInputStream());
        if (in instanceof ArmoredInputStream) {
            ArmoredInputStream aIn = (ArmoredInputStream) in;
            // it is ascii armored
            Log.d(Constants.TAG, "ASCII Armor Header Line: " + aIn.getArmorHeaderLine());

            if (aIn.isClearText()) {
                // a cleartext signature, verify it with the other method
                return verifyCleartextSignature(aIn);
            }
            // else: ascii armored encryption! go on...
        }

        return decryptVerify(in);
    }

    /**
     * Decrypt and/or verifies binary or ascii armored pgp
     *
     * @param in
     * @return
     * @throws IOException
     * @throws PgpGeneralException
     * @throws PGPException
     * @throws SignatureException
     */
    private Bundle decryptVerify(InputStream in)
            throws IOException, PgpGeneralException, PGPException, SignatureException {
        Bundle returnData = new Bundle();

        PGPObjectFactory pgpF = new PGPObjectFactory(in);
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();

        int currentProgress = 0;
        updateProgress(R.string.progress_reading_data, currentProgress, 100);

        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        if (enc == null) {
            throw new PgpGeneralException(mContext.getString(R.string.error_invalid_data));
        }

        InputStream clear;
        PGPEncryptedData encryptedData;

        currentProgress += 5;

        // TODO: currently we always only look at the first known key or symmetric encryption,
        // there might be more...
        if (mAssumeSymmetric) {
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
                throw new PgpGeneralException(
                        mContext.getString(R.string.error_no_symmetric_encryption_packet));
            }

            updateProgress(R.string.progress_preparing_streams, currentProgress, 100);

            PGPDigestCalculatorProvider digestCalcProvider =
                new JcaPGPDigestCalculatorProviderBuilder()
                    .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME).build();
            PBEDataDecryptorFactory decryptorFactory =
                new JcePBEDataDecryptorFactoryBuilder(digestCalcProvider)
                    .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME)
                    .build(mPassphrase.toCharArray());

            clear = pbe.getDataStream(decryptorFactory);

            encryptedData = pbe;
            currentProgress += 5;
        } else {
            updateProgress(R.string.progress_finding_key, currentProgress, 100);

            PGPPublicKeyEncryptedData pbe = null;
            Key secretKey = null;
            Iterator<?> it = enc.getEncryptedDataObjects();
            // find secret key
            while (it.hasNext()) {
                Object obj = it.next();
                if (obj instanceof PGPPublicKeyEncryptedData) {
                    PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) obj;
                    secretKey = mKeyProvider.getSecretKey(encData.getKeyID());
                    if (secretKey != null) {
                        pbe = encData;
                        break;
                    }
                }
            }

            if (secretKey == null) {
                throw new PgpGeneralException(mContext.getString(R.string.error_no_secret_key_found));
            }

            currentProgress += 5;
            updateProgress(R.string.progress_extracting_key, currentProgress, 100);
            PGPPrivateKey privateKey = null;
            try {
                privateKey = secretKey.extractPrivateKey(mPassphrase);
            } catch (PGPException e) {
                throw new PGPException(mContext.getString(R.string.error_wrong_passphrase));
            }
            if (privateKey == null) {
                throw new PgpGeneralException(
                    mContext.getString(R.string.error_could_not_extract_private_key));
            }
            currentProgress += 5;
            updateProgress(R.string.progress_preparing_streams, currentProgress, 100);

            PublicKeyDataDecryptorFactory decryptorFactory =
                new JcePublicKeyDataDecryptorFactoryBuilder()
                    .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME)
                    .build(privateKey);

            clear = pbe.getDataStream(decryptorFactory);

            encryptedData = pbe;
            currentProgress += 5;
        }

        PGPObjectFactory plainFact = new PGPObjectFactory(clear);
        Object dataChunk = plainFact.nextObject();
        PGPOnePassSignature signature = null;
        Key signatureKey = null;
        int signatureIndex = -1;

        if (dataChunk instanceof PGPCompressedData) {
            updateProgress(R.string.progress_decompressing_data, currentProgress, 100);

            PGPObjectFactory fact = new PGPObjectFactory(
                    ((PGPCompressedData) dataChunk).getDataStream());
            dataChunk = fact.nextObject();
            plainFact = fact;
            currentProgress += 10;
        }

        long signatureKeyId = 0;
        if (dataChunk instanceof PGPOnePassSignatureList) {
            updateProgress(R.string.progress_processing_signature, currentProgress, 100);

            returnData.putBoolean(Result.SIGNATURE, true);
            PGPOnePassSignatureList sigList = (PGPOnePassSignatureList) dataChunk;
            for (int i = 0; i < sigList.size(); ++i) {
                signature = sigList.get(i);
                signatureKey = mKeyProvider.getPublicKey(signature.getKeyID());
                if (signatureKeyId == 0) {
                    signatureKeyId = signature.getKeyID();
                }
                if (signatureKey == null) {
                    signature = null;
                } else {
                    signatureIndex = i;
                    signatureKeyId = signature.getKeyID();
                    String userId = null;
                    KeyRing signKeyRing = mKeyProvider.getPublicKeyRing(signatureKeyId);
                    if (signKeyRing != null) {
                        userId = signKeyRing.getMasterKey().getMainUserId();
                    }
                    returnData.putString(Result.SIGNATURE_USER_ID, userId);
                    break;
                }
            }

            returnData.putLong(Result.SIGNATURE_KEY_ID, signatureKeyId);

            if (signature != null) {
                JcaPGPContentVerifierBuilderProvider contentVerifierBuilderProvider =
                    new JcaPGPContentVerifierBuilderProvider()
                        .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME);

                signature.init(contentVerifierBuilderProvider, signatureKey.getPublicKey());
            } else {
                returnData.putBoolean(Result.SIGNATURE_UNKNOWN, true);
            }

            dataChunk = plainFact.nextObject();
            currentProgress += 10;
        }

        if (dataChunk instanceof PGPSignatureList) {
            dataChunk = plainFact.nextObject();
        }

        if (dataChunk instanceof PGPLiteralData) {
            updateProgress(R.string.progress_decrypting, currentProgress, 100);

            PGPLiteralData literalData = (PGPLiteralData) dataChunk;

            byte[] buffer = new byte[1 << 16];
            InputStream dataIn = literalData.getInputStream();

            int startProgress = currentProgress;
            int endProgress = 100;
            if (signature != null) {
                endProgress = 90;
            } else if (encryptedData.isIntegrityProtected()) {
                endProgress = 95;
            }

            int n;
            // TODO: progress calculation is broken here! Try to rework it based on commented code!
//            int progress = 0;
            long startPos = mInputData.getStreamPosition();
            while ((n = dataIn.read(buffer)) > 0) {
                mOutputStream.write(buffer, 0, n);
//                progress += n;
                if (signature != null) {
                    try {
                        signature.update(buffer, 0, n);
                    } catch (SignatureException e) {
                        returnData.putBoolean(Result.SIGNATURE_SUCCESS, false);
                        signature = null;
                    }
                }
                // TODO: dead code?!
                // unknown size, but try to at least have a moving, slowing down progress bar
//                currentProgress = startProgress + (endProgress - startProgress) * progress
//                        / (progress + 100000);
                if (mInputData.getSize() - startPos == 0) {
                    currentProgress = endProgress;
                } else {
                    currentProgress = (int) (startProgress +
                        (endProgress - startProgress) *
                            (mInputData.getStreamPosition() - startPos) /
                            (mInputData.getSize() - startPos));
                }
                updateProgress(currentProgress, 100);
            }

            if (signature != null) {
                updateProgress(R.string.progress_verifying_signature, 90, 100);

                PGPSignatureList signatureList = (PGPSignatureList) plainFact.nextObject();
                PGPSignature messageSignature = signatureList.get(signatureIndex);

                // these are not cleartext signatures!
                returnData.putBoolean(Result.CLEARTEXT_SIGNATURE_ONLY, false);

                // Now check binding signatures
                boolean keyBindingIsOk = verifyKeyBinding(messageSignature, signatureKey);
                boolean sigIsOk = signature.verify(messageSignature);

                returnData.putBoolean(Result.SIGNATURE_SUCCESS,
                                      keyBindingIsOk & sigIsOk);
            }
        }

        // TODO: test if this integrity really check works!
        if (encryptedData.isIntegrityProtected()) {
            updateProgress(R.string.progress_verifying_integrity, 95, 100);

            if (encryptedData.verify()) {
                // passed
                Log.d(Constants.TAG, "Integrity verification: success!");
            } else {
                // failed
                Log.d(Constants.TAG, "Integrity verification: failed!");
                throw new PgpGeneralException(mContext.getString(R.string.error_integrity_check_failed));
            }
        } else {
            // no integrity check
            Log.e(Constants.TAG, "Encrypted data was not integrity protected!");
        }

        updateProgress(R.string.progress_done, 100, 100);
        return returnData;
    }

    /**
     * This method verifies cleartext signatures
     * as defined in http://tools.ietf.org/html/rfc4880#section-7
     * <p/>
     * The method is heavily based on
     * pg/src/main/java/org.bouncycastle2/openpgp/examples/ClearSignedFileProcessor.java
     *
     * @return
     * @throws IOException
     * @throws PgpGeneralException
     * @throws PGPException
     * @throws SignatureException
     */
    private Bundle verifyCleartextSignature(ArmoredInputStream aIn)
            throws IOException, PgpGeneralException, PGPException, SignatureException {
        Bundle returnData = new Bundle();
        // cleartext signatures are never encrypted ;)
        returnData.putBoolean(Result.CLEARTEXT_SIGNATURE_ONLY, true);

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        updateProgress(R.string.progress_done, 0, 100);

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
        mOutputStream.write(clearText);

        returnData.putBoolean(Result.SIGNATURE, true);

        updateProgress(R.string.progress_processing_signature, 60, 100);
        PGPObjectFactory pgpFact = new PGPObjectFactory(aIn);

        PGPSignatureList sigList = (PGPSignatureList) pgpFact.nextObject();
        if (sigList == null) {
            throw new PgpGeneralException(mContext.getString(R.string.error_corrupt_data));
        }
        PGPSignature signature = null;
        long signatureKeyId = 0;
        Key signatureKey = null;
        for (int i = 0; i < sigList.size(); ++i) {
            signature = sigList.get(i);
            signatureKey = mKeyProvider.getPublicKey(signature.getKeyID());
            if (signatureKeyId == 0) {
                signatureKeyId = signature.getKeyID();
            }

            if (signatureKey == null) {
                signature = null;
            } else {
                signatureKeyId = signature.getKeyID();
                String userId = null;
                KeyRing signKeyRing = mKeyProvider.getPublicKeyRing(signatureKeyId);
                if (signKeyRing != null) {
                    userId = signKeyRing.getMasterKey().getMainUserId();
                }
                returnData.putString(Result.SIGNATURE_USER_ID, userId);
                break;
            }
        }

        returnData.putLong(Result.SIGNATURE_KEY_ID, signatureKeyId);

        if (signature == null) {
            returnData.putBoolean(Result.SIGNATURE_UNKNOWN, true);
            updateProgress(R.string.progress_done, 100, 100);
            return returnData;
        }

        JcaPGPContentVerifierBuilderProvider contentVerifierBuilderProvider =
                new JcaPGPContentVerifierBuilderProvider()
                        .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME);

        signature.init(contentVerifierBuilderProvider, signatureKey.getPublicKey());

        InputStream sigIn = new BufferedInputStream(new ByteArrayInputStream(clearText));

        lookAhead = readInputLine(lineOut, sigIn);

        processLine(signature, lineOut.toByteArray());

        if (lookAhead != -1) {
            do {
                lookAhead = readInputLine(lineOut, lookAhead, sigIn);

                signature.update((byte) '\r');
                signature.update((byte) '\n');

                processLine(signature, lineOut.toByteArray());
            } while (lookAhead != -1);
        }

        boolean sigIsOk = signature.verify();

        // Now check binding signatures
        boolean keyBindingIsOk = verifyKeyBinding(signature, signatureKey);

        returnData.putBoolean(Result.SIGNATURE_SUCCESS, sigIsOk & keyBindingIsOk);

        updateProgress(R.string.progress_done, 100, 100);
        return returnData;
    }

    private boolean verifyKeyBinding(PGPSignature signature, Key signatureKey) {
        long signatureKeyId = signature.getKeyID();
        boolean keyBindingIsOk = false;
        String userId = null;
        KeyRing signKeyRing = mKeyProvider.getPublicKeyRing(signatureKeyId);
        Key mKey = null;
        if (signKeyRing != null) {
            mKey = signKeyRing.getMasterKey();
        }
        if (signature.getKeyID() != mKey.getKeyId()) {
            keyBindingIsOk = verifyKeyBinding(mKey, signatureKey);
        } else {
            // if the key used to make the signature was the master key, no need to check binding sigs
            keyBindingIsOk = true;
        }
        return keyBindingIsOk;
    }

    private static boolean verifyKeyBinding(Key masterKey, Key signingKey) {
        boolean subkeyBindingIsOk = false;
        boolean tmpSubkeyBindingIsOk = false;
        boolean primkeyBindingIsOk = false;
        JcaPGPContentVerifierBuilderProvider contentVerifierBuilderProvider =
            new JcaPGPContentVerifierBuilderProvider()
                .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME);

        for (PGPSignature signature : signingKey.getSignatures()) {
            // what does gpg do if the subkey binding is wrong?
            // gpg has an invalid subkey binding error on key import I think, but doesn't shout
            // about keys without subkey signing. Can't get it to import a slightly broken one
            // either, so we will err on bad subkey binding here.
            if (signature.getKeyID() == masterKey.getKeyId() &&
                signature.getSignatureType() == PGPSignature.SUBKEY_BINDING) {
                // check and if ok, check primary key binding.
                try {
                    signature.init(contentVerifierBuilderProvider, masterKey.getPublicKey());
                    tmpSubkeyBindingIsOk = signature.verifyCertification(masterKey.getPublicKey(),
                                                                         signingKey.getPublicKey());
                } catch (PGPException e) {
                    continue;
                } catch (SignatureException e) {
                    continue;
                }

                if (tmpSubkeyBindingIsOk) {
                    subkeyBindingIsOk = true;
                }

                if (tmpSubkeyBindingIsOk) {
                    primkeyBindingIsOk = verifyPrimaryBinding(signature.getUnhashedSubPackets(),
                                                              masterKey, signingKey);
                    if (primkeyBindingIsOk) {
                        break;
                    }
                    primkeyBindingIsOk = verifyPrimaryBinding(signature.getHashedSubPackets(),
                                                              masterKey, signingKey);
                    if (primkeyBindingIsOk) {
                        break;
                    }
                }
            }
        }
        return (subkeyBindingIsOk & primkeyBindingIsOk);
    }

    public static PGPSignatureList getEmbeddedSignatures(PGPSignatureSubpacketVector packets)
            throws IOException, PGPException {
        SignatureSubpacket[] sigs = packets.getSubpackets(SignatureSubpacketTags.EMBEDDED_SIGNATURE);
        ArrayList l = new ArrayList();
        for (int i = 0; i < sigs.length; ++i) {
            byte[] data = sigs[i].getData();
            PGPSignature tmpSig = null;
            BCPGInputStream in = new BCPGInputStream(new ByteArrayInputStream(data));
            try {
                tmpSig = new PGPSignature(new SignaturePacket(in));
            } catch (IOException e) {
                tmpSig = null;
            } catch (PGPException e) {
                tmpSig = null;
            }
            if (tmpSig != null) {
                l.add(tmpSig);
            }
        }
        return new PGPSignatureList((PGPSignature[])l.toArray(new PGPSignature[l.size()]));
    }

    private static boolean verifyPrimaryBinding(PGPSignatureSubpacketVector packets,
                                                Key masterKey,
                                                Key signingKey) {
        boolean primkeyBindingIsOk = false;
        JcaPGPContentVerifierBuilderProvider contentVerifierBuilderProvider =
            new JcaPGPContentVerifierBuilderProvider()
                .setProvider(Constants.BOUNCY_CASTLE_PROVIDER_NAME);
        PGPSignatureList eSigList;

        if (packets.hasSubpacket(SignatureSubpacketTags.EMBEDDED_SIGNATURE)) {
            try {
                eSigList = getEmbeddedSignatures(packets);
            } catch (IOException e) {
                return false;
            } catch (PGPException e) {
                return false;
            }
            for (int j = 0; j < eSigList.size(); ++j) {
                PGPSignature emSig = eSigList.get(j);
                if (emSig.getSignatureType() == PGPSignature.PRIMARYKEY_BINDING) {
                    try {
                        emSig.init(contentVerifierBuilderProvider, signingKey.getPublicKey());
                        primkeyBindingIsOk = emSig.verifyCertification(masterKey.getPublicKey(),
                                                                       signingKey.getPublicKey());
                        if (primkeyBindingIsOk) {
                            break;
                        }
                    } catch (PGPException e) {
                        continue;
                    } catch (SignatureException e) {
                        continue;
                    }
                }
            }
        }
        return primkeyBindingIsOk;
    }

    /**
     * Mostly taken from ClearSignedFileProcessor in Bouncy Castle
     *
     * @param signature
     * @param line
     * @throws SignatureException
     * @throws IOException
     */
    private static void processLine(PGPSignature signature, byte[] line)
            throws SignatureException, IOException {
        int length = getLengthWithoutWhiteSpace(line);
        if (length > 0) {
            signature.update(line, 0, length);
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
        } while ((ch = fIn.read()) >= 0);

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
