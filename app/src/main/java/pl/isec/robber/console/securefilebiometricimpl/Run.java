package pl.isec.robber.console.securefilebiometricimpl;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.StandardOpenOption.READ;

import android.annotation.SuppressLint;
import android.app.Application;
import android.app.Instrumentation;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Looper;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.security.KeyException;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class Run {
    private static final String MASTER_KEY_ALIAS = "file_encryption_master_key";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
    private static final int IV_SIZE_IN_BYTES = 12;
    private static final int TAG_SIZE_IN_BYTES = 16;

    public static void main(String args[]){
        if(args.length != 2){
            System.err.println("Usage:\n\tpl.isec.robber.console.securefileimpl.Run <packageName> <encryptedFileName>");
            System.exit(1);
        }
        String packageName = args[0];
        String fileName = args[1];

        try {
            /** Initialize Android Keystore and application context **/
            initAndroidKeystore();
            Context context = initAppContext(packageName);

            /** Load SecretKey **/
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);

            if (!ks.containsAlias(MASTER_KEY_ALIAS)) {
                throw new KeyException("Key alias not found: "+ MASTER_KEY_ALIAS);
            }
            SecretKey secretKey = (SecretKey) ks.getKey(MASTER_KEY_ALIAS, null);

            /** Read encrypted file **/
            File encryptedFile = new File(context.getFilesDir(), fileName);
            InputStream inputStream = Files.newInputStream(encryptedFile.toPath(), READ);

            byte[] iv = new byte[IV_SIZE_IN_BYTES];
            int ciphertextSize = inputStream.available() - IV_SIZE_IN_BYTES;
            byte[] ciphertext = new byte[ciphertextSize];

            inputStream.read(iv, 0, IV_SIZE_IN_BYTES);
            inputStream.read(ciphertext, 0, ciphertextSize);
            inputStream.close();

            /** Decrypt data **/
            Cipher cipher = Cipher.getInstance(AES_GCM_NOPADDING);
            GCMParameterSpec spec = new GCMParameterSpec(8 * TAG_SIZE_IN_BYTES, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            cipher.updateAAD(encryptedFile.getName().getBytes(UTF_8));
            byte[] plaintext = cipher.doFinal(ciphertext);

            /** Print decrypted message **/
            System.out.println(
                new String(plaintext, UTF_8)
            );
        } catch(Exception e){
            e.printStackTrace();
        }
    }

    @SuppressLint({"BlockedPrivateApi"})
    private static void initAndroidKeystore() throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        /** static AndroidKeyStoreProvider.install() **/
        Class cAndroidKeyStoreProvider = Class.forName("android.security.keystore2.AndroidKeyStoreProvider");
        Method install = cAndroidKeyStoreProvider.getDeclaredMethod("install");
        install.invoke(cAndroidKeyStoreProvider);
    }

    private static Context initAppContext(String packageName) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException, InstantiationException {
        /** Required for ActivityThread **/
        Looper.prepareMainLooper();

        /** static ActivityThread.systemMain() **/
        Class cActivityThread = Class.forName("android.app.ActivityThread");
        Method systemMain = cActivityThread.getDeclaredMethod("systemMain");
        Object activityThread = systemMain.invoke(cActivityThread);

        /** virtual activityThread.getPackageInfo(...) **/
        Class cCompatibilityInfo = Class.forName("android.content.res.CompatibilityInfo");
        Constructor compatibilityInfoConstructor = cCompatibilityInfo.getConstructor(ApplicationInfo.class, int.class, int.class, boolean.class);
        Object compatibilityInfo = compatibilityInfoConstructor.newInstance(new ApplicationInfo(), 0x02, 200, true);

        Method getPackageInfo = cActivityThread.getDeclaredMethod("getPackageInfo", String.class, cCompatibilityInfo, int.class);
        Object loadedApk = getPackageInfo.invoke(activityThread, packageName, compatibilityInfo, 0);

        /** virtual loadedApk.makeApplication(...) **/
        Class cLoadedApk = Class.forName("android.app.LoadedApk");
        Method makeApplication = cLoadedApk.getDeclaredMethod("makeApplication", boolean.class, Instrumentation.class);
        Application application = (Application) makeApplication.invoke(loadedApk,true, null);

        return application.getApplicationContext();
    }
}
