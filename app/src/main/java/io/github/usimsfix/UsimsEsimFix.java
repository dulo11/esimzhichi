package io.github.usimsfix;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.telephony.euicc.EuiccManager;
import android.util.Log;

import java.lang.reflect.Method;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

public class UsimsEsimFix extends XposedModule {

    private static final String TAG = "USIMSeSIMFix";
    private static final String TARGET_PACKAGE = "com.wonet.usims";

    @Override
    public void onPackageReady(XposedModuleInterface.PackageReadyParam param) {
        if (!TARGET_PACKAGE.equals(param.getPackageName())) {
            return;
        }

        final ClassLoader classLoader = param.getDefaultClassLoader();

        try {
            Class<?> helper = Class.forName(
                    "com.wonet.usims.helpers.i",
                    false,
                    classLoader
            );

            Method esimCheck = helper.getDeclaredMethod(
                    "d",
                    Context.class
            );
            esimCheck.setAccessible(true);

            hook(esimCheck)
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .intercept(chain -> {
                        try {
                            Context context = (Context) chain.getArgs().get(0);
                            logEnvironment(context);
                        } catch (Throwable t) {
                            log(Log.WARN, TAG, "Diagnostic read failed", t);
                        }

                        log(Log.INFO, TAG,
                                "USIMS eSIM compatibility check -> forced TRUE");
                        return true;
                    });

            log(Log.INFO, TAG,
                    "Hook installed: com.wonet.usims.helpers.i.d(Context)");
        } catch (Throwable t) {
            log(Log.ERROR, TAG,
                    "Failed to hook USIMS eSIM compatibility method", t);
        }
    }

    private void logEnvironment(Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            boolean feature = pm.hasSystemFeature("android.hardware.telephony.euicc");

            EuiccManager euicc = null;
            try {
                euicc = (EuiccManager) context.getSystemService(Context.EUICC_SERVICE);
            } catch (Throwable ignored) {
            }

            String euiccState;
            if (euicc == null) {
                euiccState = "null";
            } else {
                try {
                    euiccState = "present,isEnabled=" + euicc.isEnabled();
                } catch (Throwable t) {
                    euiccState = "present,isEnabled=<error>";
                }
            }

            String version = "?";
            try {
                version = pm.getPackageInfo(context.getPackageName(), 0).versionName;
            } catch (Throwable ignored) {
            }

            log(Log.INFO, TAG,
                    "ENV appVersion=" + version
                            + " manufacturer=" + Build.MANUFACTURER
                            + " brand=" + Build.BRAND
                            + " model=" + Build.MODEL
                            + " device=" + Build.DEVICE
                            + " product=" + Build.PRODUCT
                            + " sdk=" + Build.VERSION.SDK_INT
                            + " euiccFeature=" + feature
                            + " euiccService=" + euiccState);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Failed to print environment", t);
        }
    }
}
