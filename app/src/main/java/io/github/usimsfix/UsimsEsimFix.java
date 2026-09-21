package io.github.usimsfix;

import android.content.Context;
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
}
