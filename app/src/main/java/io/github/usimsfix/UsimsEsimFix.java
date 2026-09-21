package io.github.usimsfix;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.media.MediaDrm;
import android.os.Build;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.telephony.euicc.EuiccManager;
import android.util.Log;

import org.json.JSONObject;

import java.lang.reflect.Method;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

public class UsimsEsimFix extends XposedModule {

    private static final String TAG = "USIMSeSIMFix";
    private static final String TARGET_PACKAGE = "com.wonet.usims";
    private static final String ROUTE_LOGIN = "routeLoginCall";
    private static final String INTEGRITY_NONCE = "generatePlayIntegrityNonce";
    private static final String INTEGRITY_VALIDATE = "validatePlayIntegrityToken";
    private static final AtomicBoolean ENV_LOGGED = new AtomicBoolean(false);
    private static final AtomicLong LOGIN_SEQ = new AtomicLong(0);
    private static volatile Context APP_CONTEXT;
    private static final java.util.Set<String> HOOKED_INTEGRITY_METHODS =
            java.util.Collections.newSetFromMap(
                    new java.util.concurrent.ConcurrentHashMap<String, Boolean>()
            );

    private static final String[] REQUEST_FIELDS = new String[]{
            "phone",
            "app_id",
            "phone_brand",
            "phone_type",
            "phone_os_version",
            "phone_manufacturer",
            "phone_esim_compatible",
            "phone_app_version",
            "device_id",
            "phone_mediadrm_id",
            "captcha_token",
            "hcaptcha_token"
    };

    @Override
    public void onPackageReady(XposedModuleInterface.PackageReadyParam param) {
        if (!TARGET_PACKAGE.equals(param.getPackageName())) {
            return;
        }

        final ClassLoader classLoader = param.getDefaultClassLoader();

        hookCompatibilityPreferenceReads();
        hookPlayIntegrityFactory(classLoader);
        hookUsimsEsimCheck(classLoader);
        hookUsimsRouteLogin(classLoader);
        hookOkHttpRouteLogin(classLoader);

        log(Log.INFO, TAG, "v1.4.3 loaded for " + TARGET_PACKAGE);
        log(Log.INFO, TAG,
                "MODULE diagnostics=routeLogin+prefs+PlayIntegrityTaskCompletion process=" + safeProcessName()
                        + " pid=" + android.os.Process.myPid()
                        + " uid=" + android.os.Process.myUid()
                        + " classLoader=" + classLoader.getClass().getName());
    }

    private void hookCompatibilityPreferenceReads() {
        try {
            Class<?> prefs = Class.forName("android.app.SharedPreferencesImpl");
            int installed = 0;

            for (Method method : prefs.getDeclaredMethods()) {
                String name = method.getName();
                Class<?>[] p = method.getParameterTypes();

                if (p.length == 0 || p[0] != String.class) {
                    continue;
                }

                if (!("getString".equals(name)
                        || "getBoolean".equals(name)
                        || "getInt".equals(name)
                        || "getLong".equals(name)
                        || "getFloat".equals(name)
                        || "contains".equals(name))) {
                    continue;
                }

                method.setAccessible(true);
                final Method hooked = method;

                hook(hooked)
                        .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                        .intercept(chain -> {
                            String key = null;
                            try {
                                if (!chain.getArgs().isEmpty()) {
                                    Object arg0 = chain.getArgs().get(0);
                                    if (arg0 != null) {
                                        key = String.valueOf(arg0);
                                    }
                                }
                            } catch (Throwable ignored) {
                            }

                            Object result = chain.proceed();

                            if (isCompatibilityPreferenceKey(key)) {
                                log(Log.INFO, TAG,
                                        "PREF_READ key=" + key
                                                + " method=" + hooked.getName()
                                                + " value="
                                                + summarizeCompatibilityPrefValue(result));
                                logInterestingStack("PREF_READ caller", 8);
                            }

                            return result;
                        });
                installed++;
            }

            log(Log.INFO, TAG,
                    "Hook installed: SharedPreferences compatibility reads count="
                            + installed);
        } catch (Throwable t) {
            log(Log.WARN, TAG,
                    "SharedPreferences compatibility hook unavailable", t);
        }
    }

    private boolean isCompatibilityPreferenceKey(String key) {
        return "backendEsimCompatibilityValue".equals(key)
                || "userphoneesimcompatible".equals(key);
    }

    private String summarizeCompatibilityPrefValue(Object value) {
        if (value == null) {
            return "null";
        }

        if (value instanceof Boolean || value instanceof Number) {
            return String.valueOf(value);
        }

        String text = String.valueOf(value);
        String lower = text.trim().toLowerCase(Locale.ROOT);

        if ("true".equals(lower)
                || "false".equals(lower)
                || "0".equals(lower)
                || "1".equals(lower)
                || "yes".equals(lower)
                || "no".equals(lower)
                || "null".equals(lower)
                || text.isEmpty()) {
            return truncate(text, 80);
        }

        return "<type=" + value.getClass().getName()
                + " len=" + text.length()
                + " sha256=" + shortHash(text) + ">";
    }

    private void logCompatibilityPreferencesSnapshot(Context context, String prefix) {
        if (context == null) {
            return;
        }

        java.io.FileInputStream input = null;
        try {
            java.io.File dir = new java.io.File(
                    context.getApplicationInfo().dataDir,
                    "shared_prefs"
            );

            java.io.File[] files = dir.listFiles();
            if (files == null || files.length == 0) {
                log(Log.INFO, TAG, prefix + " shared_prefs=<empty>");
                return;
            }

            boolean found = false;

            for (java.io.File file : files) {
                if (file == null
                        || !file.isFile()
                        || !file.getName().endsWith(".xml")) {
                    continue;
                }

                input = new java.io.FileInputStream(file);
                org.xmlpull.v1.XmlPullParser parser = android.util.Xml.newPullParser();
                parser.setInput(input, "UTF-8");

                int event;
                while ((event = parser.next())
                        != org.xmlpull.v1.XmlPullParser.END_DOCUMENT) {
                    if (event != org.xmlpull.v1.XmlPullParser.START_TAG) {
                        continue;
                    }

                    String key = parser.getAttributeValue(null, "name");
                    if (!isCompatibilityPreferenceKey(key)) {
                        continue;
                    }

                    found = true;
                    String tag = parser.getName();
                    String value;

                    if ("string".equals(tag)) {
                        try {
                            value = parser.nextText();
                        } catch (Throwable ignored) {
                            value = "<unreadable>";
                        }
                    } else {
                        value = parser.getAttributeValue(null, "value");
                    }

                    log(Log.INFO, TAG,
                            prefix
                                    + " file=" + file.getName()
                                    + " key=" + key
                                    + " tag=" + tag
                                    + " value="
                                    + summarizeCompatibilityPrefValue(value));
                }

                try {
                    input.close();
                } catch (Throwable ignored) {
                }
                input = null;
            }

            if (!found) {
                log(Log.INFO, TAG,
                        prefix
                                + " keys=[backendEsimCompatibilityValue,"
                                + "userphoneesimcompatible] <not-found>");
            }
        } catch (Throwable t) {
            log(Log.INFO, TAG,
                    prefix + " <unavailable:"
                            + t.getClass().getSimpleName() + ">");
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private void hookPlayIntegrityFactory(ClassLoader classLoader) {
        try {
            Class<?> factory = Class.forName(
                    "com.google.android.play.core.integrity.IntegrityManagerFactory",
                    false,
                    classLoader
            );

            int installed = 0;
            for (Method method : factory.getDeclaredMethods()) {
                if (!("create".equals(method.getName())
                        || "createStandard".equals(method.getName()))) {
                    continue;
                }

                method.setAccessible(true);
                final Method hooked = method;

                hook(hooked)
                        .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                        .intercept(chain -> {
                            long started =
                                    android.os.SystemClock.elapsedRealtime();

                            log(Log.INFO, TAG,
                                    "INTEGRITY_FACTORY BEGIN method="
                                            + hooked.toGenericString()
                                            + " argTypes="
                                            + summarizeArgTypes(chain.getArgs()));
                            logInterestingStack("INTEGRITY_FACTORY caller", 10);

                            Object manager = chain.proceed();

                            long elapsed =
                                    android.os.SystemClock.elapsedRealtime()
                                            - started;

                            log(Log.INFO, TAG,
                                    "INTEGRITY_FACTORY END method="
                                            + hooked.getName()
                                            + " elapsedMs=" + elapsed
                                            + " managerClass="
                                            + (manager == null
                                            ? "null"
                                            : manager.getClass().getName()));

                            if (manager != null) {
                                hookIntegrityRuntimeManager(manager);
                            }

                            return manager;
                        });
                installed++;
            }

            log(Log.INFO, TAG,
                    "Hook installed: IntegrityManagerFactory methods="
                            + installed);
        } catch (Throwable t) {
            log(Log.INFO, TAG,
                    "IntegrityManagerFactory unavailable: "
                            + t.getClass().getSimpleName());
        }
    }

    private void hookIntegrityRuntimeManager(Object manager) {
        if (manager == null) {
            return;
        }

        try {
            Class<?> cls = manager.getClass();

            for (Method method : cls.getMethods()) {
                String name = method.getName();
                if (!("requestIntegrityToken".equals(name)
                        || "prepareIntegrityToken".equals(name))) {
                    continue;
                }

                String id = cls.getName() + "#" + method.toGenericString();
                if (!HOOKED_INTEGRITY_METHODS.add(id)) {
                    continue;
                }

                method.setAccessible(true);
                final Method hooked = method;

                try {
                    hook(hooked)
                            .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                            .intercept(chain -> {
                                long started =
                                        android.os.SystemClock.elapsedRealtime();

                                log(Log.INFO, TAG,
                                        "INTEGRITY_CALL BEGIN method="
                                                + hooked.toGenericString()
                                                + " argTypes="
                                                + summarizeArgTypes(chain.getArgs()));
                                logInterestingStack("INTEGRITY_CALL caller", 10);

                                Object result = chain.proceed();

                                long elapsed =
                                        android.os.SystemClock.elapsedRealtime()
                                                - started;

                                log(Log.INFO, TAG,
                                        "INTEGRITY_CALL END method="
                                                + hooked.getName()
                                                + " elapsedMs=" + elapsed
                                                + " returnClass="
                                                + (result == null
                                                ? "null"
                                                : result.getClass().getName()));

                                if (result != null) {
                                    attachIntegrityTaskCompletionDiagnostic(
                                            result,
                                            hooked.getName(),
                                            started
                                    );
                                }

                                return result;
                            });

                    log(Log.INFO, TAG,
                            "Hook installed: integrity runtime method="
                                    + hooked.toGenericString());
                } catch (Throwable hookError) {
                    log(Log.WARN, TAG,
                            "Integrity runtime hook failed: "
                                    + hooked.toGenericString(),
                            hookError);
                }
            }
        } catch (Throwable t) {
            log(Log.WARN, TAG,
                    "Integrity runtime manager diagnostic failed", t);
        }
    }

    private void attachIntegrityTaskCompletionDiagnostic(
            Object task,
            String label,
            long startedMs) {
        try {
            Method addOnComplete = null;
            Class<?> listenerType = null;

            for (Method method : task.getClass().getMethods()) {
                if (!"addOnCompleteListener".equals(method.getName())) {
                    continue;
                }

                Class<?>[] p = method.getParameterTypes();
                if (p.length != 1) {
                    continue;
                }

                if (p[0].getName().endsWith(".OnCompleteListener")) {
                    addOnComplete = method;
                    listenerType = p[0];
                    break;
                }
            }

            if (addOnComplete == null || listenerType == null) {
                log(Log.INFO, TAG,
                        "INTEGRITY_TASK listener-unavailable label="
                                + label
                                + " taskClass=" + task.getClass().getName());
                return;
            }

            final Class<?> finalListenerType = listenerType;

            Object listener = java.lang.reflect.Proxy.newProxyInstance(
                    finalListenerType.getClassLoader(),
                    new Class[]{finalListenerType},
                    (proxy, method, args) -> {
                        if ("onComplete".equals(method.getName())
                                && args != null
                                && args.length > 0
                                && args[0] != null) {
                            logIntegrityTaskState(
                                    args[0],
                                    label,
                                    startedMs
                            );
                        }

                        if ("toString".equals(method.getName())) {
                            return "USIMSeSIMFixIntegrityListener(" + label + ")";
                        }

                        if ("hashCode".equals(method.getName())) {
                            return System.identityHashCode(proxy);
                        }

                        if ("equals".equals(method.getName())) {
                            return args != null
                                    && args.length == 1
                                    && proxy == args[0];
                        }

                        return null;
                    }
            );

            addOnComplete.setAccessible(true);
            addOnComplete.invoke(task, listener);

            log(Log.INFO, TAG,
                    "INTEGRITY_TASK listener-attached label="
                            + label
                            + " taskClass=" + task.getClass().getName());
        } catch (Throwable t) {
            log(Log.WARN, TAG,
                    "INTEGRITY_TASK listener attach failed label="
                            + label
                            + " type=" + t.getClass().getSimpleName(),
                    t);
        }
    }

    private void logIntegrityTaskState(
            Object task,
            String label,
            long startedMs) {
        try {
            long elapsedMs =
                    android.os.SystemClock.elapsedRealtime() - startedMs;

            boolean complete =
                    booleanNoArg(task, "isComplete", true);
            boolean successful =
                    booleanNoArg(task, "isSuccessful", false);
            boolean canceled =
                    booleanNoArg(task, "isCanceled", false);

            Throwable exception = null;
            try {
                Object ex = invokeNoArgs(task, "getException");
                if (ex instanceof Throwable) {
                    exception = (Throwable) ex;
                }
            } catch (Throwable ignored) {
            }

            log(Log.INFO, TAG,
                    "INTEGRITY_TASK COMPLETE label=" + label
                            + " elapsedMs=" + elapsedMs
                            + " complete=" + complete
                            + " successful=" + successful
                            + " canceled=" + canceled
                            + " exceptionClass="
                            + (exception == null
                            ? "null"
                            : exception.getClass().getName())
                            + " exceptionMessage="
                            + (exception == null
                            ? "null"
                            : summarizeThrowableMessage(
                            exception.getMessage()
                    )));

            if (successful
                    && "prepareIntegrityToken".equals(label)) {
                try {
                    Object provider = invokeNoArgs(task, "getResult");

                    log(Log.INFO, TAG,
                            "INTEGRITY_PROVIDER obtained class="
                                    + (provider == null
                                    ? "null"
                                    : provider.getClass().getName()));

                    if (provider != null) {
                        hookIntegrityRuntimeProvider(provider);
                    }
                } catch (Throwable t) {
                    log(Log.WARN, TAG,
                            "INTEGRITY_PROVIDER inspect failed type="
                                    + t.getClass().getSimpleName());
                }
            }
        } catch (Throwable t) {
            log(Log.WARN, TAG,
                    "INTEGRITY_TASK state diagnostic failed label="
                            + label,
                    t);
        }
    }

    private boolean booleanNoArg(
            Object target,
            String method,
            boolean fallback) {
        try {
            Object value = invokeNoArgs(target, method);
            return value instanceof Boolean
                    ? (Boolean) value
                    : fallback;
        } catch (Throwable t) {
            return fallback;
        }
    }

    private void hookIntegrityRuntimeProvider(Object provider) {
        if (provider == null) {
            return;
        }

        try {
            Class<?> cls = provider.getClass();

            for (Method method : cls.getMethods()) {
                if (!"request".equals(method.getName())) {
                    continue;
                }

                String id =
                        cls.getName() + "#" + method.toGenericString();

                if (!HOOKED_INTEGRITY_METHODS.add(id)) {
                    continue;
                }

                method.setAccessible(true);
                final Method hooked = method;

                try {
                    hook(hooked)
                            .setExceptionMode(
                                    XposedInterface.ExceptionMode.PROTECTIVE
                            )
                            .intercept(chain -> {
                                long started =
                                        android.os.SystemClock.elapsedRealtime();

                                log(Log.INFO, TAG,
                                        "INTEGRITY_PROVIDER_CALL BEGIN method="
                                                + hooked.toGenericString()
                                                + " argTypes="
                                                + summarizeArgTypes(
                                                chain.getArgs()
                                        ));
                                logInterestingStack(
                                        "INTEGRITY_PROVIDER_CALL caller",
                                        10
                                );

                                Object result = chain.proceed();

                                long elapsed =
                                        android.os.SystemClock
                                                .elapsedRealtime()
                                                - started;

                                log(Log.INFO, TAG,
                                        "INTEGRITY_PROVIDER_CALL END method="
                                                + hooked.getName()
                                                + " elapsedMs=" + elapsed
                                                + " returnClass="
                                                + (result == null
                                                ? "null"
                                                : result.getClass().getName()));

                                if (result != null) {
                                    attachIntegrityTaskCompletionDiagnostic(
                                            result,
                                            "standardProvider.request",
                                            started
                                    );
                                }

                                return result;
                            });

                    log(Log.INFO, TAG,
                            "Hook installed: integrity provider method="
                                    + hooked.toGenericString());
                } catch (Throwable hookError) {
                    log(Log.WARN, TAG,
                            "Integrity provider hook failed: "
                                    + hooked.toGenericString(),
                            hookError);
                }
            }
        } catch (Throwable t) {
            log(Log.WARN, TAG,
                    "Integrity provider diagnostic failed", t);
        }
    }

    private String summarizeArgTypes(java.util.List<?> args) {
        if (args == null) {
            return "null";
        }

        java.util.List<String> types = new java.util.ArrayList<>();
        for (Object arg : args) {
            types.add(arg == null ? "null" : arg.getClass().getName());
        }
        return String.valueOf(types);
    }

    private void logInterestingStack(String label, int maxFrames) {
        try {
            StackTraceElement[] frames =
                    Thread.currentThread().getStackTrace();

            int written = 0;
            for (StackTraceElement frame : frames) {
                if (frame == null) {
                    continue;
                }

                String cls = frame.getClassName();
                if (cls == null
                        || cls.startsWith("java.lang.Thread")
                        || cls.startsWith("io.github.usimsfix.")) {
                    continue;
                }

                if (!(cls.startsWith("com.wonet.usims")
                        || cls.startsWith("com.google.android.play.core.integrity")
                        || cls.startsWith("com.google.android.recaptcha")
                        || cls.startsWith("android."))) {
                    continue;
                }

                log(Log.INFO, TAG,
                        label + "[" + written + "]="
                                + frame.getClassName()
                                + "." + frame.getMethodName()
                                + ":" + frame.getLineNumber());

                written++;
                if (written >= maxFrames) {
                    break;
                }
            }

            if (written == 0) {
                log(Log.INFO, TAG, label + "=<no-interesting-frames>");
            }
        } catch (Throwable ignored) {
        }
    }

    private void hookUsimsEsimCheck(ClassLoader classLoader) {
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
                        Context context = null;
                        try {
                            if (!chain.getArgs().isEmpty()
                                    && chain.getArgs().get(0) instanceof Context) {
                                context = (Context) chain.getArgs().get(0);
                            }
                        } catch (Throwable ignored) {
                        }

                        if (context != null) {
                            try {
                                Context app = context.getApplicationContext();
                                APP_CONTEXT = app != null ? app : context;
                            } catch (Throwable ignored) {
                                APP_CONTEXT = context;
                            }
                        }

                        if (context != null && ENV_LOGGED.compareAndSet(false, true)) {
                            logEnvironment(context);
                            logCompatibilityPreferencesSnapshot(context, "PREF INITIAL");
                        }

                        Object original = "<not-evaluated>";
                        try {
                            original = chain.proceed();
                        } catch (Throwable t) {
                            original = "<error:" + t.getClass().getSimpleName() + ">";
                            log(Log.WARN, TAG, "Original eSIM check threw; forcing TRUE", t);
                        }

                        log(Log.INFO, TAG,
                                "USIMS eSIM compatibility original=" + original
                                        + " -> forced TRUE");
                        return true;
                    });

            log(Log.INFO, TAG,
                    "Hook installed: com.wonet.usims.helpers.i.d(Context)");
        } catch (Throwable t) {
            log(Log.ERROR, TAG,
                    "Failed to hook USIMS eSIM compatibility method", t);
        }
    }

    private void hookUsimsRouteLogin(ClassLoader classLoader) {
        try {
            Class<?> networkClass = Class.forName("Be.d", false, classLoader);
            Method target = null;

            for (Method m : networkClass.getDeclaredMethods()) {
                Class<?>[] p = m.getParameterTypes();
                if ("c".equals(m.getName())
                        && p.length == 4
                        && p[0] == String.class
                        && java.util.HashMap.class.isAssignableFrom(p[1])
                        && (p[3] == boolean.class || p[3] == Boolean.class)) {
                    target = m;
                    break;
                }
            }

            if (target == null) {
                log(Log.WARN, TAG,
                        "Direct network hook target not found: Be.d.c(String, HashMap, *, boolean)");
                return;
            }

            target.setAccessible(true);
            final Method hooked = target;

            hook(hooked)
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .intercept(chain -> {
                        final long requestId = LOGIN_SEQ.incrementAndGet();
                        final long startedMs = android.os.SystemClock.elapsedRealtime();

                        String url = "";
                        boolean isRouteLogin = false;
                        boolean isIntegrityNonce = false;
                        boolean isIntegrityValidate = false;
                        String endpointName = null;

                        try {
                            java.util.List<?> args = chain.getArgs();
                            Object urlObj = args.size() > 0 ? args.get(0) : null;
                            Object mapObj = args.size() > 1 ? args.get(1) : null;
                            Object callbackObj = args.size() > 2 ? args.get(2) : null;
                            Object flagObj = args.size() > 3 ? args.get(3) : null;

                            url = String.valueOf(urlObj);
                            isRouteLogin = url.contains(ROUTE_LOGIN);
                            isIntegrityNonce = url.contains(INTEGRITY_NONCE);
                            isIntegrityValidate = url.contains(INTEGRITY_VALIDATE);
                            endpointName = isRouteLogin
                                    ? ROUTE_LOGIN
                                    : (isIntegrityNonce
                                    ? INTEGRITY_NONCE
                                    : (isIntegrityValidate ? INTEGRITY_VALIDATE : null));

                            if (endpointName != null) {
                                Thread thread = Thread.currentThread();

                                log(Log.INFO, TAG,
                                        "========== " + endpointName + " DIRECT BEGIN ==========");
                                log(Log.INFO, TAG,
                                        "DIRECT requestId=" + requestId
                                                + " pid=" + android.os.Process.myPid()
                                                + " uid=" + android.os.Process.myUid()
                                                + " threadId=" + thread.getId()
                                                + " threadName=" + truncate(thread.getName(), 120));
                                log(Log.INFO, TAG,
                                        "DIRECT process=" + safeProcessName()
                                                + " classLoader=" + classLoader.getClass().getName());
                                log(Log.INFO, TAG,
                                        "DIRECT method=" + hooked.toGenericString());
                                log(Log.INFO, TAG,
                                        "DIRECT url=" + stripQuery(url));
                                log(Log.INFO, TAG,
                                        "DIRECT argsCount=" + args.size()
                                                + " callbackClass="
                                                + (callbackObj == null
                                                ? "null" : callbackObj.getClass().getName())
                                                + " flag=" + String.valueOf(flagObj));

                                if (mapObj instanceof Map) {
                                    @SuppressWarnings("unchecked")
                                    Map<Object, Object> map = (Map<Object, Object>) mapObj;

                                    log(Log.INFO, TAG,
                                            "DIRECT mapClass=" + mapObj.getClass().getName()
                                                    + " size=" + map.size());

                                    java.util.List<String> keys = new java.util.ArrayList<>();
                                    for (Object keyObj : map.keySet()) {
                                        keys.add(String.valueOf(keyObj));
                                    }
                                    java.util.Collections.sort(keys);

                                    log(Log.INFO, TAG, "DIRECT mapKeys=" + keys);
                                    logRequestShape(map, requestId);

                                    for (String key : keys) {
                                        Object valueObj = map.get(key);
                                        String value = valueObj == null
                                                ? "null" : String.valueOf(valueObj);
                                        log(Log.INFO, TAG,
                                                "DIRECT " + key + "="
                                                        + summarizeDirectMapValue(key, value));
                                    }
                                } else {
                                    log(Log.INFO, TAG,
                                            "DIRECT args[1] is not Map: "
                                                    + (mapObj == null
                                                    ? "null" : mapObj.getClass().getName()));
                                }

                                Context ctx = APP_CONTEXT;
                                if (ctx != null) {
                                    logNetworkSnapshot(ctx, "DIRECT NET");
                                    logIdentityConsistency();
                                    logCompatibilityPreferencesSnapshot(
                                            ctx,
                                            "DIRECT PREF " + endpointName
                                    );
                                } else {
                                    log(Log.INFO, TAG,
                                            "DIRECT context=<not-yet-captured>");
                                }

                                log(Log.INFO, TAG,
                                        "========== " + endpointName + " DIRECT END ==========");
                            }
                        } catch (Throwable t) {
                            log(Log.WARN, TAG,
                                    "Direct routeLoginCall request diagnostic failed", t);
                        }

                        try {
                            Object result = chain.proceed();

                            if (endpointName != null) {
                                long elapsedMs =
                                        android.os.SystemClock.elapsedRealtime() - startedMs;

                                log(Log.INFO, TAG,
                                        "========== " + endpointName + " RESPONSE BEGIN ==========");
                                log(Log.INFO, TAG,
                                        "DIRECT response.requestId=" + requestId
                                                + " endpoint=" + endpointName
                                                + " elapsedMs=" + elapsedMs
                                                + " responseThread="
                                                + truncate(Thread.currentThread().getName(), 120));
                                logDirectLoginResponse(result);
                                log(Log.INFO, TAG,
                                        "========== " + endpointName + " RESPONSE END ==========");
                            }

                            return result;
                        } catch (Throwable t) {
                            if (endpointName != null) {
                                long elapsedMs =
                                        android.os.SystemClock.elapsedRealtime() - startedMs;
                                log(Log.ERROR, TAG,
                                        endpointName + " threw requestId=" + requestId
                                                + " elapsedMs=" + elapsedMs
                                                + " type=" + t.getClass().getName()
                                                + " message="
                                                + summarizeThrowableMessage(t.getMessage()));
                                logThrowableFrames("DIRECT throwable", t, 8);
                            }
                            throw t;
                        }
                    });

            log(Log.INFO, TAG,
                    "Hook installed: Be.d.c(String, HashMap, *, boolean)");
        } catch (Throwable t) {
            log(Log.ERROR, TAG,
                    "Failed to install direct USIMS network hook", t);
        }
    }

    private void logRequestShape(Map<Object, Object> map, long requestId) {
        try {
            java.util.List<String> keys = new java.util.ArrayList<>();
            for (Object key : map.keySet()) {
                keys.add(String.valueOf(key));
            }
            java.util.Collections.sort(keys);

            StringBuilder shape = new StringBuilder();
            for (String key : keys) {
                Object value = map.get(key);
                String text = value == null ? "" : String.valueOf(value);
                shape.append(key)
                        .append(':')
                        .append(value == null ? "null" : value.getClass().getName())
                        .append(':')
                        .append(text.length())
                        .append(';');
            }

            log(Log.INFO, TAG,
                    "DIRECT requestShape requestId=" + requestId
                            + " sha256=" + shortHash(shape.toString())
                            + " keyCount=" + keys.size());
        } catch (Throwable t) {
            log(Log.WARN, TAG, "DIRECT request shape diagnostic failed", t);
        }
    }

    private void logThrowableFrames(String label, Throwable t, int maxFrames) {
        try {
            StackTraceElement[] frames = t.getStackTrace();
            int n = Math.min(frames == null ? 0 : frames.length, maxFrames);
            for (int i = 0; i < n; i++) {
                log(Log.INFO, TAG,
                        label + "[" + i + "]=" + String.valueOf(frames[i]));
            }
        } catch (Throwable ignored) {
        }
    }

    private void logDirectLoginResponse(Object result) {
        if (result == null) {
            log(Log.INFO, TAG, "DIRECT response=null");
            return;
        }

        String raw = String.valueOf(result);
        log(Log.INFO, TAG,
                "DIRECT responseClass=" + result.getClass().getName()
                        + " len=" + raw.length()
                        + " sha256=" + shortHash(raw));

        String trimmed = raw.trim();
        if (!trimmed.startsWith("{")) {
            if (looksSensitiveResponseText(trimmed)) {
                log(Log.INFO, TAG,
                        "DIRECT responseText=<redacted len=" + raw.length()
                                + " sha256=" + shortHash(raw) + ">");
            } else {
                log(Log.INFO, TAG,
                        "DIRECT responseText=" + truncate(trimmed, 1000));
            }
            return;
        }

        try {
            JSONObject obj = new JSONObject(trimmed);

            java.util.List<String> keys = new java.util.ArrayList<>();
            java.util.Iterator<String> iterator = obj.keys();
            while (iterator.hasNext()) {
                keys.add(iterator.next());
            }
            java.util.Collections.sort(keys);
            log(Log.INFO, TAG, "DIRECT responseKeys=" + keys);

            java.util.Set<String> wanted = new java.util.HashSet<>(
                    java.util.Arrays.asList(
                            "code",
                            "status",
                            "success",
                            "message",
                            "msg",
                            "error",
                            "error_code",
                            "errorcode",
                            "reason",
                            "result"
                    )
            );

            boolean found = false;
            for (String actualKey : keys) {
                String normalized = actualKey == null
                        ? "" : actualKey.toLowerCase(Locale.ROOT);
                if (!wanted.contains(normalized)) {
                    continue;
                }

                found = true;

                if (obj.isNull(actualKey)) {
                    log(Log.INFO, TAG,
                            "DIRECT response." + actualKey + "=null");
                    continue;
                }

                Object value = obj.opt(actualKey);

                if ("result".equals(normalized)) {
                    logResultStructure("DIRECT response." + actualKey, value, 0);
                    continue;
                }

                log(Log.INFO, TAG,
                        "DIRECT response." + actualKey + "="
                                + summarizeResponseValue(actualKey, value));
            }

            if (!found) {
                log(Log.INFO, TAG,
                        "DIRECT response=<JSON parsed; no diagnostic fields>");
            }
        } catch (Throwable t) {
            log(Log.WARN, TAG,
                    "DIRECT response JSON parse failed; len=" + raw.length()
                            + " sha256=" + shortHash(raw));
        }
    }

    private void logResultStructure(String label, Object value, int depth) {
        if (value == null || value == JSONObject.NULL) {
            log(Log.INFO, TAG, label + "=null");
            return;
        }

        if (depth > 3) {
            String text = String.valueOf(value);
            log(Log.INFO, TAG,
                    label + "=<depth-limit type=" + value.getClass().getName()
                            + " len=" + text.length()
                            + " sha256=" + shortHash(text) + ">");
            return;
        }

        if (value instanceof JSONObject) {
            JSONObject obj = (JSONObject) value;
            java.util.List<String> keys = new java.util.ArrayList<>();
            java.util.Iterator<String> it = obj.keys();
            while (it.hasNext()) {
                keys.add(it.next());
            }
            java.util.Collections.sort(keys);

            log(Log.INFO, TAG, label + "Keys=" + keys);

            for (String key : keys) {
                Object nested = obj.opt(key);
                String child = label + "." + key;

                if (nested == null || nested == JSONObject.NULL) {
                    log(Log.INFO, TAG, child + "=null");
                    continue;
                }

                if (isSensitiveKey(key)) {
                    String text = String.valueOf(nested);
                    log(Log.INFO, TAG,
                            child + "=<redacted type=" + nested.getClass().getName()
                                    + " len=" + text.length()
                                    + " sha256=" + shortHash(text) + ">");
                    continue;
                }

                if (nested instanceof JSONObject
                        || nested instanceof org.json.JSONArray) {
                    logResultStructure(child, nested, depth + 1);
                    continue;
                }

                if (nested instanceof Boolean || nested instanceof Number) {
                    log(Log.INFO, TAG, child + "=" + String.valueOf(nested));
                    continue;
                }

                String text = String.valueOf(nested);
                if (isReadableDiagnosticKey(key)
                        && !looksSensitiveResponseText(text)) {
                    log(Log.INFO, TAG, child + "=" + truncate(text, 1000));
                } else {
                    log(Log.INFO, TAG,
                            child + "=<type=" + nested.getClass().getName()
                                    + " len=" + text.length()
                                    + " sha256=" + shortHash(text) + ">");
                }
            }
            return;
        }

        if (value instanceof org.json.JSONArray) {
            org.json.JSONArray array = (org.json.JSONArray) value;
            log(Log.INFO, TAG,
                    label + "=<array length=" + array.length() + ">");

            int inspect = Math.min(array.length(), 5);
            for (int i = 0; i < inspect; i++) {
                Object item = array.opt(i);
                String child = label + "[" + i + "]";

                if (item == null || item == JSONObject.NULL) {
                    log(Log.INFO, TAG, child + "=null");
                } else if (item instanceof JSONObject
                        || item instanceof org.json.JSONArray) {
                    logResultStructure(child, item, depth + 1);
                } else if (item instanceof Boolean || item instanceof Number) {
                    log(Log.INFO, TAG, child + "=" + String.valueOf(item));
                } else {
                    String text = String.valueOf(item);
                    log(Log.INFO, TAG,
                            child + "=<type=" + item.getClass().getName()
                                    + " len=" + text.length()
                                    + " sha256=" + shortHash(text) + ">");
                }
            }
            return;
        }

        if (value instanceof Boolean || value instanceof Number) {
            log(Log.INFO, TAG, label + "=" + String.valueOf(value));
            return;
        }

        String text = String.valueOf(value);
        String trimmed = text.trim();

        log(Log.INFO, TAG,
                label + "=<type=" + value.getClass().getName()
                        + " len=" + text.length()
                        + " sha256=" + shortHash(text) + ">");

        if (trimmed.startsWith("{")) {
            try {
                logResultStructure(label + ".json",
                        new JSONObject(trimmed), depth + 1);
            } catch (Throwable ignored) {
            }
        } else if (trimmed.startsWith("[")) {
            try {
                logResultStructure(label + ".json",
                        new org.json.JSONArray(trimmed), depth + 1);
            } catch (Throwable ignored) {
            }
        }
    }

    private boolean isReadableDiagnosticKey(String key) {
        if (key == null) {
            return false;
        }

        String normalized = key.toLowerCase(Locale.ROOT);
        return normalized.equals("code")
                || normalized.equals("status")
                || normalized.equals("success")
                || normalized.equals("message")
                || normalized.equals("msg")
                || normalized.equals("error")
                || normalized.equals("error_code")
                || normalized.equals("errorcode")
                || normalized.equals("reason")
                || normalized.equals("compatible")
                || normalized.equals("compatibility")
                || normalized.equals("device_compatible")
                || normalized.equals("devicecompatible")
                || normalized.equals("supported")
                || normalized.equals("min_version")
                || normalized.equals("minversion")
                || normalized.equals("latest_version")
                || normalized.equals("latestversion")
                || normalized.equals("app_version")
                || normalized.equals("appversion")
                || normalized.equals("version")
                || normalized.equals("type")
                || normalized.equals("state");
    }

    private boolean isSensitiveKey(String key) {
        if (key == null) {
            return false;
        }

        String lower = key.toLowerCase(Locale.ROOT);
        return lower.contains("token")
                || lower.contains("authorization")
                || lower.contains("cookie")
                || lower.contains("session")
                || lower.contains("secret")
                || lower.contains("password")
                || lower.contains("phone")
                || lower.contains("mobile")
                || lower.contains("email")
                || lower.contains("device_id")
                || lower.contains("mediadrm")
                || lower.contains("android_id")
                || lower.contains("signature")
                || lower.contains("captcha")
                || lower.equals("key")
                || lower.endsWith("_key");
    }

    private String summarizeResponseValue(String key, Object value) {
        if (value == null || value == JSONObject.NULL) {
            return "null";
        }

        String lower = key == null ? "" : key.toLowerCase(Locale.ROOT);
        String text = String.valueOf(value);

        if (lower.contains("token")
                || lower.contains("authorization")
                || lower.contains("cookie")
                || lower.contains("session")
                || lower.contains("secret")
                || lower.contains("password")
                || lower.contains("phone")
                || lower.contains("mobile")
                || lower.contains("email")
                || lower.contains("device")) {
            return "<redacted len=" + text.length()
                    + " sha256=" + shortHash(text) + ">";
        }

        if (value instanceof JSONObject
                || value instanceof org.json.JSONArray) {
            return "<json len=" + text.length()
                    + " sha256=" + shortHash(text) + ">";
        }

        return truncate(text, 1000);
    }

    private boolean looksSensitiveResponseText(String text) {
        if (text == null) {
            return false;
        }

        String lower = text.toLowerCase(Locale.ROOT);
        return lower.contains("token")
                || lower.contains("authorization")
                || lower.contains("cookie")
                || lower.contains("session")
                || lower.contains("secret")
                || lower.contains("password")
                || lower.contains("device_id")
                || lower.contains("mediadrm")
                || lower.contains("phone\"")
                || lower.contains("mobile\"")
                || lower.contains("email\"");
    }

    private String summarizeThrowableMessage(String message) {
        if (message == null) {
            return "null";
        }
        if (looksSensitiveResponseText(message)) {
            return "<redacted len=" + message.length()
                    + " sha256=" + shortHash(message) + ">";
        }
        return truncate(message, 500);
    }

    private String summarizeDirectMapValue(String key, String value) {
        if (value == null) {
            return "null";
        }

        String lower = key == null ? "" : key.toLowerCase(Locale.ROOT);

        if ("phone_brand".equals(key)
                || "phone_type".equals(key)
                || "phone_os_version".equals(key)
                || "phone_manufacturer".equals(key)
                || "phone_esim_compatible".equals(key)
                || "phone_app_version".equals(key)) {
            return truncate(value, 300);
        }

        if ("app_id".equals(key)) {
            return sensitiveSummary(value);
        }

        if ("phone".equals(key)) {
            return "<redacted len=" + value.length() + ">";
        }

        if ("device_id".equals(key)
                || "phone_mediadrm_id".equals(key)) {
            return sensitiveSummary(value);
        }

        if (lower.contains("token")
                || lower.contains("captcha")
                || lower.contains("password")
                || lower.contains("secret")
                || lower.contains("authorization")
                || lower.contains("cookie")
                || lower.contains("signature")
                || lower.contains("key")) {
            return "<redacted len=" + value.length()
                    + " sha256=" + shortHash(value) + ">";
        }

        return "<len=" + value.length()
                + " sha256=" + shortHash(value) + ">";
    }

    private void hookOkHttpRouteLogin(ClassLoader classLoader) {
        try {
            Class<?> builder = Class.forName(
                    "okhttp3.Request$Builder",
                    false,
                    classLoader
            );
            Method build = builder.getDeclaredMethod("build");
            build.setAccessible(true);

            hook(build)
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .intercept(chain -> {
                        Object request = chain.proceed();
                        try {
                            inspectRequest(request, classLoader);
                        } catch (Throwable t) {
                            log(Log.WARN, TAG, "HTTP diagnostic failed", t);
                        }
                        return request;
                    });

            log(Log.INFO, TAG, "Hook installed: okhttp3.Request$Builder.build()");
        } catch (Throwable t) {
            log(Log.WARN, TAG,
                    "OkHttp build hook unavailable; request-field diagnostics may be limited", t);
        }
    }

    private void inspectRequest(Object request, ClassLoader classLoader) throws Exception {
        if (request == null) {
            return;
        }

        Object urlObj = invokeNoArgs(request, "url");
        String url = String.valueOf(urlObj);
        if (!url.contains(ROUTE_LOGIN)) {
            return;
        }

        String method = stringValue(invokeNoArgs(request, "method"));
        Object body = invokeNoArgs(request, "body");

        log(Log.INFO, TAG, "========== routeLoginCall BEGIN ==========");
        log(Log.INFO, TAG, "HTTP method=" + method + " url=" + stripQuery(url));

        inspectHeaders(request);

        Map<String, String> values = new LinkedHashMap<>();
        boolean parsedAsForm = extractFormBody(body, values);

        String rawBody = null;
        if (!parsedAsForm) {
            rawBody = readRequestBody(body, classLoader);
            if (rawBody != null) {
                parseKnownFields(rawBody, values);
            }
        }

        String bodyClass = body == null ? "null" : body.getClass().getName();
        String contentType = safeStringInvoke(body, "contentType");
        String contentLength = safeStringInvoke(body, "contentLength");

        String bodyDigest = rawBody == null
                ? "<not-copied>"
                : shortHash(rawBody);

        log(Log.INFO, TAG,
                "BODY class=" + bodyClass
                        + " contentType=" + contentType
                        + " contentLength=" + contentLength
                        + " parsedAsForm=" + parsedAsForm
                        + " bodySha256=" + bodyDigest);

        for (String key : REQUEST_FIELDS) {
            if (values.containsKey(key)) {
                log(Log.INFO, TAG,
                        "REQ " + key + "=" + summarizeRequestValue(key, values.get(key)));
            } else {
                log(Log.INFO, TAG, "REQ " + key + "=<missing>");
            }
        }

        log(Log.INFO, TAG, "========== routeLoginCall END ==========");
    }

    private void inspectHeaders(Object request) {
        try {
            Object headers = invokeNoArgs(request, "headers");
            if (headers == null) {
                return;
            }

            Object namesObj = invokeNoArgs(headers, "names");
            if (!(namesObj instanceof Set)) {
                return;
            }

            @SuppressWarnings("unchecked")
            Set<Object> names = (Set<Object>) namesObj;
            Method get = headers.getClass().getMethod("get", String.class);

            int count = 0;
            for (Object n : names) {
                if (count++ >= 40) {
                    log(Log.INFO, TAG, "HDR <truncated>");
                    break;
                }

                String name = String.valueOf(n);
                Object valueObj = get.invoke(headers, name);
                String value = valueObj == null ? "" : String.valueOf(valueObj);

                String lower = name.toLowerCase(Locale.ROOT);
                if (lower.contains("authorization")
                        || lower.contains("cookie")
                        || lower.contains("token")
                        || lower.contains("secret")
                        || lower.contains("api-key")
                        || lower.contains("apikey")
                        || lower.contains("signature")) {
                    value = "<redacted len=" + value.length() + ">";
                } else {
                    value = truncate(value, 240);
                }

                log(Log.INFO, TAG, "HDR " + name + "=" + value);
            }
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Header diagnostic failed", t);
        }
    }

    private boolean extractFormBody(Object body, Map<String, String> out) {
        if (body == null) {
            return false;
        }

        try {
            Class<?> cls = body.getClass();
            if (!"okhttp3.FormBody".equals(cls.getName())) {
                return false;
            }

            Method size = cls.getMethod("size");
            Method name = cls.getMethod("name", int.class);
            Method value = cls.getMethod("value", int.class);

            int n = ((Number) size.invoke(body)).intValue();
            for (int i = 0; i < n; i++) {
                String k = String.valueOf(name.invoke(body, i));
                if (isKnownRequestField(k)) {
                    out.put(k, String.valueOf(value.invoke(body, i)));
                }
            }
            return true;
        } catch (Throwable t) {
            log(Log.WARN, TAG, "FormBody parse failed", t);
            return false;
        }
    }

    private String readRequestBody(Object body, ClassLoader classLoader) {
        if (body == null) {
            return null;
        }

        try {
            try {
                Method isDuplex = body.getClass().getMethod("isDuplex");
                Object duplex = isDuplex.invoke(body);
                if (Boolean.TRUE.equals(duplex)) {
                    log(Log.INFO, TAG, "BODY copy skipped: duplex body");
                    return null;
                }
            } catch (Throwable ignored) {
            }

            try {
                Method isOneShot = body.getClass().getMethod("isOneShot");
                Object oneShot = isOneShot.invoke(body);
                if (Boolean.TRUE.equals(oneShot)) {
                    log(Log.INFO, TAG, "BODY copy skipped: one-shot body");
                    return null;
                }
            } catch (Throwable ignored) {
            }

            Class<?> bufferClass = Class.forName("okio.Buffer", false, classLoader);
            Class<?> sinkClass = Class.forName("okio.BufferedSink", false, classLoader);
            Object buffer = bufferClass.getDeclaredConstructor().newInstance();

            Method writeTo = body.getClass().getMethod("writeTo", sinkClass);
            writeTo.invoke(body, buffer);

            Method readUtf8 = bufferClass.getMethod("readUtf8");
            Object raw = readUtf8.invoke(buffer);
            if (raw == null) {
                return null;
            }

            String text = String.valueOf(raw);
            if (text.length() > 200_000) {
                log(Log.INFO, TAG, "BODY copy too large; only first 200000 chars parsed");
                return text.substring(0, 200_000);
            }
            return text;
        } catch (Throwable t) {
            log(Log.WARN, TAG, "RequestBody copy failed", t);
            return null;
        }
    }

    private void parseKnownFields(String raw, Map<String, String> out) {
        if (raw == null || raw.isEmpty()) {
            return;
        }

        String trimmed = raw.trim();

        if (trimmed.startsWith("{")) {
            try {
                JSONObject obj = new JSONObject(trimmed);
                for (String key : REQUEST_FIELDS) {
                    if (obj.has(key) && !obj.isNull(key)) {
                        out.put(key, String.valueOf(obj.opt(key)));
                    }
                }
            } catch (Throwable ignored) {
            }
        }

        try {
            String[] parts = raw.split("&");
            for (String part : parts) {
                int eq = part.indexOf('=');
                if (eq <= 0) {
                    continue;
                }
                String key = URLDecoder.decode(
                        part.substring(0, eq),
                        StandardCharsets.UTF_8.name()
                );
                if (!isKnownRequestField(key)) {
                    continue;
                }
                String value = URLDecoder.decode(
                        part.substring(eq + 1),
                        StandardCharsets.UTF_8.name()
                );
                out.put(key, value);
            }
        } catch (Throwable ignored) {
        }

        for (String key : REQUEST_FIELDS) {
            if (out.containsKey(key)) {
                continue;
            }
            try {
                Pattern p = Pattern.compile(
                        "name=\\\"" + Pattern.quote(key)
                                + "\\\"[^\\r\\n]*[\\r\\n]+[\\r\\n]+([^\\r\\n]*)"
                );
                Matcher m = p.matcher(raw);
                if (m.find()) {
                    out.put(key, m.group(1));
                }
            } catch (Throwable ignored) {
            }
        }
    }

    private void logEnvironment(Context context) {
        log(Log.INFO, TAG, "========== ENVIRONMENT BEGIN ==========");

        try {
            PackageManager pm = context.getPackageManager();

            PackageInfo self = pm.getPackageInfo(
                    context.getPackageName(),
                    PackageManager.GET_SIGNING_CERTIFICATES
            );

            String installer;
            try {
                installer = pm.getInstallerPackageName(context.getPackageName());
            } catch (Throwable t) {
                installer = "<error>";
            }

            log(Log.INFO, TAG,
                    "APP package=" + context.getPackageName()
                            + " versionName=" + self.versionName
                            + " versionCode=" + getLongVersionCode(self)
                            + " installer=" + installer
                            + " certSha256=" + signingCertSha256(self));

            logPackage(pm, "com.android.vending", "PLAY_STORE");
            logPackage(pm, "com.google.android.gms", "GMS");
            logPackage(pm, "com.google.android.gsf", "GSF");

            log(Log.INFO, TAG,
                    "BUILD manufacturer=" + Build.MANUFACTURER
                            + " brand=" + Build.BRAND
                            + " model=" + Build.MODEL
                            + " device=" + Build.DEVICE
                            + " product=" + Build.PRODUCT);

            log(Log.INFO, TAG,
                    "BUILD2 hardware=" + Build.HARDWARE
                            + " board=" + Build.BOARD
                            + " bootloader=" + Build.BOOTLOADER
                            + " type=" + Build.TYPE
                            + " tags=" + Build.TAGS
                            + " user=" + Build.USER);

            log(Log.INFO, TAG,
                    "BUILD3 id=" + Build.ID
                            + " display=" + Build.DISPLAY
                            + " fingerprint=" + Build.FINGERPRINT);

            log(Log.INFO, TAG,
                    "ANDROID release=" + Build.VERSION.RELEASE
                            + " sdk=" + Build.VERSION.SDK_INT
                            + " securityPatch=" + Build.VERSION.SECURITY_PATCH
                            + " incremental=" + Build.VERSION.INCREMENTAL
                            + " baseOs=" + Build.VERSION.BASE_OS
                            + " previewSdk=" + Build.VERSION.PREVIEW_SDK_INT
                            + " radio=" + safeRadioVersion()
                            + " abis=" + Arrays.toString(Build.SUPPORTED_ABIS));

            logAppRuntime(context, self);
            logEsim(context, pm);
            logSelectedFeatures(pm);
            logIdentifiers(context);
            logTelephony(context);
            logNetworkSnapshot(context, "NET");
            logLocaleAndAgent();
            logSystemProperties();
            logIdentityConsistency();

        } catch (Throwable t) {
            log(Log.WARN, TAG, "Environment diagnostic failed", t);
        }

        log(Log.INFO, TAG, "========== ENVIRONMENT END ==========");
    }

    private void logAppRuntime(Context context, PackageInfo self) {
        try {
            android.content.pm.ApplicationInfo ai =
                    context.getPackageManager().getApplicationInfo(
                            context.getPackageName(), 0);

            log(Log.INFO, TAG,
                    "RUNTIME process=" + safeProcessName()
                            + " pid=" + android.os.Process.myPid()
                            + " uid=" + android.os.Process.myUid()
                            + " targetSdk=" + ai.targetSdkVersion
                            + " minSdk=" + ai.minSdkVersion
                            + " debuggable="
                            + ((ai.flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0)
                            + " sourceDir=" + truncate(ai.sourceDir, 300));

            log(Log.INFO, TAG,
                    "RUNTIME vmName=" + System.getProperty("java.vm.name")
                            + " vmVersion=" + System.getProperty("java.vm.version")
                            + " osArch=" + System.getProperty("os.arch")
                            + " processors=" + Runtime.getRuntime().availableProcessors());

            if (Build.VERSION.SDK_INT >= 30) {
                try {
                    android.content.pm.InstallSourceInfo isi =
                            context.getPackageManager()
                                    .getInstallSourceInfo(context.getPackageName());

                    log(Log.INFO, TAG,
                            "INSTALL initiating="
                                    + isi.getInitiatingPackageName()
                                    + " installing="
                                    + isi.getInstallingPackageName()
                                    + " originating="
                                    + isi.getOriginatingPackageName());
                } catch (Throwable t) {
                    log(Log.INFO, TAG,
                            "INSTALL source=<unavailable:"
                                    + t.getClass().getSimpleName() + ">");
                }
            }
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Runtime diagnostic failed", t);
        }
    }

    private void logNetworkSnapshot(Context context, String prefix) {
        try {
            android.net.ConnectivityManager cm =
                    (android.net.ConnectivityManager)
                            context.getSystemService(Context.CONNECTIVITY_SERVICE);

            if (cm == null) {
                log(Log.INFO, TAG, prefix + " connectivityService=null");
                return;
            }

            android.net.Network network = cm.getActiveNetwork();
            android.net.NetworkCapabilities caps =
                    network == null ? null : cm.getNetworkCapabilities(network);
            android.net.LinkProperties link =
                    network == null ? null : cm.getLinkProperties(network);

            StringBuilder transports = new StringBuilder();
            if (caps != null) {
                if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI)) {
                    transports.append("WIFI,");
                }
                if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR)) {
                    transports.append("CELLULAR,");
                }
                if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) {
                    transports.append("VPN,");
                }
                if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET)) {
                    transports.append("ETHERNET,");
                }
                if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_BLUETOOTH)) {
                    transports.append("BLUETOOTH,");
                }
            }

            String privateDns = "<none>";
            String proxy = "<none>";

            if (link != null) {
                try {
                    String p = link.getPrivateDnsServerName();
                    if (p != null && !p.isEmpty()) {
                        privateDns = p;
                    }
                } catch (Throwable ignored) {
                }

                try {
                    android.net.ProxyInfo pi = link.getHttpProxy();
                    if (pi != null) {
                        proxy = truncate(
                                String.valueOf(pi.getHost()) + ":" + pi.getPort(),
                                200
                        );
                    }
                } catch (Throwable ignored) {
                }
            }

            log(Log.INFO, TAG,
                    prefix
                            + " active=" + (network != null)
                            + " transports=" + transports
                            + " metered=" + cm.isActiveNetworkMetered()
                            + " validated="
                            + (caps != null
                            && caps.hasCapability(
                            android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED))
                            + " internet="
                            + (caps != null
                            && caps.hasCapability(
                            android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET))
                            + " privateDns=" + privateDns
                            + " proxy=" + proxy);
        } catch (Throwable t) {
            log(Log.INFO, TAG,
                    prefix + " <unavailable:"
                            + t.getClass().getSimpleName() + ">");
        }
    }

    private void logIdentityConsistency() {
        try {
            String propManufacturer =
                    readSystemProperty("ro.product.manufacturer");
            String propBrand =
                    readSystemProperty("ro.product.brand");
            String propModel =
                    readSystemProperty("ro.product.model");
            String propDevice =
                    readSystemProperty("ro.product.device");
            String propName =
                    readSystemProperty("ro.product.name");
            String propFingerprint =
                    readSystemProperty("ro.build.fingerprint");

            log(Log.INFO, TAG,
                    "IDENTITY_MATCH manufacturer="
                            + safeEquals(Build.MANUFACTURER, propManufacturer)
                            + " brand=" + safeEquals(Build.BRAND, propBrand)
                            + " model=" + safeEquals(Build.MODEL, propModel)
                            + " device=" + safeEquals(Build.DEVICE, propDevice)
                            + " product=" + safeEquals(Build.PRODUCT, propName)
                            + " fingerprint="
                            + safeEquals(Build.FINGERPRINT, propFingerprint));
        } catch (Throwable t) {
            log(Log.INFO, TAG,
                    "IDENTITY_MATCH <unavailable:"
                            + t.getClass().getSimpleName() + ">");
        }
    }

    private String readSystemProperty(String key) {
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            Method get = sp.getDeclaredMethod("get", String.class, String.class);
            get.setAccessible(true);
            Object value = get.invoke(null, key, "");
            return value == null ? "" : String.valueOf(value);
        } catch (Throwable t) {
            return "";
        }
    }

    private boolean safeEquals(String a, String b) {
        return a == null ? b == null : a.equals(b);
    }

    private String safeProcessName() {
        try {
            if (Build.VERSION.SDK_INT >= 28) {
                return String.valueOf(android.app.Application.getProcessName());
            }
        } catch (Throwable ignored) {
        }
        return "<unavailable>";
    }

    private void logEsim(Context context, PackageManager pm) {
        try {
            boolean feature = pm.hasSystemFeature("android.hardware.telephony.euicc");

            EuiccManager euicc = null;
            try {
                euicc = (EuiccManager) context.getSystemService(Context.EUICC_SERVICE);
            } catch (Throwable ignored) {
            }

            String serviceState;
            if (euicc == null) {
                serviceState = "null";
            } else {
                try {
                    serviceState = "present,isEnabled=" + euicc.isEnabled();
                } catch (Throwable t) {
                    serviceState = "present,isEnabled=<error>";
                }
            }

            log(Log.INFO, TAG,
                    "ESIM euiccFeature=" + feature
                            + " euiccService=" + serviceState);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "eSIM diagnostic failed", t);
        }
    }

    private void logSelectedFeatures(PackageManager pm) {
        String[] features = new String[]{
                "android.hardware.telephony",
                "android.hardware.telephony.gsm",
                "android.hardware.telephony.cdma",
                "android.hardware.telephony.euicc",
                "android.hardware.nfc",
                "android.hardware.nfc.hce",
                "android.hardware.se.omapi.ese",
                "android.hardware.se.omapi.uicc",
                "com.google.android.feature.GOOGLE_BUILD",
                "com.google.android.feature.PIXEL_EXPERIENCE"
        };

        StringBuilder sb = new StringBuilder("FEATURES ");
        for (String f : features) {
            try {
                sb.append(f)
                        .append('=')
                        .append(pm.hasSystemFeature(f))
                        .append(' ');
            } catch (Throwable t) {
                sb.append(f).append("=<error> ");
            }
        }
        log(Log.INFO, TAG, sb.toString().trim());
    }

    private void logIdentifiers(Context context) {
        try {
            String androidId = Settings.Secure.getString(
                    context.getContentResolver(),
                    Settings.Secure.ANDROID_ID
            );
            log(Log.INFO, TAG,
                    "ID androidId=" + sensitiveSummary(androidId));
        } catch (Throwable t) {
            log(Log.INFO, TAG,
                    "ID androidId=<error:" + t.getClass().getSimpleName() + ">");
        }

        MediaDrm drm = null;
        try {
            UUID widevine = UUID.fromString("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed");
            drm = new MediaDrm(widevine);
            byte[] unique = drm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID);
            log(Log.INFO, TAG,
                    "ID widevineDeviceUniqueId=<bytes=" + unique.length
                            + " sha256=" + shortHash(unique) + ">");
        } catch (Throwable t) {
            log(Log.INFO, TAG,
                    "ID widevineDeviceUniqueId=<error:"
                            + t.getClass().getSimpleName() + ">");
        } finally {
            if (drm != null) {
                try {
                    drm.release();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private void logTelephony(Context context) {
        try {
            TelephonyManager tm =
                    (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
            if (tm == null) {
                log(Log.INFO, TAG, "TEL service=null");
                return;
            }

            String networkCountry = safeTelephony(() -> tm.getNetworkCountryIso());
            String simCountry = safeTelephony(() -> tm.getSimCountryIso());
            String networkOperator = safeTelephony(() -> tm.getNetworkOperator());
            String simOperator = safeTelephony(() -> tm.getSimOperator());
            String networkName = safeTelephony(() -> tm.getNetworkOperatorName());
            String simName = safeTelephony(() -> tm.getSimOperatorName());
            String phoneType = safeTelephony(() -> String.valueOf(tm.getPhoneType()));
            String simState = safeTelephony(() -> String.valueOf(tm.getSimState()));

            log(Log.INFO, TAG,
                    "TEL networkCountry=" + networkCountry
                            + " simCountry=" + simCountry
                            + " networkOperator=" + networkOperator
                            + " simOperator=" + simOperator
                            + " networkName=" + truncate(networkName, 80)
                            + " simName=" + truncate(simName, 80)
                            + " phoneType=" + phoneType
                            + " simState=" + simState);
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Telephony diagnostic failed", t);
        }
    }

    private void logLocaleAndAgent() {
        try {
            log(Log.INFO, TAG,
                    "LOCALE languageTag=" + Locale.getDefault().toLanguageTag()
                            + " timezone=" + TimeZone.getDefault().getID()
                            + " http.agent=" + truncate(
                            String.valueOf(System.getProperty("http.agent")),
                            300
                    ));
        } catch (Throwable t) {
            log(Log.WARN, TAG, "Locale diagnostic failed", t);
        }
    }

    private void logSystemProperties() {
        String[] keys = new String[]{
                "ro.product.manufacturer",
                "ro.product.brand",
                "ro.product.model",
                "ro.product.device",
                "ro.product.name",
                "ro.product.system.manufacturer",
                "ro.product.system.brand",
                "ro.product.system.model",
                "ro.product.system.device",
                "ro.product.vendor.manufacturer",
                "ro.product.vendor.brand",
                "ro.product.vendor.model",
                "ro.product.vendor.device",
                "ro.build.fingerprint",
                "ro.system.build.fingerprint",
                "ro.vendor.build.fingerprint",
                "ro.build.type",
                "ro.build.tags",
                "ro.build.version.security_patch",
                "ro.product.first_api_level",
                "ro.boot.verifiedbootstate",
                "ro.boot.flash.locked",
                "ro.boot.vbmeta.device_state",
                "ro.boot.veritymode"
        };

        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            Method get = sp.getDeclaredMethod("get", String.class, String.class);
            get.setAccessible(true);

            for (String key : keys) {
                try {
                    Object value = get.invoke(null, key, "");
                    log(Log.INFO, TAG,
                            "PROP " + key + "=" + truncate(String.valueOf(value), 400));
                } catch (Throwable t) {
                    log(Log.INFO, TAG,
                            "PROP " + key + "=<error:"
                                    + t.getClass().getSimpleName() + ">");
                }
            }
        } catch (Throwable t) {
            log(Log.INFO, TAG,
                    "PROP SystemProperties=<unavailable:"
                            + t.getClass().getSimpleName() + ">");
        }
    }

    private void logPackage(PackageManager pm, String pkg, String label) {
        try {
            PackageInfo pi = pm.getPackageInfo(pkg, 0);
            log(Log.INFO, TAG,
                    label + " package=" + pkg
                            + " versionName=" + pi.versionName
                            + " versionCode=" + getLongVersionCode(pi)
                            + " enabled=" + pm.getApplicationInfo(pkg, 0).enabled);
        } catch (Throwable t) {
            log(Log.INFO, TAG,
                    label + " package=" + pkg
                            + " <unavailable:" + t.getClass().getSimpleName() + ">");
        }
    }

    private long getLongVersionCode(PackageInfo pi) {
        if (Build.VERSION.SDK_INT >= 28) {
            return pi.getLongVersionCode();
        }
        return pi.versionCode;
    }

    private String signingCertSha256(PackageInfo pi) {
        try {
            SigningInfo info = pi.signingInfo;
            if (info == null) {
                return "<none>";
            }

            Signature[] signatures = info.hasMultipleSigners()
                    ? info.getApkContentsSigners()
                    : info.getSigningCertificateHistory();

            if (signatures == null || signatures.length == 0) {
                return "<none>";
            }

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < signatures.length; i++) {
                if (i > 0) {
                    sb.append(',');
                }
                sb.append(fullHash(signatures[i].toByteArray()));
            }
            return sb.toString();
        } catch (Throwable t) {
            return "<error:" + t.getClass().getSimpleName() + ">";
        }
    }

    private Object invokeNoArgs(Object target, String method) throws Exception {
        if (target == null) {
            return null;
        }
        Method m = target.getClass().getMethod(method);
        m.setAccessible(true);
        return m.invoke(target);
    }

    private String safeStringInvoke(Object target, String method) {
        try {
            Object result = invokeNoArgs(target, method);
            return String.valueOf(result);
        } catch (Throwable t) {
            return "<unavailable>";
        }
    }

    private String stringValue(Object obj) {
        return obj == null ? "null" : String.valueOf(obj);
    }

    private boolean isKnownRequestField(String key) {
        if (key == null) {
            return false;
        }
        for (String f : REQUEST_FIELDS) {
            if (f.equals(key)) {
                return true;
            }
        }
        return false;
    }

    private String summarizeRequestValue(String key, String value) {
        if (value == null) {
            return "null";
        }

        if ("phone".equals(key)) {
            return "<redacted len=" + value.length() + ">";
        }

        if ("device_id".equals(key)
                || "phone_mediadrm_id".equals(key)) {
            return sensitiveSummary(value);
        }

        if ("captcha_token".equals(key)
                || "hcaptcha_token".equals(key)) {
            return "<present len=" + value.length()
                    + " sha256=" + shortHash(value) + ">";
        }

        return truncate(value, 300);
    }

    private String sensitiveSummary(String value) {
        if (value == null) {
            return "null";
        }
        return "<len=" + value.length()
                + " sha256=" + shortHash(value) + ">";
    }

    private String safeRadioVersion() {
        try {
            return String.valueOf(Build.getRadioVersion());
        } catch (Throwable t) {
            return "<unavailable>";
        }
    }

    private interface StringSupplier {
        String get() throws Exception;
    }

    private String safeTelephony(StringSupplier supplier) {
        try {
            String s = supplier.get();
            return s == null ? "null" : s;
        } catch (Throwable t) {
            return "<error:" + t.getClass().getSimpleName() + ">";
        }
    }

    private String stripQuery(String url) {
        if (url == null) {
            return "null";
        }
        int q = url.indexOf('?');
        return q >= 0 ? url.substring(0, q) : url;
    }

    private String truncate(String s, int max) {
        if (s == null) {
            return "null";
        }
        if (s.length() <= max) {
            return s;
        }
        return s.substring(0, max) + "...<truncated>";
    }

    private String shortHash(String text) {
        if (text == null) {
            return "null";
        }
        return shortHash(text.getBytes(StandardCharsets.UTF_8));
    }

    private String shortHash(byte[] data) {
        String full = fullHash(data);
        if (full.startsWith("<")) {
            return full;
        }
        return full.length() <= 16 ? full : full.substring(0, 16);
    }

    private String fullHash(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(data);
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format(Locale.ROOT, "%02x", b & 0xff));
            }
            return sb.toString();
        } catch (Throwable t) {
            return "<hash-error>";
        }
    }
}
