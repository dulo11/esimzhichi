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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

public class UsimsEsimFix extends XposedModule {

    private static final String TAG = "USIMSeSIMFix";
    private static final String TARGET_PACKAGE = "com.wonet.usims";
    private static final String ROUTE_LOGIN = "routeLoginCall";
    private static final AtomicBoolean ENV_LOGGED = new AtomicBoolean(false);

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

        hookUsimsEsimCheck(classLoader);
        hookOkHttpRouteLogin(classLoader);

        log(Log.INFO, TAG, "v1.2.0 loaded for " + TARGET_PACKAGE);
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

                        if (context != null && ENV_LOGGED.compareAndSet(false, true)) {
                            logEnvironment(context);
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
                        try {
                            Object urlObj = chain.getArgs().size() > 0
                                    ? chain.getArgs().get(0) : null;
                            Object mapObj = chain.getArgs().size() > 1
                                    ? chain.getArgs().get(1) : null;

                            String url = String.valueOf(urlObj);
                            if (url.contains(ROUTE_LOGIN)) {
                                log(Log.INFO, TAG,
                                        "========== routeLoginCall DIRECT BEGIN ==========");
                                log(Log.INFO, TAG,
                                        "DIRECT method=" + hooked.toGenericString());
                                log(Log.INFO, TAG,
                                        "DIRECT url=" + stripQuery(url));

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

                                log(Log.INFO, TAG,
                                        "========== routeLoginCall DIRECT END ==========");
                            }
                        } catch (Throwable t) {
                            log(Log.WARN, TAG,
                                    "Direct routeLoginCall diagnostic failed", t);
                        }

                        return chain.proceed();
                    });

            log(Log.INFO, TAG,
                    "Hook installed: Be.d.c(String, HashMap, *, boolean)");
        } catch (Throwable t) {
            log(Log.ERROR, TAG,
                    "Failed to install direct USIMS network hook", t);
        }
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
                || "phone_app_version".equals(key)
                || "app_id".equals(key)) {
            return truncate(value, 300);
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

            logEsim(context, pm);
            logSelectedFeatures(pm);
            logIdentifiers(context);
            logTelephony(context);
            logLocaleAndAgent();
            logSystemProperties();

        } catch (Throwable t) {
            log(Log.WARN, TAG, "Environment diagnostic failed", t);
        }

        log(Log.INFO, TAG, "========== ENVIRONMENT END ==========");
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
