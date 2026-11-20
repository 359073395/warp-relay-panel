-keep class hev.htproxy.** { *; }
-keepclassmembers class com.starbridge.panel.MainActivity$WebBridge {
    @android.webkit.JavascriptInterface <methods>;
}
