package com.example;

import android.app.PendingIntent;
import android.content.ClipboardManager;
import android.database.sqlite.SQLiteDatabase;
import android.net.http.SslError;
import android.os.Environment;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import java.security.MessageDigest;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Sample {
    void crypto() throws Exception {
        SecretKeySpec key = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
        IvParameterSpec iv = new IvParameterSpec("fedcba9876543210".getBytes());
        MessageDigest md = MessageDigest.getInstance("MD5");
    }
    void storage(SQLiteDatabase db, String user, ClipboardManager cm) {
        java.io.File f = Environment.getExternalStorageDirectory();
        db.rawQuery("SELECT * FROM users WHERE name = '" + user, null);
        cm.setPrimaryClip(null);
        WebView.setWebContentsDebuggingEnabled(true);
        PendingIntent.getActivity(null, 0, null, PendingIntent.FLAG_MUTABLE);
    }
    class Client extends WebViewClient {
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            handler.proceed();
        }
    }
}
