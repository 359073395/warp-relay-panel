package com.starbridge.panel

import android.content.Context

object CoreHolder {
    @Volatile
    private var instance: CoreManager? = null

    fun get(context: Context): CoreManager {
        return instance ?: synchronized(this) {
            instance ?: CoreManager(context.applicationContext).also { instance = it }
        }
    }
}
