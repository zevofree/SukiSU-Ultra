package com.sukisu.ultra.ui.theme

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.updateTransition
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.paint
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.zIndex
import coil.compose.AsyncImagePainter
import coil.compose.rememberAsyncImagePainter
import androidx.compose.foundation.background
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.unit.dp
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import androidx.core.content.edit
import androidx.core.net.toUri
import com.sukisu.ultra.ui.util.BackgroundTransformation
import com.sukisu.ultra.ui.util.saveTransformedBackground

/**
 * 主题配置对象，管理应用的主题相关状态
 */
object ThemeConfig {
    var customBackgroundUri by mutableStateOf<Uri?>(null)
    var forceDarkMode by mutableStateOf<Boolean?>(null)
    var currentTheme by mutableStateOf<ThemeColors>(ThemeColors.Default)
    var useDynamicColor by mutableStateOf(false)
    var backgroundImageLoaded by mutableStateOf(false)
    var needsResetOnThemeChange by mutableStateOf(false)
    var isThemeChanging by mutableStateOf(false)
    var preventBackgroundRefresh by mutableStateOf(false)

    private var lastDarkModeState: Boolean? = null
    fun detectThemeChange(currentDarkMode: Boolean): Boolean {
        val isChanged = lastDarkModeState != null && lastDarkModeState != currentDarkMode
        lastDarkModeState = currentDarkMode
        return isChanged
    }

    fun resetBackgroundState() {
        if (!preventBackgroundRefresh) {
            backgroundImageLoaded = false
        }
        isThemeChanging = true
    }
}

/**
 * 应用主题
 */
@Composable
fun KernelSUTheme(
    darkTheme: Boolean = when(ThemeConfig.forceDarkMode) {
        true -> true
        false -> false
        null -> isSystemInDarkTheme()
    },
    dynamicColor: Boolean = ThemeConfig.useDynamicColor,
    content: @Composable () -> Unit
) {
    val context = LocalContext.current
    val systemIsDark = isSystemInDarkTheme()

    // 检测系统主题变化并保存状态
    val themeChanged = ThemeConfig.detectThemeChange(systemIsDark)
    LaunchedEffect(systemIsDark, themeChanged) {
        if (ThemeConfig.forceDarkMode == null && themeChanged) {
            Log.d("ThemeSystem", "系统主题变化检测: 从 ${!systemIsDark} 变为 $systemIsDark")
            ThemeConfig.resetBackgroundState()

            if (!ThemeConfig.preventBackgroundRefresh) {
                context.loadCustomBackground()
            }

            CardConfig.apply {
                load(context)
                if (!isCustomAlphaSet) {
                    cardAlpha = if (systemIsDark) 0.50f else 1f
                }
                save(context)
            }
        }
    }

    // 初始加载配置
    LaunchedEffect(Unit) {
        context.loadThemeMode()
        context.loadThemeColors()
        context.loadDynamicColorState()
        CardConfig.load(context)

        if (!ThemeConfig.backgroundImageLoaded && !ThemeConfig.preventBackgroundRefresh) {
            context.loadCustomBackground()
            ThemeConfig.backgroundImageLoaded = false
        }

        ThemeConfig.preventBackgroundRefresh = context.getSharedPreferences("theme_prefs", Context.MODE_PRIVATE)
            .getBoolean("prevent_background_refresh", true)
    }

    // 创建颜色方案
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            if (darkTheme) createDynamicDarkColorScheme(context) else createDynamicLightColorScheme(context)
        }
        darkTheme -> createDarkColorScheme()
        else -> createLightColorScheme()
    }

    // 根据暗色模式和自定义背景调整卡片配置
    val isDarkModeWithCustomBackground = darkTheme && ThemeConfig.customBackgroundUri != null
    if (darkTheme && !dynamicColor) {
        CardConfig.setDarkModeDefaults()
    }
    CardConfig.updateShadowEnabled(!isDarkModeWithCustomBackground)

    val backgroundUri = rememberSaveable { mutableStateOf(ThemeConfig.customBackgroundUri) }

    LaunchedEffect(ThemeConfig.customBackgroundUri) {
        backgroundUri.value = ThemeConfig.customBackgroundUri
    }

    val bgImagePainter = backgroundUri.value?.let {
        rememberAsyncImagePainter(
            model = it,
            onError = {
                Log.e("ThemeSystem", "背景图加载失败: ${it.result.throwable.message}")
                ThemeConfig.customBackgroundUri = null
                context.saveCustomBackground(null)
            },
            onSuccess = {
                Log.d("ThemeSystem", "背景图加载成功")
                ThemeConfig.backgroundImageLoaded = true
                ThemeConfig.isThemeChanging = false

                ThemeConfig.preventBackgroundRefresh = true
                context.getSharedPreferences("theme_prefs", Context.MODE_PRIVATE)
                    .edit { putBoolean("prevent_background_refresh", true) }
            }
        )
    }

    val transition = updateTransition(
        targetState = ThemeConfig.backgroundImageLoaded,
        label = "bgTransition"
    )
    val bgAlpha by transition.animateFloat(
        label = "bgAlpha",
        transitionSpec = {
            spring(
                dampingRatio = 0.8f,
                stiffness = 300f
            )
        }
    ) { loaded -> if (loaded) 1f else 0f }

    DisposableEffect(systemIsDark) {
        onDispose {
            if (ThemeConfig.isThemeChanging) {
                ThemeConfig.isThemeChanging = false
            }
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography
    ) {
        Box(modifier = Modifier.fillMaxSize()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .zIndex(-2f)
                    .background(if (darkTheme) Color.Black else Color.White)
            )

            // 自定义背景层
            backgroundUri.value?.let { uri ->
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .zIndex(-1f)
                        .alpha(bgAlpha)
                ) {
                    // 背景图片
                    bgImagePainter?.let { painter ->
                        Box(
                            modifier = Modifier
                                .fillMaxSize()
                                .paint(
                                    painter = painter,
                                    contentScale = ContentScale.Crop
                                )
                                .graphicsLayer {
                                    alpha = (painter.state as? AsyncImagePainter.State.Success)?.let { 1f } ?: 0f
                                }
                        )
                    }

                    // 亮度调节层
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(
                                if (darkTheme) Color.Black.copy(alpha = 0.6f)
                                else Color.White.copy(alpha = 0.1f)
                            )
                    )

                    // 边缘渐变遮罩
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(
                                Brush.radialGradient(
                                    colors = listOf(
                                        Color.Transparent,
                                        if (darkTheme) Color.Black.copy(alpha = 0.5f)
                                        else Color.Black.copy(alpha = 0.2f)
                                    ),
                                    radius = 1200f
                                )
                            )
                    )
                }
            }

            // 内容层
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .zIndex(1f)
            ) {
                content()
            }
        }
    }
}

/**
 * 创建动态深色颜色方案
 */
@RequiresApi(Build.VERSION_CODES.S)
@Composable
private fun createDynamicDarkColorScheme(context: Context) =
    dynamicDarkColorScheme(context).copy(
        background = Color.Transparent,
        surface = Color.Transparent,
        onBackground = Color.White,
        onSurface = Color.White
    )

/**
 * 创建动态浅色颜色方案
 */
@RequiresApi(Build.VERSION_CODES.S)
@Composable
private fun createDynamicLightColorScheme(context: Context) =
    dynamicLightColorScheme(context).copy(
        background = Color.Transparent,
        surface = Color.Transparent
    )

/**
 * 创建深色颜色方案
 */
@Composable
private fun createDarkColorScheme() = darkColorScheme(
    primary = ThemeConfig.currentTheme.Primary.copy(alpha = 0.8f),
    onPrimary = Color.White,
    primaryContainer = ThemeConfig.currentTheme.PrimaryContainer.copy(alpha = 0.15f),
    onPrimaryContainer = Color.White,
    secondary = ThemeConfig.currentTheme.Secondary.copy(alpha = 0.8f),
    onSecondary = Color.White,
    secondaryContainer = ThemeConfig.currentTheme.SecondaryContainer.copy(alpha = 0.15f),
    onSecondaryContainer = Color.White,
    tertiary = ThemeConfig.currentTheme.Tertiary.copy(alpha = 0.8f),
    onTertiary = Color.White,
    tertiaryContainer = ThemeConfig.currentTheme.TertiaryContainer.copy(alpha = 0.15f),
    onTertiaryContainer = Color.White,
    background = Color.Transparent,
    surface = Color.Transparent,
    onBackground = Color.White,
    onSurface = Color.White,
    surfaceVariant = Color(0xFF2F2F2F),
    onSurfaceVariant = Color.White.copy(alpha = 0.7f),
    outline = Color.White.copy(alpha = 0.12f),
    outlineVariant = Color.White.copy(alpha = 0.12f),
    error = ThemeConfig.currentTheme.Error,
    onError = ThemeConfig.currentTheme.OnError,
    errorContainer = ThemeConfig.currentTheme.ErrorContainer.copy(alpha = 0.15f),
    onErrorContainer = Color.White
)

/**
 * 创建浅色颜色方案
 */
@Composable
private fun createLightColorScheme() = lightColorScheme(
    primary = ThemeConfig.currentTheme.Primary,
    onPrimary = ThemeConfig.currentTheme.OnPrimary,
    primaryContainer = ThemeConfig.currentTheme.PrimaryContainer,
    onPrimaryContainer = ThemeConfig.currentTheme.OnPrimaryContainer,
    secondary = ThemeConfig.currentTheme.Secondary,
    onSecondary = ThemeConfig.currentTheme.OnSecondary,
    secondaryContainer = ThemeConfig.currentTheme.SecondaryContainer,
    onSecondaryContainer = ThemeConfig.currentTheme.OnSecondaryContainer,
    tertiary = ThemeConfig.currentTheme.Tertiary,
    onTertiary = ThemeConfig.currentTheme.OnTertiary,
    tertiaryContainer = ThemeConfig.currentTheme.TertiaryContainer,
    onTertiaryContainer = ThemeConfig.currentTheme.OnTertiaryContainer,
    background = Color.Transparent,
    surface = Color.Transparent,
    onBackground = Color.Black.copy(alpha = 0.87f),
    onSurface = Color.Black.copy(alpha = 0.87f),
    surfaceVariant = Color(0xFFF5F5F5),
    onSurfaceVariant = Color.Black.copy(alpha = 0.78f),
    outline = Color.Black.copy(alpha = 0.12f),
    outlineVariant = Color.Black.copy(alpha = 0.12f),
    error = ThemeConfig.currentTheme.Error,
    onError = ThemeConfig.currentTheme.OnError,
    errorContainer = ThemeConfig.currentTheme.ErrorContainer,
    onErrorContainer = ThemeConfig.currentTheme.OnErrorContainer
)

/**
 * 复制图片到应用内部存储并提升持久性
 */
private fun Context.copyImageToInternalStorage(uri: Uri): Uri? {
    return try {
        val contentResolver: ContentResolver = contentResolver
        val inputStream: InputStream = contentResolver.openInputStream(uri) ?: return null

        val fileName = "custom_background.jpg"
        val file = File(filesDir, fileName)

        val backupFile = File(filesDir, "${fileName}.backup")
        val outputStream = FileOutputStream(backupFile)
        val buffer = ByteArray(4 * 1024)
        var read: Int

        while (inputStream.read(buffer).also { read = it } != -1) {
            outputStream.write(buffer, 0, read)
        }

        outputStream.flush()
        outputStream.close()
        inputStream.close()

        if (file.exists()) {
            file.delete()
        }
        backupFile.renameTo(file)

        Uri.fromFile(file)
    } catch (e: Exception) {
        Log.e("ImageCopy", "复制图片失败: ${e.message}")
        null
    }
}

/**
 * 保存并应用自定义背景
 */
fun Context.saveAndApplyCustomBackground(uri: Uri, transformation: BackgroundTransformation? = null) {
    val finalUri = if (transformation != null) {
        saveTransformedBackground(uri, transformation)
    } else {
        copyImageToInternalStorage(uri)
    }

    // 保存到配置文件
    getSharedPreferences("theme_prefs", Context.MODE_PRIVATE)
        .edit {
            putString("custom_background", finalUri?.toString())
            // 设置阻止刷新标志为false，允许新设置的背景加载一次
            putBoolean("prevent_background_refresh", false)
        }

    ThemeConfig.customBackgroundUri = finalUri
    ThemeConfig.backgroundImageLoaded = false
    ThemeConfig.preventBackgroundRefresh = false
    CardConfig.cardElevation = 0.dp
    CardConfig.isCustomBackgroundEnabled = true
}

/**
 * 保存自定义背景
 */
fun Context.saveCustomBackground(uri: Uri?) {
    val newUri = uri?.let { copyImageToInternalStorage(it) }

    // 保存到配置文件
    getSharedPreferences("theme_prefs", Context.MODE_PRIVATE)
        .edit {
            putString("custom_background", newUri?.toString())
            if (uri == null) {
                // 如果清除背景，也重置阻止刷新标志
                putBoolean("prevent_background_refresh", false)
            } else {
                // 设置阻止刷新标志为false，允许新设置的背景加载一次
                putBoolean("prevent_background_refresh", false)
            }
        }

    ThemeConfig.customBackgroundUri = newUri
    ThemeConfig.backgroundImageLoaded = false
    ThemeConfig.preventBackgroundRefresh = false

    if (uri != null) {
        CardConfig.cardElevation = 0.dp
        CardConfig.isCustomBackgroundEnabled = true
    }
}

/**
 * 加载自定义背景
 */
fun Context.loadCustomBackground() {
    val uriString = getSharedPreferences("theme_prefs", Context.MODE_PRIVATE)
        .getString("custom_background", null)

    val newUri = uriString?.toUri()
    val preventRefresh = getSharedPreferences("theme_prefs", Context.MODE_PRIVATE)
        .getBoolean("prevent_background_refresh", false)

    ThemeConfig.preventBackgroundRefresh = preventRefresh

    if (!preventRefresh || ThemeConfig.customBackgroundUri?.toString() != newUri?.toString()) {
        Log.d("ThemeSystem", "加载自定义背景: $uriString, 阻止刷新: $preventRefresh")
        ThemeConfig.customBackgroundUri = newUri
        ThemeConfig.backgroundImageLoaded = false
    }
}

/**
 * 保存主题模式
 */
fun Context.saveThemeMode(forceDark: Boolean?) {
    getSharedPreferences("theme_prefs", Context.MODE_PRIVATE)
        .edit {
            putString(
                "theme_mode", when (forceDark) {
                    true -> "dark"
                    false -> "light"
                    null -> "system"
                }
            )
        }
    ThemeConfig.forceDarkMode = forceDark
    ThemeConfig.needsResetOnThemeChange = forceDark == null
}

/**
 * 加载主题模式
 */
fun Context.loadThemeMode() {
    val mode = getSharedPreferences("theme_prefs", Context.MODE_PRIVATE)
        .getString("theme_mode", "system")

    ThemeConfig.forceDarkMode = when(mode) {
        "dark" -> true
        "light" -> false
        else -> null
    }
    ThemeConfig.needsResetOnThemeChange = ThemeConfig.forceDarkMode == null
}

/**
 * 保存主题颜色
 */
fun Context.saveThemeColors(themeName: String) {
    getSharedPreferences("theme_prefs", Context.MODE_PRIVATE)
        .edit {
            putString("theme_colors", themeName)
        }

    ThemeConfig.currentTheme = ThemeColors.fromName(themeName)
}

/**
 * 加载主题颜色
 */
fun Context.loadThemeColors() {
    val themeName = getSharedPreferences("theme_prefs", Context.MODE_PRIVATE)
        .getString("theme_colors", "default")

    ThemeConfig.currentTheme = ThemeColors.fromName(themeName ?: "default")
}

/**
 * 保存动态颜色状态
 */
fun Context.saveDynamicColorState(enabled: Boolean) {
    getSharedPreferences("theme_prefs", Context.MODE_PRIVATE)
        .edit {
            putBoolean("use_dynamic_color", enabled)
        }
    ThemeConfig.useDynamicColor = enabled
}

/**
 * 加载动态颜色状态
 */
fun Context.loadDynamicColorState() {
    val enabled = getSharedPreferences("theme_prefs", Context.MODE_PRIVATE)
        .getBoolean("use_dynamic_color", true)

    ThemeConfig.useDynamicColor = enabled
}