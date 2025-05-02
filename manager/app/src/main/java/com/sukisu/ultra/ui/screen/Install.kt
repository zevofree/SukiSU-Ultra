package com.sukisu.ultra.ui.screen

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.StringRes
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.LocalIndication
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AutoFixHigh
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.RadioButtonDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.TopAppBarScrollBehavior
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.maxkeppeker.sheets.core.models.base.Header
import com.maxkeppeker.sheets.core.models.base.rememberUseCaseState
import com.maxkeppeler.sheets.list.ListDialog
import com.maxkeppeler.sheets.list.models.ListOption
import com.maxkeppeler.sheets.list.models.ListSelection
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.generated.destinations.FlashScreenDestination
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.ramcosta.composedestinations.navigation.EmptyDestinationsNavigator
import com.sukisu.ultra.R
import com.sukisu.ultra.flash.HorizonKernelFlashProgress
import com.sukisu.ultra.flash.HorizonKernelState
import com.sukisu.ultra.flash.HorizonKernelWorker
import com.sukisu.ultra.ui.component.DialogHandle
import com.sukisu.ultra.ui.component.SlotSelectionDialog
import com.sukisu.ultra.ui.component.rememberConfirmDialog
import com.sukisu.ultra.ui.component.rememberCustomDialog
import com.sukisu.ultra.ui.theme.CardConfig.cardAlpha
import com.sukisu.ultra.ui.theme.CardConfig.cardElevation
import com.sukisu.ultra.ui.theme.getCardColors
import com.sukisu.ultra.ui.util.LkmSelection
import com.sukisu.ultra.ui.util.getCurrentKmi
import com.sukisu.ultra.ui.util.getSupportedKmis
import com.sukisu.ultra.ui.util.isAbDevice
import com.sukisu.ultra.ui.util.isInitBoot
import com.sukisu.ultra.ui.util.rootAvailable
import com.sukisu.ultra.getKernelVersion

/**
 * @author weishu
 * @date 2024/3/12.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Destination<RootGraph>
@Composable
fun InstallScreen(navigator: DestinationsNavigator) {
    var installMethod by remember { mutableStateOf<InstallMethod?>(null) }
    var lkmSelection by remember { mutableStateOf<LkmSelection>(LkmSelection.KmiNone) }
    val context = LocalContext.current
    var showRebootDialog by remember { mutableStateOf(false) }
    var showSlotSelectionDialog by remember { mutableStateOf(false) }
    var tempKernelUri by remember { mutableStateOf<Uri?>(null) }
    val horizonKernelState = remember { HorizonKernelState() }
    val flashState by horizonKernelState.state.collectAsState()
    val summary = stringResource(R.string.horizon_kernel_summary)
    val kernelVersion = getKernelVersion()
    val isGKI = kernelVersion.isGKI()

    val onFlashComplete = {
        showRebootDialog = true
    }

    if (showRebootDialog) {
        RebootDialog(
            show = true,
            onDismiss = { showRebootDialog = false },
            onConfirm = {
                showRebootDialog = false
                try {
                    val process = Runtime.getRuntime().exec("su")
                    process.outputStream.bufferedWriter().use { writer ->
                        writer.write("svc power reboot\n")
                        writer.write("exit\n")
                    }
                } catch (_: Exception) {
                    Toast.makeText(context, R.string.failed_reboot, Toast.LENGTH_SHORT).show()
                }
            }
        )
    }

    val onInstall = {
        installMethod?.let { method ->
            when (method) {
                is InstallMethod.HorizonKernel -> {
                    method.uri?.let { uri ->
                        val worker = HorizonKernelWorker(
                            context = context,
                            state = horizonKernelState,
                            slot = method.slot
                        )
                        worker.uri = uri
                        worker.setOnFlashCompleteListener(onFlashComplete)
                        worker.start()
                    }
                }
                else -> {
                    val flashIt = FlashIt.FlashBoot(
                        boot = if (method is InstallMethod.SelectFile) method.uri else null,
                        lkm = lkmSelection,
                        ota = method is InstallMethod.DirectInstallToInactiveSlot
                    )
                    navigator.navigate(FlashScreenDestination(flashIt))
                }
            }
        }
        Unit
    }

    // 槽位选择
    SlotSelectionDialog(
        show = showSlotSelectionDialog,
        onDismiss = { showSlotSelectionDialog = false },
        onSlotSelected = { slot ->
            showSlotSelectionDialog = false
            val horizonMethod = InstallMethod.HorizonKernel(
                uri = tempKernelUri,
                slot = slot,
                summary = summary
            )
            installMethod = horizonMethod
        }
    )

    val currentKmi by produceState(initialValue = "") {
        value = getCurrentKmi()
    }

    val selectKmiDialog = rememberSelectKmiDialog { kmi ->
        kmi?.let {
            lkmSelection = LkmSelection.KmiString(it)
            onInstall()
        }
    }

    val onClickNext = {
        if (lkmSelection == LkmSelection.KmiNone && currentKmi.isBlank()) {
            selectKmiDialog.show()
        } else {
            onInstall()
        }
    }

    val selectLkmLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        if (it.resultCode == Activity.RESULT_OK) {
            it.data?.data?.let { uri ->
                lkmSelection = LkmSelection.LkmUri(uri)
            }
        }
    }

    val onLkmUpload = {
        selectLkmLauncher.launch(Intent(Intent.ACTION_GET_CONTENT).apply {
            type = "application/octet-stream"
        })
    }

    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())

    Scaffold(
        topBar = {
            TopBar(
                onBack = { navigator.popBackStack() },
                onLkmUpload = onLkmUpload,
                scrollBehavior = scrollBehavior
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal
        )
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .padding(innerPadding)
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .verticalScroll(rememberScrollState())
                .padding(top = 12.dp)
        ) {
            SelectInstallMethod(
                isGKI = isGKI,
                onSelected = { method ->
                    if (method is InstallMethod.HorizonKernel && method.uri != null && method.slot == null) {
                        tempKernelUri = method.uri
                        showSlotSelectionDialog = true
                    } else {
                        installMethod = method
                    }
                    horizonKernelState.reset()
                }
            )

            AnimatedVisibility(
                visible = flashState.isFlashing && installMethod is InstallMethod.HorizonKernel,
                enter = fadeIn() + expandVertically(),
                exit = fadeOut() + shrinkVertically()
            ) {
                HorizonKernelFlashProgress(flashState)
            }

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
            ) {
                (lkmSelection as? LkmSelection.LkmUri)?.let {
                    ElevatedCard(
                        colors = getCardColors(MaterialTheme.colorScheme.surfaceVariant),
                        elevation = CardDefaults.cardElevation(defaultElevation = cardElevation),
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 12.dp)
                            .clip(MaterialTheme.shapes.medium)
                            .shadow(
                                elevation = cardElevation,
                                shape = MaterialTheme.shapes.medium,
                                spotColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)
                            )
                    ) {
                        Text(
                            text = stringResource(
                                id = R.string.selected_lkm,
                                it.uri.lastPathSegment ?: "(file)"
                            ),
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.padding(16.dp)
                        )
                    }
                }

                (installMethod as? InstallMethod.HorizonKernel)?.let { method ->
                    if (method.slot != null) {
                        ElevatedCard(
                            colors = getCardColors(MaterialTheme.colorScheme.surfaceVariant),
                            elevation = CardDefaults.cardElevation(defaultElevation = cardElevation),
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(bottom = 12.dp)
                                .clip(MaterialTheme.shapes.medium)
                                .shadow(
                                    elevation = cardElevation,
                                    shape = MaterialTheme.shapes.medium,
                                    spotColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)
                                )
                        ) {
                            Text(
                                text = stringResource(
                                    id = R.string.selected_slot,
                                    if (method.slot == "a") stringResource(id = R.string.slot_a)
                                    else stringResource(id = R.string.slot_b)
                                ),
                                style = MaterialTheme.typography.bodyMedium,
                                modifier = Modifier.padding(16.dp)
                            )
                        }
                    }
                }

                Button(
                    modifier = Modifier.fillMaxWidth(),
                    enabled = installMethod != null && !flashState.isFlashing,
                    onClick = onClickNext,
                    shape = MaterialTheme.shapes.medium,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.primary,
                        contentColor = MaterialTheme.colorScheme.onPrimary,
                        disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f),
                        disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                    )
                ) {
                    Text(
                        stringResource(id = R.string.install_next),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
            }
        }
    }
}

@Composable
private fun RebootDialog(
    show: Boolean,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit
) {
    if (show) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(stringResource(id = R.string.reboot_complete_title)) },
            text = { Text(stringResource(id = R.string.reboot_complete_msg)) },
            confirmButton = {
                TextButton(onClick = onConfirm) {
                    Text(stringResource(id = R.string.yes))
                }
            },
            dismissButton = {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(id = R.string.no))
                }
            }
        )
    }
}

sealed class InstallMethod {
    data class SelectFile(
        val uri: Uri? = null,
        @StringRes override val label: Int = R.string.select_file,
        override val summary: String?
    ) : InstallMethod()

    data object DirectInstall : InstallMethod() {
        override val label: Int
            get() = R.string.direct_install
    }

    data object DirectInstallToInactiveSlot : InstallMethod() {
        override val label: Int
            get() = R.string.install_inactive_slot
    }

    data class HorizonKernel(
        val uri: Uri? = null,
        val slot: String? = null,
        @StringRes override val label: Int = R.string.horizon_kernel,
        override val summary: String? = null
    ) : InstallMethod()

    abstract val label: Int
    open val summary: String? = null
}

@Composable
private fun SelectInstallMethod(
    isGKI: Boolean = false,
    onSelected: (InstallMethod) -> Unit = {}
) {
    val rootAvailable = rootAvailable()
    val isAbDevice = isAbDevice()
    val horizonKernelSummary = stringResource(R.string.horizon_kernel_summary)
    val selectFileTip = stringResource(
        id = R.string.select_file_tip,
        if (isInitBoot()) "init_boot" else "boot"
    )

    val radioOptions = mutableListOf<InstallMethod>(
        InstallMethod.SelectFile(summary = selectFileTip)
    )

    if (rootAvailable) {
        radioOptions.add(InstallMethod.DirectInstall)
        if (isAbDevice) {
            radioOptions.add(InstallMethod.DirectInstallToInactiveSlot)
        }
        radioOptions.add(InstallMethod.HorizonKernel(summary = horizonKernelSummary))
    }

    var selectedOption by remember { mutableStateOf<InstallMethod?>(null) }
    var currentSelectingMethod by remember { mutableStateOf<InstallMethod?>(null) }

    val selectImageLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        if (it.resultCode == Activity.RESULT_OK) {
            it.data?.data?.let { uri ->
                val option = when (currentSelectingMethod) {
                    is InstallMethod.SelectFile -> InstallMethod.SelectFile(
                        uri,
                        summary = selectFileTip
                    )

                    is InstallMethod.HorizonKernel -> InstallMethod.HorizonKernel(
                        uri,
                        summary = horizonKernelSummary
                    )

                    else -> null
                }
                option?.let {
                    selectedOption = it
                    onSelected(it)
                }
            }
        }
    }

    val confirmDialog = rememberConfirmDialog(
        onConfirm = {
            selectedOption = InstallMethod.DirectInstallToInactiveSlot
            onSelected(InstallMethod.DirectInstallToInactiveSlot)
        },
        onDismiss = null
    )

    val dialogTitle = stringResource(id = android.R.string.dialog_alert_title)
    val dialogContent = stringResource(id = R.string.install_inactive_slot_warning)

    val onClick = { option: InstallMethod ->
        currentSelectingMethod = option
        when (option) {
            is InstallMethod.SelectFile, is InstallMethod.HorizonKernel -> {
                selectImageLauncher.launch(Intent(Intent.ACTION_GET_CONTENT).apply {
                    type = "application/*"
                    putExtra(
                        Intent.EXTRA_MIME_TYPES,
                        arrayOf("application/octet-stream", "application/zip")
                    )
                })
            }

            is InstallMethod.DirectInstall -> {
                selectedOption = option
                onSelected(option)
            }

            is InstallMethod.DirectInstallToInactiveSlot -> {
                confirmDialog.showConfirm(dialogTitle, dialogContent)
            }
        }
    }

    var LKMExpanded by remember { mutableStateOf(false) }
    var GKIExpanded by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.padding(horizontal = 16.dp)
    ) {
        // LKM 安装
        if (isGKI && rootAvailable) {
            ElevatedCard(
                colors = getCardColors(MaterialTheme.colorScheme.surfaceVariant),
                elevation = CardDefaults.cardElevation(defaultElevation = cardElevation),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 12.dp)
                    .clip(MaterialTheme.shapes.large)
                    .shadow(
                        elevation = cardElevation,
                        shape = MaterialTheme.shapes.large,
                        spotColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)
                    )
            ) {
                ListItem(
                    leadingContent = {
                        Icon(
                            Icons.Filled.AutoFixHigh,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary
                        )
                    },
                    headlineContent = {
                        Text(
                            stringResource(R.string.Lkm_install_methods),
                            style = MaterialTheme.typography.titleMedium
                        )
                    },
                    modifier = Modifier.clickable {
                        LKMExpanded = !LKMExpanded
                    }
                )

                AnimatedVisibility(
                    visible = LKMExpanded,
                    enter = fadeIn() + expandVertically(),
                    exit = shrinkVertically() + fadeOut()
                ) {
                    Column(
                        modifier = Modifier.padding(
                            start = 16.dp,
                            end = 16.dp,
                            bottom = 16.dp
                        )
                    ) {
                        radioOptions.take(3).forEach { option ->
                            val interactionSource = remember { MutableInteractionSource() }
                            Surface(
                                color = if (option.javaClass == selectedOption?.javaClass)
                                    MaterialTheme.colorScheme.secondaryContainer.copy(alpha = cardAlpha)
                                else
                                    MaterialTheme.colorScheme.surfaceContainerHighest.copy(alpha = cardAlpha),
                                shape = MaterialTheme.shapes.medium,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp)
                                    .clip(MaterialTheme.shapes.medium)
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .toggleable(
                                            value = option.javaClass == selectedOption?.javaClass,
                                            onValueChange = { onClick(option) },
                                            role = Role.RadioButton,
                                            indication = LocalIndication.current,
                                            interactionSource = interactionSource
                                        )
                                        .padding(vertical = 8.dp, horizontal = 12.dp)
                                ) {
                                    RadioButton(
                                        selected = option.javaClass == selectedOption?.javaClass,
                                        onClick = null,
                                        interactionSource = interactionSource,
                                        colors = RadioButtonDefaults.colors(
                                            selectedColor = MaterialTheme.colorScheme.primary,
                                            unselectedColor = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    )
                                    Column(
                                        modifier = Modifier
                                            .padding(start = 10.dp)
                                            .weight(1f)
                                    ) {
                                        Text(
                                            text = stringResource(id = option.label),
                                            style = MaterialTheme.typography.bodyLarge
                                        )
                                        option.summary?.let {
                                            Text(
                                                text = it,
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // GKI 安装
        if (rootAvailable) {
            ElevatedCard(
                colors = getCardColors(MaterialTheme.colorScheme.surfaceVariant),
                elevation = CardDefaults.cardElevation(defaultElevation = cardElevation),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 12.dp)
                    .clip(MaterialTheme.shapes.large)
                    .shadow(
                        elevation = cardElevation,
                        shape = MaterialTheme.shapes.large,
                        spotColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)
                    )
            ) {
                ListItem(
                    leadingContent = {
                        Icon(
                            Icons.Filled.FileUpload,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary
                        )
                    },
                    headlineContent = {
                        Text(
                            stringResource(R.string.GKI_install_methods),
                            style = MaterialTheme.typography.titleMedium
                        )
                    },
                    modifier = Modifier.clickable {
                        GKIExpanded = !GKIExpanded
                    }
                )

                AnimatedVisibility(
                    visible = GKIExpanded,
                    enter = fadeIn() + expandVertically(),
                    exit = shrinkVertically() + fadeOut()
                ) {
                    Column(
                        modifier = Modifier.padding(
                            start = 16.dp,
                            end = 16.dp,
                            bottom = 16.dp
                        )
                    ) {
                        if (radioOptions.size > 3) {
                            radioOptions.drop(3).forEach { option ->
                                val interactionSource = remember { MutableInteractionSource() }
                                Surface(
                                    color = if (option.javaClass == selectedOption?.javaClass)
                                        MaterialTheme.colorScheme.secondaryContainer.copy(alpha = cardAlpha)
                                    else
                                        MaterialTheme.colorScheme.surfaceContainerHighest.copy(alpha = cardAlpha),
                                    shape = MaterialTheme.shapes.medium,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 4.dp)
                                        .clip(MaterialTheme.shapes.medium)
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .toggleable(
                                                value = option.javaClass == selectedOption?.javaClass,
                                                onValueChange = { onClick(option) },
                                                role = Role.RadioButton,
                                                indication = LocalIndication.current,
                                                interactionSource = interactionSource
                                            )
                                            .padding(vertical = 8.dp, horizontal = 12.dp)
                                    ) {
                                        RadioButton(
                                            selected = option.javaClass == selectedOption?.javaClass,
                                            onClick = null,
                                            interactionSource = interactionSource,
                                            colors = RadioButtonDefaults.colors(
                                                selectedColor = MaterialTheme.colorScheme.primary,
                                                unselectedColor = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        )
                                        Column(
                                            modifier = Modifier
                                                .padding(start = 10.dp)
                                                .weight(1f)
                                        ) {
                                            Text(
                                                text = stringResource(id = option.label),
                                                style = MaterialTheme.typography.bodyLarge
                                            )
                                            option.summary?.let {
                                                Text(
                                                    text = it,
                                                    style = MaterialTheme.typography.bodySmall,
                                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 如果没有root，显示一个提示卡片
        if (!rootAvailable) {
            ElevatedCard(
                colors = getCardColors(MaterialTheme.colorScheme.errorContainer),
                elevation = CardDefaults.cardElevation(defaultElevation = cardElevation),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 12.dp)
                    .clip(MaterialTheme.shapes.large)
                    .shadow(
                        elevation = cardElevation,
                        shape = MaterialTheme.shapes.large,
                        spotColor = MaterialTheme.colorScheme.error.copy(alpha = 0.1f)
                    )
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(24.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Filled.AutoFixHigh,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier
                            .padding(end = 16.dp)
                    )
                    Text(
                        text = stringResource(R.string.root_require_for_install),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onErrorContainer
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun rememberSelectKmiDialog(onSelected: (String?) -> Unit): DialogHandle {
    return rememberCustomDialog { dismiss ->
        val supportedKmi by produceState(initialValue = emptyList<String>()) {
            value = getSupportedKmis()
        }
        val options = supportedKmi.map { value ->
            ListOption(
                titleText = value
            )
        }

        var selection by remember { mutableStateOf<String?>(null) }
        val backgroundColor = MaterialTheme.colorScheme.surfaceContainerHighest

        MaterialTheme(
            colorScheme = MaterialTheme.colorScheme.copy(
                surface = backgroundColor
            )
        ) {
            ListDialog(state = rememberUseCaseState(visible = true, onFinishedRequest = {
                onSelected(selection)
            }, onCloseRequest = {
                dismiss()
            }), header = Header.Default(
                title = stringResource(R.string.select_kmi),
            ), selection = ListSelection.Single(
                showRadioButtons = true,
                options = options,
            ) { _, option ->
                selection = option.titleText
            })
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TopBar(
    onBack: () -> Unit = {},
    onLkmUpload: () -> Unit = {},
    scrollBehavior: TopAppBarScrollBehavior? = null
) {
    val cardColor = MaterialTheme.colorScheme.surfaceVariant
    val cardAlpha = cardAlpha

    TopAppBar(
        title = {
            Text(
                stringResource(R.string.install),
                style = MaterialTheme.typography.titleLarge
            )
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = cardColor.copy(alpha = cardAlpha),
            scrolledContainerColor = cardColor.copy(alpha = cardAlpha)
        ),
        navigationIcon = {
            IconButton(onClick = onBack) {
                Icon(
                    Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = stringResource(R.string.back)
                )
            }
        },
        windowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal
        ),
        scrollBehavior = scrollBehavior
    )
}

@Preview
@Composable
fun SelectInstallPreview() {
    InstallScreen(EmptyDestinationsNavigator)
}