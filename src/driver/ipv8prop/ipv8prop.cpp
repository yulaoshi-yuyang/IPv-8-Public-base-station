/*++

Copyright (c) IPv8+ Project. All rights reserved.

Module Name:

    ipv8prop.cpp

Abstract:

    IPv8+ 协议 notify object DLL（Phase 5C 修订）。

    实现 INetCfgComponentControl（notify object 必需）+ INetCfgComponentPropertyUi
    （属性页）+ INetCfgComponentSetup。MergePropPages 提供两个只读标签页：

      常规   —— 本机 IPv8 身份（读 %USERPROFILE%\.ipv8\visa.bin：地址 + 签证
                有效期）、名称解析说明、统一门户入口（ipv8.yulaoshi.xyz）。
      适配器 —— ipv8proto.sys 运行状态与逐适配器绑定/流量报表（\\.\IPv8Proto
                三 IOCTL），手动刷新；驱动未运行时红横幅指引修复。

    设计原则：控件要么展示真实数据要么执行真实动作；无假表单、无假状态灯。
    任何文件/IOCTL/剪贴板失败一律降级文案，绝不崩溃宿主进程。

--*/

#define ISOLATION_AWARE_ENABLED 1   /* 控件经本 DLL 的 comctl32 v6 清单渲染 */

#include <windows.h>
#include <winioctl.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <commctrl.h>
#include <objbase.h>
#include <netcfgn.h>
#include <shellapi.h>
#include <new>
#include <cstdio>
#include "resource.h"

#pragma comment(lib, "iphlpapi.lib")

/* 属性页/notify object COM 类 ID，必须与 ipv8proto.inf 中
   "HKR, Ndi, Clsid, ..." 的 GUID 完全一致。 */
static const wchar_t kClsidString[] = L"{7E5F3A9C-1D64-4B2E-9C38-A50F8E2D6B71}";
static const GUID kNotifyClsid =
    { 0x7E5F3A9C, 0x1D64, 0x4B2E, { 0x9C, 0x38, 0xA5, 0x0F, 0x8E, 0x2D, 0x6B, 0x71 } };

/* SELFREG_E_CLASS 字面值（objbase.h 在当前包含顺序下未导出该宏）*/
static const HRESULT kSelfRegEClass = static_cast<HRESULT>(0x80040201L);

/* 客户统一入口：门户跑在中枢机，经 Cloudflare 隧道发布；客户机只认域名。
   不做任何本机端口探测。 */
static const wchar_t kPortalUrl[] = L"https://ipv8.yulaoshi.xyz";

static HINSTANCE g_hInst = nullptr;

/* ---- 与内核 driver.h 逐字节一致的用户态镜像 ---- */
#pragma pack(push, 1)

typedef struct _IPV8_VERSION_INFO {
    unsigned long  Magic;
    unsigned short Major;
    unsigned short Minor;
    unsigned short NdisMajor;
    unsigned short NdisMinor;
} IPV8_VERSION_INFO;

typedef struct _IPV8_GLOBAL_STATS {
    unsigned long Magic;
    long          OpenCount;
    long          Unloading;
    unsigned long Reserved;
} IPV8_GLOBAL_STATS;

/* Phase 5B（驱动 v0.10）：180 字节，与内核 driver.h IPV8_BINDING_ENTRY 逐字节一致 */
#define IPV8_BINDING_NAME_CHARS 64

typedef struct _IPV8_BINDING_ENTRY {
    unsigned long long RxPackets;                        /* +0  */
    unsigned long long TxPackets;                        /* +8  */
    unsigned long long RxDropped;                        /* +16 */
    unsigned long long TxDropped;                        /* +24 */
    unsigned long      Bound;                            /* +32 */
    unsigned long      IfIndex;                          /* +36 */
    unsigned char      Mac[6];                           /* +40 */
    unsigned char      Pad[2];                           /* +46 */
    unsigned long      NameChars;                        /* +48 */
    wchar_t            Name[IPV8_BINDING_NAME_CHARS];    /* +52, 128B */
} IPV8_BINDING_ENTRY;

static_assert(sizeof(IPV8_BINDING_ENTRY) == 180,
    "IPV8_BINDING_ENTRY 必须与内核 180B pack(1) 布局一致");

typedef struct _IPV8_BINDINGS_OUT {
    unsigned long      Magic;
    unsigned long      Total;
    unsigned long      Count;
    unsigned long      Reserved;
    IPV8_BINDING_ENTRY Entries[1];
} IPV8_BINDINGS_OUT;

#pragma pack(pop)

/* IOCTL 码与内核侧同源计算，杜绝硬编码漂移 */
static const DWORD IOCTL_IPV8_GET_VERSION =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
static const DWORD IOCTL_IPV8_GET_STATS =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
static const DWORD IOCTL_IPV8_GET_BINDINGS =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);

#define IPV8_IOCTL_MAGIC 0xFB14UL

/* 单次 IOCTL 返回的绑定条数上限（适配器数量远小于此） */
#define MAX_BINDING_ENTRIES 32

/* ---- IOCTL 封装：失败返回 false，绝不抛异常。
   GENERIC_READ 与驱动 SDDL 的 (A;;GR;;;WD) 对应，普通用户可查。 ---- */

static bool DriverQuery(DWORD ioctl, void* out, DWORD outSize, DWORD* got)
{
    HANDLE h = CreateFileW(L"\\\\.\\IPv8Proto", GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;

    DWORD bytes = 0;
    bool ok = DeviceIoControl(h, ioctl, nullptr, 0, out, outSize, &bytes, nullptr)
        && bytes > 0;
    CloseHandle(h);
    if (got)
        *got = bytes;
    return ok;
}

/* ---- visa.bin 读取（与 ping8 / 门户同一文件契约）----
   布局: magic "IP8V"(4) + ver(1) + machine_id(32) + ipv8_addr(16, 偏移37)
         + ed_pubkey(32) + issued_at(8) + expires_at(8, 偏移93) + nonce(16)
         + ca_sig(64)，总长 181。多字节整数均大端。 */

#define VISA_MIN_READ       101
#define VISA_ADDR_OFFSET    37
#define VISA_EXPIRES_OFFSET 93

struct VisaDisplay {
    bool          Present;    /* 文件存在且 magic/version 合法 */
    bool          Expired;    /* Present 且有效期已过 */
    wchar_t       Addr[40];   /* 冒号规范形式 8 组 4hex */
    wchar_t       Expiry[96]; /* 人类可读有效期 */
};

static unsigned long long Be64(const unsigned char* p)
{
    unsigned long long v = 0;
    for (int i = 0; i < 8; ++i)
        v = (v << 8) | p[i];
    return v;
}

static unsigned long long UnixNowSecs()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return (u.QuadPart - 116444736000000000ULL) / 10000000ULL;
}

static void QueryVisa(VisaDisplay* v)
{
    ZeroMemory(v, sizeof(*v));

    wchar_t home[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"USERPROFILE", home, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return;

    wchar_t path[MAX_PATH + 32];
    if (swprintf_s(path, L"%s\\.ipv8\\visa.bin", home) < 0)
        return;

    HANDLE h = CreateFileW(path, FILE_READ_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return;

    unsigned char buf[256];
    DWORD got = 0;
    BOOL readOk = ReadFile(h, buf, sizeof(buf), &got, nullptr);
    CloseHandle(h);
    if (!readOk || got < VISA_MIN_READ)
        return;
    if (buf[0] != 0x49 || buf[1] != 0x50 || buf[2] != 0x38 ||
        buf[3] != 0x56 || buf[4] != 1)
        return;

    v->Present = true;

    /* 16 字节地址：大端 8 组，冒号分隔（与 ping8、门户一致）*/
    wchar_t* p = v->Addr;
    int left = (int)(sizeof(v->Addr) / sizeof(wchar_t));
    for (int i = 0; i < 8; ++i) {
        unsigned g = ((unsigned)buf[VISA_ADDR_OFFSET + i * 2] << 8)
            | buf[VISA_ADDR_OFFSET + i * 2 + 1];
        int wrote = swprintf_s(p, (size_t)left, L"%s%04x",
            i ? L":" : L"", g);
        if (wrote < 0)
            break;
        p += wrote;
        left -= wrote;
    }

    unsigned long long exp = Be64(buf + VISA_EXPIRES_OFFSET);
    if (exp == 0) {
        wcscpy_s(v->Expiry, L"永不过期");
        return;
    }

    ULARGE_INTEGER ftv;
    ftv.QuadPart = exp * 10000000ULL + 116444736000000000ULL;
    FILETIME ft;
    ft.dwLowDateTime = ftv.LowPart;
    ft.dwHighDateTime = ftv.HighPart;
    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&ft, &st)) {
        wcscpy_s(v->Expiry, L"未知");
        return;
    }

    long long diff = (long long)exp - (long long)UnixNowSecs();
    if (diff < 0) {
        v->Expired = true;
        swprintf_s(v->Expiry, L"已过期（%04u/%02u/%02u）",
            st.wYear, st.wMonth, st.wDay);
    } else if (diff < 86400) {
        swprintf_s(v->Expiry, L"今日到期（%04u/%02u/%02u）",
            st.wYear, st.wMonth, st.wDay);
    } else {
        unsigned long long days = (unsigned long long)diff / 86400;
        swprintf_s(v->Expiry, L"%llu 天后到期（%04u/%02u/%02u）",
            days, st.wYear, st.wMonth, st.wDay);
    }
}

/* ======================================================================
   常规页
   ====================================================================== */

struct GeneralUi {
    HFONT  Mono;
    HBRUSH WarnBrush;
};

static HFONT CreateMonoFont()
{
    return CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_MODERN, L"Consolas");
}

static void CopyTextToClipboard(HWND owner, const wchar_t* text)
{
    size_t bytes = (wcslen(text) + 1) * sizeof(wchar_t);
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!mem)
        return;
    void* p = GlobalLock(mem);
    memcpy(p, text, bytes);
    GlobalUnlock(mem);

    if (!OpenClipboard(owner)) {
        GlobalFree(mem);
        return;
    }
    EmptyClipboard();
    HANDLE placed = SetClipboardData(CF_UNICODETEXT, mem);
    CloseClipboard();
    if (!placed)
        GlobalFree(mem);  /* 成功时所有权已移交，不得释放 */
}

static INT_PTR CALLBACK GeneralProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_INITDIALOG: {
        GeneralUi* ui = new (std::nothrow) GeneralUi();
        if (!ui)
            return TRUE;
        ui->Mono = CreateMonoFont();
        ui->WarnBrush = CreateSolidBrush(RGB(0xFF, 0xF8, 0xE6));
        SetWindowLongPtrW(hDlg, GWLP_USERDATA, (LONG_PTR)ui);

        VisaDisplay v;
        QueryVisa(&v);

        HWND addr = GetDlgItem(hDlg, IDC_EDIT_ADDR);
        if (ui->Mono)
            SendMessageW(addr, WM_SETFONT, (WPARAM)ui->Mono, TRUE);

        const wchar_t* banner = nullptr;
        if (v.Present) {
            SetWindowTextW(addr, v.Addr);
            SetDlgItemTextW(hDlg, IDC_TXT_VISA, v.Expiry);
            if (v.Expired)
                banner = L"签证已过期。请尽快运行 ping8 auto 自动续签，"
                         L"或在管理门户中重新签发。";
        } else {
            SetWindowTextW(addr, L"（尚未配置 IPv8 身份）");
            SetDlgItemTextW(hDlg, IDC_TXT_VISA, L"—");
            EnableWindow(GetDlgItem(hDlg, IDC_BTN_COPY), FALSE);
            banner = L"本机尚未配置 IPv8 身份。请运行 ping8 auto 一键自动配置，"
                     L"或在管理门户中完成签发。";
        }

        BOOL showBanner = banner != nullptr;
        SetDlgItemTextW(hDlg, IDC_BANNER_NOVISA, showBanner ? banner : L"");
        ShowWindow(GetDlgItem(hDlg, IDC_BANNER_NOVISA),
            showBanner ? SW_SHOW : SW_HIDE);
        ShowWindow(GetDlgItem(hDlg, IDC_ICON_WARN),
            showBanner ? SW_SHOW : SW_HIDE);
        HICON warnIcon = (HICON)LoadImageW(nullptr,
            IDI_EXCLAMATION, IMAGE_ICON, 16, 16, LR_SHARED);
        SendDlgItemMessageW(hDlg, IDC_ICON_WARN, STM_SETICON,
            (WPARAM)warnIcon, 0);
        return TRUE;
    }

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_BTN_COPY: {
            /* 无签证降级态时按钮已置灰；置灰时 BN_CLICKED 不会到这里，
               再查一次启用态双保险，避免复制占位文案。 */
            if (!IsWindowEnabled(GetDlgItem(hDlg, IDC_BTN_COPY)))
                return TRUE;
            wchar_t addr[40];
            GetDlgItemTextW(hDlg, IDC_EDIT_ADDR, addr,
                (int)(sizeof(addr) / sizeof(wchar_t)));
            if (addr[0] != 0) {
                CopyTextToClipboard(hDlg, addr);
                SetDlgItemTextW(hDlg, IDC_BTN_COPY, L"已复制");
                SetTimer(hDlg, 1, 1200, nullptr);
            }
            return TRUE;
        }
        case IDC_BTN_PORTAL:
            ShellExecuteW(hDlg, L"open", kPortalUrl, nullptr, nullptr,
                SW_SHOWNORMAL);
            return TRUE;
        default:
            return FALSE;
        }

    case WM_TIMER:
        if (wp == 1) {
            KillTimer(hDlg, 1);
            SetDlgItemTextW(hDlg, IDC_BTN_COPY, L"复制(&C)");
        }
        return TRUE;

    case WM_CTLCOLORSTATIC: {
        GeneralUi* ui = (GeneralUi*)GetWindowLongPtrW(hDlg, GWLP_USERDATA);
        HWND ctl = (HWND)lp;
        if (ui && ctl == GetDlgItem(hDlg, IDC_BANNER_NOVISA)
            && IsWindowVisible(ctl)) {
            HDC hdc = (HDC)wp;
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(0x7A, 0x4B, 0x00));
            return (INT_PTR)(LONG_PTR)ui->WarnBrush;
        }
        return FALSE;
    }

    case WM_NCDESTROY: {
        GeneralUi* ui = (GeneralUi*)GetWindowLongPtrW(hDlg, GWLP_USERDATA);
        if (ui) {
            if (ui->Mono)
                DeleteObject(ui->Mono);
            if (ui->WarnBrush)
                DeleteObject(ui->WarnBrush);
            delete ui;
            SetWindowLongPtrW(hDlg, GWLP_USERDATA, 0);
        }
        return FALSE;
    }

    default:
        return FALSE;
    }
}

/* ======================================================================
   适配器页
   ====================================================================== */

struct AdapterUi {
    HBRUSH ErrorBrush;
};

/* 列定义：宽度用 DLU，初始化时按当前 DPI 经 MapDialogRect 换算 */
struct ColumnDef {
    const wchar_t* Title;
    int            WidthDlu;
    int            Format;
};

static const ColumnDef kColumns[] = {
    { L"#",        18, LVCFMT_LEFT   },
    { L"适配器",   72, LVCFMT_LEFT   },
    { L"物理地址", 62, LVCFMT_LEFT   },
    { L"状态",     34, LVCFMT_CENTER },
    { L"接收",     34, LVCFMT_RIGHT  },
    { L"发送",     34, LVCFMT_RIGHT  },
    { L"丢包",     38, LVCFMT_RIGHT  },
};

static void InitListColumns(HWND hDlg, HWND lv)
{
    ListView_SetExtendedListViewStyleEx(lv,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);

    for (int i = 0; i < (int)(sizeof(kColumns) / sizeof(kColumns[0])); ++i) {
        RECT r = { 0, 0, kColumns[i].WidthDlu, 0 };
        MapDialogRect(hDlg, &r);
        LVCOLUMNW col = {};
        col.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT;
        col.fmt = kColumns[i].Format;
        col.cx = r.right;
        col.pszText = (LPWSTR)kColumns[i].Title;
        ListView_InsertColumn(lv, i, &col);
    }
}

/* 包数/丢包数是无符号整数计数：要 locale 千分位但不要小数位。
   不传 NUMBERFMT 时 GetNumberFormatW 会按 locale 默认 NumDigits=2
   把 0 渲染成 "0.00"，故显式 NumDigits=0。 */
static void FormatCount(unsigned long long v, wchar_t* out, int cch)
{
    wchar_t raw[32];
    swprintf_s(raw, L"%llu", v);

    wchar_t thou[8], dot[8];
    int n1 = GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_STHOUSAND,
        thou, (int)(sizeof(thou) / sizeof(wchar_t)));
    int n2 = GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SDECIMAL,
        dot, (int)(sizeof(dot) / sizeof(wchar_t)));

    NUMBERFMTW nf = {};
    nf.NumDigits      = 0;
    nf.LeadingZero    = 1;
    nf.Grouping       = 3;
    nf.lpDecimalSep   = (n2 > 0) ? dot  : (wchar_t*)L".";
    nf.lpThousandSep  = (n1 > 0) ? thou : (wchar_t*)L",";
    nf.NegativeOrder  = 0;

    if (!GetNumberFormatW(LOCALE_USER_DEFAULT, 0, raw, &nf, out, cch))
        wcscpy_s(out, (size_t)cch, raw);
}

/* 驱动给的适配器名是 NDIS 设备路径 \DEVICE\{接口GUID}，对普通用户不可读。
   用 iphlpapi 建一张 GUID(大写) → 系统别名（ncpa 显示的 WLAN/以太网…）表；
   查不到时回退原始设备名，绝不臆造。每次刷新重建（改名/插拔后即更新）。 */
struct AliasEntry {
    wchar_t Guid[40];
    wchar_t Alias[256];
};
static const int kMaxAliasEntries = 64;

static int BuildAliasMap(AliasEntry* map, int capacity)
{
    ULONG bufLen = 0;
    /* 只要 AdapterName(GUID) 与 FriendlyName(别名)，其余地址信息全跳过。 */
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
                | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_UNICAST;
    ULONG ret = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, nullptr, &bufLen);
    if (ret != ERROR_BUFFER_OVERFLOW || bufLen == 0)
        return 0;

    unsigned char* heap = new (std::nothrow) unsigned char[bufLen];
    if (!heap)
        return 0;

    int count = 0;
    ret = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
        (IP_ADAPTER_ADDRESSES*)heap, &bufLen);
    if (ret == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES* aa = (IP_ADAPTER_ADDRESSES*)heap;
             aa && count < capacity; aa = aa->Next) {
            /* AdapterName 是 ANSI 的 "{GUID}"；FriendlyName 是系统别名。 */
            if (!aa->AdapterName || !aa->FriendlyName)
                continue;
            wchar_t wguid[40];
            int wlen = MultiByteToWideChar(CP_ACP, 0, aa->AdapterName, -1,
                wguid, (int)(sizeof(wguid) / sizeof(wchar_t)));
            if (wlen <= 0)
                continue;
            int i = 0;
            for (; wguid[i] && i < 39; ++i)
                map[count].Guid[i] = (wchar_t)towupper(wguid[i]);
            map[count].Guid[i] = 0;
            wcsncpy_s(map[count].Alias, aa->FriendlyName,
                (size_t)(sizeof(map[count].Alias) / sizeof(wchar_t)) - 1);
            ++count;
        }
    }
    delete[] heap;
    return count;
}

/* 从 \DEVICE\{GUID} 取出指向 '{' 的子串（大写比较）；无花括号则原样返回。 */
static const wchar_t* GuidPart(const wchar_t* dev)
{
    const wchar_t* p = wcsrchr(dev, L'{');
    return p ? p : dev;
}

static const wchar_t* LookupAlias(const AliasEntry* map, int count,
    const wchar_t* deviceName)
{
    const wchar_t* key = GuidPart(deviceName);
    for (int i = 0; i < count; ++i) {
        const wchar_t* a = map[i].Guid;
        const wchar_t* b = key;
        bool eq = true;
        while (*a && *b) {
            if (towupper(*a) != towupper(*b)) { eq = false; break; }
            ++a; ++b;
        }
        if (eq && *a == 0 && *b == 0)
            return map[i].Alias;
    }
    return nullptr;
}

static void FillAdapterRow(HWND lv, int row, const IPV8_BINDING_ENTRY& e,
    const AliasEntry* aliasMap, int aliasCount)
{
    wchar_t idx[16], mac[24], rx[32], tx[32], rxd[32], txd[32], drop[80];
    swprintf_s(idx, L"%d", row + 1);
    swprintf_s(mac, L"%02X-%02X-%02X-%02X-%02X-%02X",
        e.Mac[0], e.Mac[1], e.Mac[2], e.Mac[3], e.Mac[4], e.Mac[5]);

    wchar_t name[IPV8_BINDING_NAME_CHARS + 1];
    unsigned long cc = e.NameChars;
    if (cc > IPV8_BINDING_NAME_CHARS)
        cc = IPV8_BINDING_NAME_CHARS;
    memcpy(name, e.Name, cc * sizeof(wchar_t));
    name[cc] = 0;

    /* 优先展示系统别名（WLAN/以太网…），映射不到再用设备路径，不臆造。 */
    const wchar_t* display = LookupAlias(aliasMap, aliasCount, name);
    const wchar_t* col1 = display ? display : name;

    LVITEMW lvi = {};
    lvi.mask = LVIF_TEXT;
    lvi.iItem = row;
    lvi.iSubItem = 0;
    lvi.pszText = idx;
    ListView_InsertItem(lv, &lvi);
    ListView_SetItemText(lv, row, 1, (LPWSTR)col1);
    ListView_SetItemText(lv, row, 2, mac);

    if (e.Bound) {
        FormatCount(e.RxPackets, rx, (int)(sizeof(rx) / sizeof(wchar_t)));
        FormatCount(e.TxPackets, tx, (int)(sizeof(tx) / sizeof(wchar_t)));
        FormatCount(e.RxDropped, rxd, (int)(sizeof(rxd) / sizeof(wchar_t)));
        FormatCount(e.TxDropped, txd, (int)(sizeof(txd) / sizeof(wchar_t)));
        swprintf_s(drop, L"%s/%s", rxd, txd);
        ListView_SetItemText(lv, row, 3, (LPWSTR)L"已绑定");
        ListView_SetItemText(lv, row, 4, rx);
        ListView_SetItemText(lv, row, 5, tx);
        ListView_SetItemText(lv, row, 6, drop);
    } else {
        ListView_SetItemText(lv, row, 3, (LPWSTR)L"未绑定");
        ListView_SetItemText(lv, row, 4, (LPWSTR)L"—");
        ListView_SetItemText(lv, row, 5, (LPWSTR)L"—");
        ListView_SetItemText(lv, row, 6, (LPWSTR)L"—");
    }
}

static void SetAdapterErrorMode(HWND hDlg, bool error)
{
    int errorVis = error ? SW_SHOW : SW_HIDE;
    int dataVis = error ? SW_HIDE : SW_SHOW;
    ShowWindow(GetDlgItem(hDlg, IDC_TXT_DRVSTATUS), dataVis);
    ShowWindow(GetDlgItem(hDlg, IDC_LIST), dataVis);
    ShowWindow(GetDlgItem(hDlg, IDC_TXT_HINT), dataVis);
    ShowWindow(GetDlgItem(hDlg, IDC_ICON_ERR), errorVis);
    ShowWindow(GetDlgItem(hDlg, IDC_BANNER_DRV), errorVis);
    if (error) {
        SetDlgItemTextW(hDlg, IDC_BANNER_DRV,
            L"ipv8proto.sys 未运行，适配器统计不可用。\r\n"
            L"请以管理员身份运行 scripts\\driver-install.ps1 安装并启动驱动，"
            L"再点“刷新”。");
    }
}

static void ReloadAdapters(HWND hDlg)
{
    HWND lv = GetDlgItem(hDlg, IDC_LIST);
    ListView_DeleteAllItems(lv);

    IPV8_VERSION_INFO ver = {};
    DWORD got = 0;
    bool ok = DriverQuery(IOCTL_IPV8_GET_VERSION, &ver, sizeof(ver), &got)
        && ver.Magic == IPV8_IOCTL_MAGIC;

    unsigned char big[sizeof(IPV8_BINDINGS_OUT)
        + MAX_BINDING_ENTRIES * sizeof(IPV8_BINDING_ENTRY)] = {};
    IPV8_BINDINGS_OUT* b = (IPV8_BINDINGS_OUT*)big;
    if (ok) {
        ok = DriverQuery(IOCTL_IPV8_GET_BINDINGS, big, sizeof(big), &got)
            && b->Magic == IPV8_IOCTL_MAGIC;
    }

    if (!ok) {
        SetAdapterErrorMode(hDlg, true);
        return;
    }

    unsigned long boundCount = 0;
    AliasEntry aliasMap[kMaxAliasEntries];
    int aliasCount = BuildAliasMap(aliasMap, kMaxAliasEntries);
    for (unsigned long i = 0; i < b->Count; ++i) {
        if (b->Entries[i].Bound)
            ++boundCount;
        FillAdapterRow(lv, (int)i, b->Entries[i], aliasMap, aliasCount);
    }

    wchar_t status[160];
    swprintf_s(status,
        L"IPv8Proto v%u.%u 运行中（NDIS %u.%u）· %lu 个适配器已绑定",
        (unsigned)ver.Major, (unsigned)ver.Minor,
        (unsigned)ver.NdisMajor, (unsigned)ver.NdisMinor, boundCount);
    SetDlgItemTextW(hDlg, IDC_TXT_DRVSTATUS, status);
    SetAdapterErrorMode(hDlg, false);
}

static INT_PTR CALLBACK AdapterProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_INITDIALOG: {
        AdapterUi* ui = new (std::nothrow) AdapterUi();
        if (!ui)
            return TRUE;
        ui->ErrorBrush = CreateSolidBrush(RGB(0xFD, 0xF1, 0xF0));
        SetWindowLongPtrW(hDlg, GWLP_USERDATA, (LONG_PTR)ui);

        InitListColumns(hDlg, GetDlgItem(hDlg, IDC_LIST));
        HICON errIcon = (HICON)LoadImageW(nullptr,
            IDI_HAND, IMAGE_ICON, 16, 16, LR_SHARED);
        SendDlgItemMessageW(hDlg, IDC_ICON_ERR, STM_SETICON,
            (WPARAM)errIcon, 0);
        ReloadAdapters(hDlg);
        return TRUE;
    }

    case WM_COMMAND:
        if (LOWORD(wp) == IDC_BTN_REFRESH) {
            ReloadAdapters(hDlg);
            return TRUE;
        }
        return FALSE;

    case WM_CTLCOLORSTATIC: {
        AdapterUi* ui = (AdapterUi*)GetWindowLongPtrW(hDlg, GWLP_USERDATA);
        HWND ctl = (HWND)lp;
        if (ui && ctl == GetDlgItem(hDlg, IDC_BANNER_DRV)
            && IsWindowVisible(ctl)) {
            HDC hdc = (HDC)wp;
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(0xA8, 0x2A, 0x1E));
            return (INT_PTR)(LONG_PTR)ui->ErrorBrush;
        }
        return FALSE;
    }

    case WM_NCDESTROY: {
        AdapterUi* ui = (AdapterUi*)GetWindowLongPtrW(hDlg, GWLP_USERDATA);
        if (ui) {
            if (ui->ErrorBrush)
                DeleteObject(ui->ErrorBrush);
            delete ui;
            SetWindowLongPtrW(hDlg, GWLP_USERDATA, 0);
        }
        return FALSE;
    }

    default:
        return FALSE;
    }
}

/* ---- 引用计数（对象 + LockServer），DllCanUnloadNow 依据 ---- */

static volatile LONG g_cRefs = 0;

/* ---- Notify object：netcfgx 经 Ndi\Clsid CoCreate ---- */

class CNotifyObject : public INetCfgComponentControl,
                      public INetCfgComponentPropertyUi,
                      public INetCfgComponentSetup
{
public:
    CNotifyObject() noexcept
        : m_refs(1), m_comp(nullptr), m_ncfg(nullptr)
    {
        InterlockedIncrement(&g_cRefs);
    }

    ~CNotifyObject() noexcept
    {
        if (m_comp) m_comp->Release();
        if (m_ncfg) m_ncfg->Release();
        InterlockedDecrement(&g_cRefs);
    }

    /* ---- IUnknown（INetCfgComponentControl 为主基类）---- */

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) noexcept override
    {
        if (!ppv)
            return E_INVALIDARG;
        *ppv = nullptr;
        if (riid == __uuidof(IUnknown))
            *ppv = static_cast<INetCfgComponentControl*>(this);
        else if (riid == __uuidof(INetCfgComponentControl))
            *ppv = static_cast<INetCfgComponentControl*>(this);
        else if (riid == __uuidof(INetCfgComponentPropertyUi))
            *ppv = static_cast<INetCfgComponentPropertyUi*>(this);
        else if (riid == __uuidof(INetCfgComponentSetup))
            *ppv = static_cast<INetCfgComponentSetup*>(this);
        else
            return E_NOINTERFACE;
        AddRef();
        return S_OK;
    }

    ULONG STDMETHODCALLTYPE AddRef() noexcept override
    {
        return (ULONG)InterlockedIncrement(&m_refs);
    }

    ULONG STDMETHODCALLTYPE Release() noexcept override
    {
        ULONG u = (ULONG)InterlockedDecrement(&m_refs);
        if (u == 0)
            delete this;
        return u;
    }

    /* ---- INetCfgComponentControl（必需接口）----
       只读组件：无注册表写、无 PNP 重配置，全部 no-op。 */

    HRESULT STDMETHODCALLTYPE Initialize(
        _In_ INetCfgComponent* pIComp,
        _In_ INetCfg* pINetCfg,
        _In_ BOOL fInstalling) noexcept override
    {
        UNREFERENCED_PARAMETER(fInstalling);
        if (!pIComp || !pINetCfg)
            return E_INVALIDARG;
        m_comp = pIComp;
        m_comp->AddRef();
        m_ncfg = pINetCfg;
        m_ncfg->AddRef();
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE ApplyRegistryChanges(void) noexcept override
    {
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE ApplyPnpChanges(
        _In_ INetCfgPnpReconfigCallback* pICallback) noexcept override
    {
        UNREFERENCED_PARAMETER(pICallback);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE CancelChanges(void) noexcept override
    {
        return S_OK;
    }

    /* ---- INetCfgComponentSetup（安装/升级/卸载回调）----
       netcfg 安装协议组件时会 QI 此接口；缺失则安装失败。本组件无需
       特殊安装逻辑，全部 no-op。 */

    HRESULT STDMETHODCALLTYPE Install(_In_ DWORD dwSetupFlags) noexcept override
    {
        UNREFERENCED_PARAMETER(dwSetupFlags);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE Upgrade(
        _In_ DWORD dwSetupFlags,
        _In_ DWORD dwUpgradeFomBuildNo) noexcept override
    {
        UNREFERENCED_PARAMETER(dwSetupFlags);
        UNREFERENCED_PARAMETER(dwUpgradeFomBuildNo);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE ReadAnswerFile(
        _In_ LPCWSTR pszwAnswerFile,
        _In_ LPCWSTR pszwAnswerSections) noexcept override
    {
        UNREFERENCED_PARAMETER(pszwAnswerFile);
        UNREFERENCED_PARAMETER(pszwAnswerSections);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE Removing(void) noexcept override
    {
        return S_OK;
    }

    /* ---- INetCfgComponentPropertyUi（属性页）----
       文档要求任何方法不得返回 E_NOTIMPL。 */

    HRESULT STDMETHODCALLTYPE QueryPropertyUi(
        _In_ IUnknown* pUnkReserved) noexcept override
    {
        UNREFERENCED_PARAMETER(pUnkReserved);
        return S_OK;  /* 任意上下文均可显示 */
    }

    HRESULT STDMETHODCALLTYPE SetContext(
        _In_ IUnknown* pUnkReserved) noexcept override
    {
        UNREFERENCED_PARAMETER(pUnkReserved);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE MergePropPages(
        _Inout_ DWORD* pdwDefPages,
        _Out_ BYTE** pahpspPrivate,
        _Out_ UINT* pcPages,
        _In_ HWND hwndParent,
        _In_opt_ LPCWSTR* pszStartPage) noexcept override
    {
        UNREFERENCED_PARAMETER(hwndParent);
        UNREFERENCED_PARAMETER(pszStartPage);
        if (!pdwDefPages || !pahpspPrivate || !pcPages)
            return E_INVALIDARG;
        UNREFERENCED_PARAMETER(pdwDefPages);

        /* SysListView32 类注册（现代宿主通常已注册，此处幂等兜底）*/
        INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_LISTVIEW_CLASSES };
        InitCommonControlsEx(&icc);

        HPROPSHEETPAGE hGeneral = CreatePage(
            IDD_PAGE_GENERAL, L"常规", GeneralProc);
        if (!hGeneral)
            return E_FAIL;
        HPROPSHEETPAGE hAdapters = CreatePage(
            IDD_PAGE_ADAPTERS, L"适配器", AdapterProc);
        if (!hAdapters) {
            DestroyPropertySheetPage(hGeneral);
            return E_FAIL;
        }

        /* 宿主负责释放该数组（CoTaskMemAlloc 契约） */
        HPROPSHEETPAGE* arr =
            (HPROPSHEETPAGE*)CoTaskMemAlloc(2 * sizeof(HPROPSHEETPAGE));
        if (!arr) {
            DestroyPropertySheetPage(hGeneral);
            DestroyPropertySheetPage(hAdapters);
            return E_OUTOFMEMORY;
        }
        arr[0] = hGeneral;
        arr[1] = hAdapters;

        *pahpspPrivate = (BYTE*)arr;
        *pcPages = 2;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE ValidateProperties(
        _In_ HWND hwndSheet) noexcept override
    {
        UNREFERENCED_PARAMETER(hwndSheet);
        return S_OK;  /* 页面只读，无可校验项 */
    }

    HRESULT STDMETHODCALLTYPE ApplyProperties(void) noexcept override
    {
        return S_OK;  /* 页面只读，无可应用项 */
    }

    HRESULT STDMETHODCALLTYPE CancelProperties(void) noexcept override
    {
        return S_OK;
    }

private:
    static HPROPSHEETPAGE CreatePage(int resid, const wchar_t* title,
        DLGPROC proc)
    {
        PROPSHEETPAGEW psp = {};
        psp.dwSize = sizeof(psp);
        psp.dwFlags = PSP_USETITLE;
        psp.hInstance = g_hInst;
        psp.pszTemplate = MAKEINTRESOURCEW(resid);
        psp.pszTitle = title;
        psp.pfnDlgProc = proc;
        return CreatePropertySheetPageW(&psp);
    }

    volatile LONG      m_refs;
    INetCfgComponent*  m_comp;
    INetCfg*           m_ncfg;
};

/* ---- 类厂 ---- */

class CClassFactory : public IClassFactory
{
public:
    CClassFactory() noexcept : m_refs(1)
    {
        InterlockedIncrement(&g_cRefs);
    }

    ~CClassFactory() noexcept
    {
        InterlockedDecrement(&g_cRefs);
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) noexcept override
    {
        if (!ppv)
            return E_INVALIDARG;
        *ppv = nullptr;
        if (riid == __uuidof(IUnknown) || riid == __uuidof(IClassFactory))
            *ppv = static_cast<IClassFactory*>(this);
        else
            return E_NOINTERFACE;
        AddRef();
        return S_OK;
    }

    ULONG STDMETHODCALLTYPE AddRef() noexcept override
    {
        return (ULONG)InterlockedIncrement(&m_refs);
    }

    ULONG STDMETHODCALLTYPE Release() noexcept override
    {
        ULONG u = (ULONG)InterlockedDecrement(&m_refs);
        if (u == 0)
            delete this;
        return u;
    }

    HRESULT STDMETHODCALLTYPE CreateInstance(
        IUnknown* pUnkOuter, REFIID riid, void** ppv) noexcept override
    {
        if (!ppv)
            return E_INVALIDARG;
        *ppv = nullptr;
        if (pUnkOuter)
            return CLASS_E_NOAGGREGATION;

        CNotifyObject* o = new (std::nothrow) CNotifyObject();
        if (!o)
            return E_OUTOFMEMORY;
        HRESULT hr = o->QueryInterface(riid, ppv);
        o->Release();
        return hr;
    }

    HRESULT STDMETHODCALLTYPE LockServer(BOOL fLock) noexcept override
    {
        if (fLock)
            InterlockedIncrement(&g_cRefs);
        else
            InterlockedDecrement(&g_cRefs);
        return S_OK;
    }

private:
    volatile LONG m_refs;
};

/* ---- 标准 COM 导出（经 ipv8prop.def 导出）---- */

HRESULT STDMETHODCALLTYPE
DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
    if (!ppv)
        return E_INVALIDARG;
    *ppv = nullptr;
    if (!IsEqualGUID(rclsid, kNotifyClsid))
        return CLASS_E_CLASSNOTAVAILABLE;

    CClassFactory* f = new (std::nothrow) CClassFactory();
    if (!f)
        return E_OUTOFMEMORY;
    HRESULT hr = f->QueryInterface(riid, ppv);
    f->Release();
    return hr;
}

HRESULT STDMETHODCALLTYPE DllCanUnloadNow(void)
{
    return g_cRefs == 0 ? S_OK : S_FALSE;
}

/* ---- COM 自注册 ----
   INF 的 HKR 只能写网络组件实例键，无法注册 COM InprocServer32；
   netcfgx 处理 Ndi\ComponentDll 时会调用本导出，driver-install.ps1 的
   regsvr32 兜底。 */

static bool WriteClsidString(const wchar_t* subkey, const wchar_t* valueName,
    const wchar_t* value)
{
    HKEY hKey = nullptr;
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, subkey, 0, nullptr, 0,
            KEY_WRITE, nullptr, &hKey, nullptr) != ERROR_SUCCESS)
        return false;

    DWORD bytes = (DWORD)((wcslen(value) + 1) * sizeof(wchar_t));
    LONG rc = RegSetValueExW(hKey, valueName, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(value), bytes);
    RegCloseKey(hKey);
    return rc == ERROR_SUCCESS;
}

extern "C" HRESULT __stdcall DllRegisterServer()
{
    wchar_t keyPath[160];
    swprintf_s(keyPath, 160, L"CLSID\\%s", kClsidString);

    /* 默认值：人类可读名称 */
    if (!WriteClsidString(keyPath, nullptr, L"IPv8 Notify Object"))
        return kSelfRegEClass;

    /* 取本 DLL 完整路径（已由 INF 复制到 System32）*/
    wchar_t dllPath[MAX_PATH] = {};
    HMODULE self = nullptr;
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
        | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&DllRegisterServer), &self);
    if (!self || !GetModuleFileNameW(self, dllPath, MAX_PATH))
        return kSelfRegEClass;

    wcscat_s(keyPath, 160, L"\\InprocServer32");
    HKEY hKey = nullptr;
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, keyPath, 0, nullptr, 0,
            KEY_WRITE, nullptr, &hKey, nullptr) != ERROR_SUCCESS)
        return kSelfRegEClass;

    DWORD pathBytes = (DWORD)((wcslen(dllPath) + 1) * sizeof(wchar_t));
    LONG rc = RegSetValueExW(hKey, nullptr, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(dllPath), pathBytes);
    if (rc == ERROR_SUCCESS)
    {
        rc = RegSetValueExW(hKey, L"ThreadingModel", 0, REG_SZ,
            reinterpret_cast<const BYTE*>(L"Both"),
            sizeof(L"Both"));  /* 含结尾 NUL */
    }
    RegCloseKey(hKey);

    return rc == ERROR_SUCCESS ? S_OK : kSelfRegEClass;
}

extern "C" HRESULT __stdcall DllUnregisterServer()
{
    wchar_t inprocKey[160];
    swprintf_s(inprocKey, 160, L"CLSID\\%s\\InprocServer32", kClsidString);
    RegDeleteKeyW(HKEY_CLASSES_ROOT, inprocKey);  /* 必须先删子键 */

    wchar_t clsidKey[160];
    swprintf_s(clsidKey, 160, L"CLSID\\%s", kClsidString);
    RegDeleteKeyW(HKEY_CLASSES_ROOT, clsidKey);

    return S_OK;  /* 键不存在也视为成功，保证卸载幂等 */
}

/* ---- DllMain ---- */

extern "C" BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hInst);
        g_hInst = hInst;
    }
    return TRUE;
}
