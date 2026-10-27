import { defineStore } from 'pinia'
import { computed, ref, shallowRef, watch } from 'vue'
import { Channel, invoke } from '@tauri-apps/api/core'
import {
  type DetailData,
  type InterfaceInfo,
  type LiveEvent,
  type PacketRow,
  type ParseResult,
  type Stats,
} from '../types/messages'

const PROTO_DIR_KEY = 'zenoh-analyzer.proto-dir'
const THEME_KEY = 'zenoh-analyzer.theme'

export const useAnalyzerStore = defineStore('analyzer', () => {
  // ---------- 数据 ----------
  const rows = shallowRef<PacketRow[]>([])
  const selectedIndex = ref<number | null>(null)
  const detailCache = new Map<number, DetailData>()
  const detail = shallowRef<DetailData | null>(null)
  const stats = shallowRef<Stats | null>(null)

  const mode = ref<'idle' | 'file' | 'live'>('idle')
  const loading = ref(false)
  const error = ref<string | null>(null)
  const warnings = ref<string[]>([])
  const fileName = ref('')

  // ---------- 过滤 ----------
  const filterText = ref('')
  const filterType = ref<string>('全部')
  const filterIncomplete = ref(false)

  const typeOptions = computed(() => {
    if (!stats.value) return ['全部']
    return ['全部', ...stats.value.byType.map(([t]) => t)]
  })

  const filteredRows = computed<PacketRow[]>(() => {
    let list = rows.value
    const t = filterText.value.trim().toLowerCase()
    if (t) {
      list = list.filter(
        (r) =>
          r.topic.toLowerCase().includes(t) ||
          r.anyType.toLowerCase().includes(t) ||
          r.outerType.toLowerCase().includes(t) ||
          r.summary.toLowerCase().includes(t) ||
          r.src.includes(t) ||
          r.dst.includes(t) ||
          r.msgType.toLowerCase().includes(t),
      )
    }
    if (filterType.value !== '全部') {
      list = list.filter((r) => r.msgType === filterType.value)
    }
    if (filterIncomplete.value) {
      list = list.filter((r) => !r.topicComplete)
    }
    if (mode.value === 'live') {
      // 实时消息因 TCP 段跨包延迟提交，到达序≠时间序，按时间排序显示
      list = [...list].sort((a, b) => a.tsUs - b.tsUs || a.index - b.index)
    }
    return list
  })

  // ---------- 主题 ----------
  const theme = ref<'dark' | 'light'>(
    (localStorage.getItem(THEME_KEY) as 'dark' | 'light') ?? 'light',
  )
  watch(
    theme,
    (t) => {
      localStorage.setItem(THEME_KEY, t)
      document.documentElement.classList.toggle('theme-light', t === 'light')
    },
    { immediate: true },
  )
  function toggleTheme() {
    theme.value = theme.value === 'dark' ? 'light' : 'dark'
  }

  // ---------- proto 配置持久化 ----------
  const protoDir = ref(localStorage.getItem(PROTO_DIR_KEY) ?? '')
  watch(protoDir, (v) => localStorage.setItem(PROTO_DIR_KEY, v))

  // ---------- 文件模式 ----------
  const lastPcapPath = ref('')

  async function openPcap(path: string) {
    loading.value = true
    error.value = null
    const prevSelected = selectedIndex.value
    try {
      const result = await invoke<ParseResult>('parse_pcap', {
        pcapPath: path,
        protoDir: protoDir.value || null,
      })
      lastPcapPath.value = path
      detailCache.clear()
      rows.value = result.rows
      warnings.value = result.warnings
      detail.value = null
      selectedIndex.value = null
      mode.value = 'file'
      fileName.value = path.split(/[\\/]/).pop() ?? path
      await refreshStats()
      if (result.rows.length > 0) selectRow(prevSelected ?? 0)
    } catch (e) {
      error.value = String(e)
    } finally {
      loading.value = false
    }
  }

  /** proto 目录变更后，用最近打开的 pcap 重新解析 */
  async function reparseWithProto() {
    if (lastPcapPath.value && mode.value === 'file') {
      await openPcap(lastPcapPath.value)
    }
  }

  async function refreshStats() {
    try {
      stats.value = await invoke<Stats>('get_stats')
    } catch {
      stats.value = null
    }
  }

  async function saveDisplayedPcapng(path: string): Promise<number> {
    const idxs = filteredRows.value.map((r) => r.index)
    const n = await invoke<number>('save_displayed_pcapng', { path, indexes: idxs })
    return n
  }

  // ---------- 详情（懒加载） ----------
  async function selectRow(index: number | null) {
    selectedIndex.value = index
    if (index === null) {
      detail.value = null
      return
    }
    const cached = detailCache.get(index)
    if (cached) {
      detail.value = cached
      return
    }
    try {
      const d = await invoke<DetailData>('get_detail', { index })
      detailCache.set(index, d)
      // 期间用户可能已切走
      if (selectedIndex.value === index) detail.value = d
    } catch (e) {
      error.value = String(e)
    }
  }

  // ---------- 实时模式 ----------
  const interfaces = ref<InterfaceInfo[]>([])
  const selectedInterface = ref('')
  const bpfFilter = ref('tcp port 7447')
  const capturing = ref(false)
  const paused = ref(false)
  const follow = ref(true)
  const liveTotal = ref(0)
  const pausedBuffer = shallowRef<PacketRow[]>([])

  async function loadInterfaces() {
    try {
      interfaces.value = await invoke<InterfaceInfo[]>('list_interfaces')
      if (interfaces.value.length > 0 && !selectedInterface.value) {
        // 优先选有 IPv4 地址的非回环接口
        const preferred =
          interfaces.value.find((i) => i.addresses.length > 0 && !i.name.includes('loopback')) ??
          interfaces.value[0]
        selectedInterface.value = preferred.name
      }
    } catch (e) {
      error.value = String(e)
    }
  }

  async function startCapture() {
    loading.value = true
    error.value = null
    try {
      detailCache.clear()
      rows.value = []
      pausedBuffer.value = []
      liveTotal.value = 0
      detail.value = null
      selectedIndex.value = null
      warnings.value = []
      mode.value = 'live'
      fileName.value = `实时捕获 (${selectedInterface.value.split('/').pop() ?? ''})`

      const channel = new Channel<LiveEvent>((event) => {
        if (event.kind === 'rows') {
          liveTotal.value = event.total
          if (paused.value && event.rows.length > 0) {
            pausedBuffer.value = [...pausedBuffer.value, ...event.rows]
          } else {
            appendRows(event.rows, event.updates ?? [])
          }
        } else {
          error.value = event.message
          capturing.value = false
        }
      })
      await invoke('start_capture', {
        interface: selectedInterface.value,
        bpf: bpfFilter.value,
        protoDir: protoDir.value || null,
        onRows: channel,
      })
      capturing.value = true
    } catch (e) {
      error.value = String(e)
    } finally {
      loading.value = false
    }
  }

  function appendRows(newRows: PacketRow[], updates: PacketRow[] = []) {
    if (updates.length > 0) {
      // 按 index 覆盖已有行（配对信息回填）
      const byIndex = new Map(updates.map((u) => [u.index, u]))
      rows.value = rows.value.map((r) => byIndex.get(r.index) ?? r)
    }
    if (newRows.length > 0) {
      rows.value = [...rows.value, ...newRows]
    }
    if (selectedIndex.value === null && newRows.length > 0) {
      selectRow(newRows[0].index)
    }
    refreshStats()
  }

  async function stopCapture() {
    try {
      await invoke('stop_capture')
    } finally {
      capturing.value = false
      if (pausedBuffer.value.length > 0) {
        appendRows(pausedBuffer.value)
        pausedBuffer.value = []
      }
      paused.value = false
    }
  }

  function togglePause() {
    if (paused.value) {
      // 恢复：把缓冲的数据补上
      appendRows(pausedBuffer.value)
      pausedBuffer.value = []
    }
    paused.value = !paused.value
  }

  function clearData() {
    rows.value = []
    detailCache.clear()
    detail.value = null
    selectedIndex.value = null
    stats.value = null
    warnings.value = []
    mode.value = 'idle'
    fileName.value = ''
    liveTotal.value = 0
  }

  return {
    rows,
    filteredRows,
    selectedIndex,
    detail,
    stats,
    mode,
    loading,
    error,
    warnings,
    fileName,
    filterText,
    filterType,
    filterIncomplete,
    typeOptions,
    theme,
    toggleTheme,
    protoDir,
    lastPcapPath,
    reparseWithProto,
    interfaces,
    selectedInterface,
    bpfFilter,
    capturing,
    paused,
    follow,
    liveTotal,
    pausedBuffer,
    openPcap,
    saveDisplayedPcapng,
    selectRow,
    loadInterfaces,
    startCapture,
    stopCapture,
    togglePause,
    clearData,
  }
})
