<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { useVirtualizer } from '@tanstack/vue-virtual'
import { ArrowDown, ArrowUp } from 'lucide-vue-next'
import { useAnalyzerStore } from '../stores/analyzer'
import { fmtAbsTime } from '../types/messages'

const store = useAnalyzerStore()

// ---------- 列定义与宽度（可拖拽，localStorage 持久化） ----------
interface Col {
  key: string
  title: string
  w: number
}
const DEFAULT_WIDTHS = [64, 120, 70, 130, 320, 70, 160, 240]
const WIDTHS_KEY = 'zenoh-analyzer.table-widths'

function loadWidths(): number[] {
  try {
    const saved = JSON.parse(localStorage.getItem(WIDTHS_KEY) ?? 'null') as number[] | null
    if (Array.isArray(saved) && saved.length === DEFAULT_WIDTHS.length) {
      return saved.map((w) => Math.max(30, w))
    }
  } catch {
    /* ignore */
  }
  return [...DEFAULT_WIDTHS]
}

const widths = ref<number[]>(loadWidths())
watch(widths, (v) => localStorage.setItem(WIDTHS_KEY, JSON.stringify(v)), { deep: true })

const cols = computed<Col[]>(() => [
  { key: 'no', title: '序号', w: widths.value[0] },
  { key: 'time', title: '时间', w: widths.value[1] },
  { key: 'dir', title: '方向', w: widths.value[2] },
  { key: 'type', title: 'Zenoh 消息', w: widths.value[3] },
  { key: 'topic', title: 'Topic', w: widths.value[4] },
  { key: 'pair', title: '配对', w: widths.value[5] },
  { key: 'summary', title: '摘要', w: widths.value[6] },
  { key: 'device', title: '设备', w: widths.value[7] },
])

const gridTemplate = computed(() => widths.value.map((w) => `${w}px`).join(' '))
const totalWidth = computed(() => widths.value.reduce((a, b) => a + b, 0))

let resizing = -1
let resizeStartX = 0
let resizeStartW = 0
const resizingNow = ref(false)

function startResize(i: number, e: MouseEvent) {
  e.preventDefault()
  e.stopPropagation()
  resizing = i
  resizeStartX = e.clientX
  resizeStartW = widths.value[i]
  resizingNow.value = true
  const move = (ev: MouseEvent) => {
    if (resizing < 0) return
    const dx = ev.clientX - resizeStartX
    widths.value[resizing] = Math.max(30, resizeStartW + dx)
  }
  const up = () => {
    resizing = -1
    resizingNow.value = false
    window.removeEventListener('mousemove', move)
    window.removeEventListener('mouseup', up)
  }
  window.addEventListener('mousemove', move)
  window.addEventListener('mouseup', up)
}

function resetWidth(i: number) {
  widths.value[i] = DEFAULT_WIDTHS[i]
}

// ---------- 虚拟滚动 ----------
const parent = ref<HTMLElement | null>(null)
const list = computed(() => store.filteredRows)

const virtualizerOptions = computed(() => ({
  count: list.value.length,
  getScrollElement: () => parent.value,
  estimateSize: () => 26,
  overscan: 20,
}))
const virtualizer = useVirtualizer(virtualizerOptions)

// 键盘：上下导航 + Ctrl+C 复制选中行
function onKeydown(e: KeyboardEvent) {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'c') {
    const row = store.rows.find((r) => r.index === store.selectedIndex)
    if (row) {
      const text = [
        `#${row.frameNumber || row.index + 1}`,
        fmtAbsTime(row.tsUs),
        row.src,
        row.direction,
        row.msgType,
        row.topic,
        [row.outerType, row.anyType].filter(Boolean).join(' → '),
        row.summary,
      ]
        .filter(Boolean)
        .join('\t')
      navigator.clipboard.writeText(text)
    }
    return
  }
  if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return
  if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return
  e.preventDefault()
  const cur = store.selectedIndex
  const curIdx = list.value.findIndex((r) => r.index === cur)
  let next: number
  if (curIdx === -1) {
    next = 0
  } else {
    next = e.key === 'ArrowDown' ? Math.min(curIdx + 1, list.value.length - 1) : Math.max(curIdx - 1, 0)
  }
  const row = list.value[next]
  if (row) {
    store.selectRow(row.index)
    scrollToIndex(next)
  }
}

function scrollToIndex(i: number) {
  nextTick(() => {
    virtualizer.value.scrollToIndex(i, { align: 'auto' })
  })
}

// 跟随最新
watch(
  () => list.value.length,
  async (n, old) => {
    if (store.mode === 'live' && store.follow && !store.paused && n > (old ?? 0)) {
      await nextTick()
      parent.value?.scrollTo({ top: parent.value.scrollHeight })
    }
  },
)

// 跟随选中项
watch(
  () => store.selectedIndex,
  (idx) => {
    if (idx === null) return
    const i = list.value.findIndex((r) => r.index === idx)
    if (i >= 0) scrollToIndex(i)
  },
)

// 表头与数据体横向滚动同步（表头自身不显示滚动条）
const headerShift = ref(0)
function onBodyScroll() {
  headerShift.value = parent.value?.scrollLeft ?? 0
}

const pairMap = computed(() => {
  const m = new Map<number, number>()
  for (const r of store.rows) {
    if (r.pairIndex !== null) {
      m.set(r.index, r.pairIndex)
    }
  }
  return m
})
function pairOf(index: number): number | null {
  return pairMap.value.get(index) ?? null
}

/** 选中 Request 时高亮其全部 Response；选中 Response 时高亮 Request 及同 rid 兄弟 */
const highlightSet = computed(() => {
  const set = new Set<number>()
  const sel = store.selectedIndex
  if (sel === null) return set
  set.add(sel)
  const selRow = store.rows.find((r) => r.index === sel)
  if (!selRow) return set
  const isResp = selRow.msgType.startsWith('Response')
  const anchor = isResp ? pairOf(sel) : sel // Request 自身或其配对的 Request
  if (anchor === null) return set
  // anchor 是 Request：收集所有回指它的 Response
  for (const r of store.rows) {
    if (r.pairIndex === anchor && r.index !== sel) set.add(r.index)
  }
  const reqIdx = isResp ? anchor : sel
  // Response 选中时也高亮 Request 本身
  if (isResp && pairOf(sel) !== null) set.add(pairOf(sel)!)
  void reqIdx
  return set
})

function rowClass(r: (typeof list.value)[number]): string {
  const cls = ['h-[26px]']
  if (r.index === store.selectedIndex) cls.push('bg-accent/25')
  else if (highlightSet.value.has(r.index)) cls.push('bg-green/15')
  return cls.join(' ')
}

function typeClass(t: string): string {
  if (t.startsWith('Push')) return 'text-cyan'
  if (t.startsWith('Request')) return 'text-orange'
  if (t.startsWith('Response(Reply)')) return 'text-green'
  if (t.startsWith('Response(Err)')) return 'text-red'
  if (t.startsWith('ResponseFinal')) return 'text-green/70'
  if (t.startsWith('Declare') || t.startsWith('Interest')) return 'text-purple'
  return 'text-text-dim'
}
</script>

<template>
  <div class="flex flex-col h-full min-h-0 outline-none" tabindex="0" @keydown="onKeydown">
    <!-- 表头（无独立滚动条，随数据体横向同步；stable gutter 对齐滚动条宽度） -->
    <div
      class="overflow-hidden border-b border-border-dim bg-bg-panel select-none shrink-0 scrollbar-gutter"
    >
      <div
        class="grid items-center h-7 text-[11px] text-text-dim px-2"
        :style="{
          gridTemplateColumns: gridTemplate,
          width: `${totalWidth}px`,
          transform: `translateX(${-headerShift}px)`,
        }"
      >
        <div
          v-for="(c, i) in cols"
          :key="c.key"
          class="relative h-7 flex items-center min-w-0"
        >
          <span class="truncate">{{ c.title }}</span>

          <!-- 列宽拖拽手柄（含常显分隔线） -->
          <div
            class="absolute right-0 top-0 h-full w-[9px] cursor-col-resize group -mr-[4px] z-10"
            title="拖拽调整列宽，双击恢复默认"
            @mousedown="startResize(i, $event)"
            @dblclick="resetWidth(i)"
          >
            <div
              class="absolute right-[4px] top-1.5 bottom-1.5 w-px bg-text-dim/40 group-hover:w-[2px] group-hover:bg-accent transition-colors"
            />
          </div>
        </div>
      </div>
    </div>

    <!-- 数据体 -->
    <div ref="parent" class="flex-1 overflow-auto min-h-0 relative scrollbar-gutter" @scroll="onBodyScroll">
      <div
        v-if="list.length === 0"
        class="absolute inset-0 flex flex-col items-center justify-center gap-2 text-text-dim"
      >
        <template v-if="store.loading">
          <div class="animate-pulse text-accent">解析中…</div>
        </template>
        <template v-else>
          <div class="text-[15px]">打开 pcapng 文件，或开始实时捕获</div>
          <div class="text-[12px]">解码需要 proto 定义目录（工具栏选择）</div>
        </template>
      </div>

      <div :style="{ height: `${virtualizer.getTotalSize()}px`, position: 'relative', minWidth: `${totalWidth}px` }">
        <div
          v-for="vrow in virtualizer.getVirtualItems()"
          :key="list[vrow.index].index"
          :style="{
            position: 'absolute',
            top: 0,
            left: 0,
            width: '100%',
            transform: `translateY(${vrow.start}px)`,
          }"
        >
          <div
            class="grid items-center px-2 mono text-[12px] cursor-pointer hover:bg-bg-hover border-b border-border-dim/30 select-text"
            :class="rowClass(list[vrow.index])"
            :style="{ gridTemplateColumns: gridTemplate }"
            :title="list[vrow.index].warnings.join('；')"
            @click="store.selectRow(list[vrow.index].index)"
          >
            <div class="text-text-dim truncate">{{ vrow.index + 1 }}</div>
            <div class="truncate">{{ fmtAbsTime(list[vrow.index].tsUs) }}</div>
            <div class="truncate" :class="list[vrow.index].direction === '→设备' ? 'text-orange' : 'text-cyan'">
              {{ list[vrow.index].direction }}
            </div>
            <div class="truncate" :class="typeClass(list[vrow.index].msgType)" :title="list[vrow.index].msgType">
              {{ list[vrow.index].msgType }}
            </div>
            <div class="truncate" :class="list[vrow.index].topicComplete ? '' : 'text-orange'" :title="list[vrow.index].topic">
              {{ list[vrow.index].topic }}
            </div>
            <div class="text-center truncate">
              <span
                v-if="list[vrow.index].pairIndex !== null"
                class="inline-flex items-center gap-0.5 text-green"
                :title="list[vrow.index].rttMs !== null ? `RTT ${list[vrow.index].rttMs!.toFixed(1)} ms` : '配对消息'"
              >
                <ArrowDown v-if="list[vrow.index].msgType.startsWith('Request')" :size="12" />
                <ArrowUp v-else :size="12" />
                {{ list[vrow.index].rttMs !== null ? `${list[vrow.index].rttMs!.toFixed(0)}ms` : '' }}
              </span>
            </div>
            <div class="truncate text-text-dim" :title="list[vrow.index].summary">{{ list[vrow.index].summary }}</div>
            <div class="truncate" :title="list[vrow.index].deviceId">{{ list[vrow.index].deviceId }}</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
