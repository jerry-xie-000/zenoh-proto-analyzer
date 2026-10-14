<script setup lang="ts">
import { computed, provide, reactive, ref, watch } from 'vue'
import { Check, Copy, ListCollapse, ListTree, Maximize2, Search } from 'lucide-vue-next'
import { useAnalyzerStore } from '../stores/analyzer'
import { fmtAbsTime, fmtRelTime, type ProtoFieldNode } from '../types/messages'
import ProtoNode from './ProtoNode.vue'

const emit = defineEmits<{ toggleMax: [] }>()

const store = useAnalyzerStore()
const treeSearch = ref('')
const expandedBus = reactive({
  expandTick: 0,
  collapseTick: 0,
  mode: 'default' as 'default' | 'expandAll' | 'collapse',
})
provide('proto-tree-bus', expandedBus)

// 切换选中行时重置树状态（树按 selectedIndex 重建，重新挂载即按默认全展开初始化）
watch(
  () => store.selectedIndex,
  () => {
    treeSearch.value = ''
    expandedBus.mode = 'default'
    copied.value = false
  },
)

function expandAll() {
  expandedBus.mode = 'expandAll'
  expandedBus.expandTick++
}
function collapseAll() {
  expandedBus.mode = 'collapse'
  expandedBus.collapseTick++
}

const row = computed(() =>
  store.selectedIndex !== null ? store.rows.find((r) => r.index === store.selectedIndex) : null,
)

// ---------- 复制 ----------
const copied = ref(false)

function treeToText(n: ProtoFieldNode, depth: number): string {
  const pad = '  '.repeat(depth)
  let line = pad + n.name
  if (n.kind === 'repeated' || n.kind === 'map') line += ` ${n.valueLabel}`
  else if (n.kind === 'message') {
    if (n.valueLabel) line += ` (${n.valueLabel})`
  } else line += `: ${n.valueLabel}`
  const lines = [line]
  for (const c of n.children) lines.push(treeToText(c, depth + 1))
  return lines.join('\n')
}

async function copyDetail() {
  if (!row.value || !store.detail) return
  const lines: string[] = []
  lines.push(
    `#${row.value.frameNumber || row.value.index + 1}  ${fmtAbsTime(row.value.tsUs)}  ${row.value.src} → ${row.value.dst}  ${row.value.msgType}`,
  )
  if (row.value.topic) lines.push(`Topic: ${row.value.topic}`)
  lines.push('')
  lines.push('[Zenoh]')
  for (const f of store.detail.zenohFields) lines.push(`  ${f.key}: ${f.value}`)
  if (store.detail.protoTree) {
    lines.push('')
    lines.push('[Protobuf]')
    lines.push(treeToText(store.detail.protoTree, 0))
  }
  if (store.detail.hexLines.length) {
    lines.push('')
    lines.push('[Hex]')
    lines.push(...store.detail.hexLines)
  }
  await navigator.clipboard.writeText(lines.join('\n'))
  copied.value = true
  setTimeout(() => (copied.value = false), 1500)
}
</script>

<template>
  <div class="flex flex-col h-full min-h-0 bg-bg-base">
    <div v-if="!row || !store.detail" class="flex-1 flex items-center justify-center text-text-dim">
      选择一条消息查看详情（↑↓ 键切换）
    </div>
    <template v-else>
      <!-- 概要条 -->
      <div class="flex items-center gap-3 px-3 h-8 border-b border-border-dim bg-bg-panel text-[12px] shrink-0">
        <span class="mono text-accent">#{{ row.frameNumber || row.index + 1 }}</span>
        <span :class="row.direction === '→设备' ? 'text-orange' : 'text-cyan'">
          {{ row.src }} → {{ row.dst }}
        </span>
        <span>{{ fmtAbsTime(row.tsUs) }} <span class="text-text-dim">({{ fmtRelTime(row.relUs) }})</span></span>
        <span class="text-text-dim">{{ row.msgType }}</span>
        <div class="flex-1" />
        <button
          class="flex items-center gap-1 text-text-dim hover:text-accent"
          :class="{ 'text-green': copied }"
          title="复制本条详情全文"
          @click="copyDetail"
        >
          <Check v-if="copied" :size="14" class="text-green" />
          <Copy v-else :size="14" />
          {{ copied ? '已复制' : '复制详情' }}
        </button>
        <button
          class="text-text-dim hover:text-accent"
          title="详情面板最大化 / 还原 (Esc)"
          @click="emit('toggleMax')"
        >
          <Maximize2 :size="14" />
        </button>
      </div>

      <div class="flex-1 overflow-auto min-h-0 p-2 space-y-2 select-text cursor-text">
        <!-- Zenoh 层 -->
        <details open class="section">
          <summary class="sec-title">Zenoh 层</summary>
          <div class="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-0.5 mono text-[12px] px-1">
            <template v-for="f in store.detail.zenohFields" :key="f.key">
              <div class="text-text-dim">{{ f.key }}</div>
              <div class="break-all">{{ f.value }}</div>
            </template>
          </div>
        </details>

        <!-- Protobuf 树 -->
        <details open class="section">
          <summary class="sec-title flex items-center gap-2">
            Protobuf
            <div class="relative" @click.stop>
              <Search :size="12" class="absolute left-1.5 top-1/2 -translate-y-1/2 text-text-dim" />
              <input
                v-model="treeSearch"
                class="input w-48 h-6 pl-6 text-[11px]"
                placeholder="树内搜索字段/值…"
                @keydown.stop
              />
            </div>
            <div class="flex items-center gap-1" @click.stop>
              <button
                class="flex items-center gap-0.5 text-[11px] text-text-dim hover:text-accent"
                title="展开全部层级"
                @click="expandAll"
              >
                <ListTree :size="12" /> 展开全部
              </button>
              <button
                class="flex items-center gap-0.5 text-[11px] text-text-dim hover:text-accent"
                title="一键折叠到第一层"
                @click="collapseAll"
              >
                <ListCollapse :size="12" /> 一键折叠
              </button>
            </div>
          </summary>
          <div class="px-1">
            <template v-if="store.detail.protoTree">
              <ProtoNode
                :key="store.selectedIndex ?? 'none'"
                :node="store.detail.protoTree"
                :depth="0"
                :search="treeSearch"
              />
            </template>
            <div v-else class="text-text-dim text-[12px] px-1">无 payload 或未加载 proto</div>
          </div>
        </details>

        <!-- 原始 Hex -->
        <details class="section">
          <summary class="sec-title">原始 Hex（{{ row.payloadLen }} 字节）</summary>
          <pre class="mono text-[11px] text-text-dim px-2 py-1 whitespace-pre overflow-x-auto select-text cursor-text">{{ store.detail.hexLines.join('\n') }}</pre>
        </details>

        <!-- 警告 -->
        <div v-if="row.warnings.length" class="text-orange text-[11px] px-1">
          ⚠ {{ row.warnings.join('；') }}
        </div>
      </div>
    </template>
  </div>
</template>
