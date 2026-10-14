<script setup lang="ts">
// protobuf 树节点：递归展开、数组批量展开/收起、bytes hex 分页、搜索过滤
import { computed, inject, ref, watch } from 'vue'
import { ChevronDown, ChevronRight, ListTree, ListCollapse } from 'lucide-vue-next'
import type { ProtoFieldNode } from '../types/messages'

const props = defineProps<{
  node: ProtoFieldNode
  depth: number
  search?: string
}>()

const HEX_BYTES_PER_PAGE = 256
const hexPage = ref(0)

const node = computed(() => props.node)
const isContainer = computed(() => node.value.children?.length > 0)

// 树总线：展开/折叠广播给所有后代。
// mode 记录最后操作意图：v-if 折叠的子树在展开时新挂载的组件据此初始化状态
interface TreeBus {
  expandTick: number
  collapseTick: number
  mode: 'default' | 'expandAll' | 'collapse'
}
const bus = inject<TreeBus>('proto-tree-bus', {
  expandTick: 0,
  collapseTick: 0,
  mode: 'default',
})

function initialExpanded(): boolean {
  // bytes 节点（hex 数据）默认折叠，其余默认全部展开
  if (node.value.kind === 'bytes') return false
  if (bus.mode === 'expandAll') return true
  if (bus.mode === 'collapse') return props.depth === 0
  return true
}
const expanded = ref(initialExpanded())

watch(
  () => bus.expandTick,
  () => {
    if (isContainer.value && node.value.kind !== 'bytes') expanded.value = true
  },
)
watch(
  () => bus.collapseTick,
  () => {
    // 全部折叠：只保留根节点展开（能看到第一层字段）
    expanded.value = props.depth === 0
  },
)

const matches = computed(() => {
  const s = props.search?.trim().toLowerCase()
  if (!s) return true
  return (
    node.value.name.toLowerCase().includes(s) ||
    node.value.valueLabel.toLowerCase().includes(s) ||
    node.value.typeName.toLowerCase().includes(s)
  )
})

const childMatches = computed(() => {
  const s = props.search?.trim().toLowerCase()
  if (!s) return true
  const hit = (n: ProtoFieldNode): boolean =>
    n.name.toLowerCase().includes(s) ||
    n.valueLabel.toLowerCase().includes(s) ||
    n.typeName.toLowerCase().includes(s) ||
    n.children.some(hit)
  return node.value.children.some(hit)
})

const visibleChildren = computed(() => {
  const s = props.search?.trim().toLowerCase()
  if (!s) return node.value.children
  const hit = (n: ProtoFieldNode): boolean =>
    n.name.toLowerCase().includes(s) ||
    n.valueLabel.toLowerCase().includes(s) ||
    n.typeName.toLowerCase().includes(s) ||
    n.children.some(hit)
  return node.value.children.filter((c) => hit(c))
})

const kindColor = computed(() => {
  switch (node.value.kind) {
    case 'message':
      return 'text-accent'
    case 'repeated':
    case 'map':
      return 'text-purple'
    case 'enum':
      return 'text-orange'
    case 'bytes':
      return 'text-cyan'
    case 'timestamp':
      return 'text-accent'
    case 'error':
      return 'text-red'
    default:
      return 'text-green'
  }
})

/** 值是否像标量一样渲染（message/repeated 之外都渲染 ": value"） */
const showValue = computed(
  () => node.value.kind !== 'message' && node.value.kind !== 'repeated',
)

const isBigArray = computed(
  () => (node.value.kind === 'repeated' || node.value.kind === 'map') && node.value.children.length > 3,
)

const HEX_GROUP_CHARS = HEX_BYTES_PER_PAGE * 3
const hexPages = computed(() =>
  node.value.hex ? Math.ceil(node.value.hex.length / HEX_GROUP_CHARS) : 0,
)
const hexDisplay = computed(() => {
  if (!node.value.hex) return ''
  if (hexPages.value <= 1) return node.value.hex
  const start = hexPage.value * HEX_GROUP_CHARS
  return node.value.hex.slice(start, start + HEX_GROUP_CHARS)
})
const hexStartByte = computed(() => hexPage.value * HEX_BYTES_PER_PAGE)

function toggle() {
  // 手动操作后回归默认展开策略，全局模式不再影响新挂载的子层
  bus.mode = 'default'
  if (isContainer.value) expanded.value = !expanded.value
}

function expandAllBelow() {
  bus.mode = 'expandAll'
  bus.expandTick++
}
function collapseBelow() {
  bus.mode = 'collapse'
  bus.collapseTick++
}

function label(n: ProtoFieldNode): string {
  if (n.index !== null) return `[${n.index}] ${n.name}`
  return n.name
}
</script>

<template>
  <div v-if="matches || childMatches" class="leading-[20px]">
    <div
      class="flex items-start gap-1 cursor-pointer hover:bg-bg-hover/60 rounded px-1 -mx-1"
      :class="{ 'bg-orange/10': search && matches }"
      @click="toggle"
    >
      <span class="w-3.5 shrink-0 flex justify-center" :class="isContainer ? 'text-text-dim' : 'opacity-0'">
        <ChevronDown v-if="expanded" :size="13" class="mt-[3px]" />
        <ChevronRight v-else :size="13" class="mt-[3px]" />
      </span>
      <span class="shrink-0" :class="kindColor">{{ label(node) }}</span>
      <span v-if="node.kind === 'repeated' || node.kind === 'map'" class="text-purple shrink-0">
        {{ node.valueLabel }}
      </span>
      <span v-if="showValue" class="text-text-dim shrink-0">:</span>
      <span
        v-if="showValue"
        class="break-all"
        :class="node.kind === 'timestamp' ? 'text-cyan font-medium' : 'text-text-main'"
      >{{ node.valueLabel }}</span>
      <span class="text-[10px] text-text-dim/60 ml-auto pl-2 shrink-0 mt-[2px]">{{ node.typeName }}</span>
      <span
        v-if="isBigArray && expanded"
        class="shrink-0 flex items-center gap-1 text-[10px]"
        @click.stop
      >
        <button
          class="flex items-center gap-0.5 text-accent hover:underline"
          title="展开此数组下全部层级"
          @click="expandAllBelow"
        >
          <ListTree :size="11" /> 展开全部
        </button>
        <button
          class="flex items-center gap-0.5 text-text-dim hover:text-text-main hover:underline"
          title="收起到第一层"
          @click="collapseBelow"
        >
          <ListCollapse :size="11" /> 收起
        </button>
      </span>
    </div>

    <!-- bytes hex -->
    <div v-if="node.kind === 'bytes' && expanded && hexDisplay" class="ml-5 my-0.5">
      <pre class="mono text-[11px] text-cyan/80 whitespace-pre-wrap bg-bg-base/50 rounded p-1.5 border border-border-dim/40">{{ hexDisplay }}</pre>
      <div v-if="hexPages > 1" class="flex items-center gap-2 text-[11px] text-text-dim mt-0.5">
        <button class="hover:text-text-main disabled:opacity-30" :disabled="hexPage === 0" @click.stop="hexPage--">
          ‹ 上一页
        </button>
        <span>{{ hexStartByte }}–{{ Math.min((hexPage + 1) * HEX_BYTES_PER_PAGE, node.hexTotal ?? 0) }} / {{ node.hexTotal }} 字节，第 {{ hexPage + 1 }}/{{ hexPages }} 页</span>
        <button
          class="hover:text-text-main disabled:opacity-30"
          :disabled="hexPage >= hexPages - 1"
          @click.stop="hexPage++"
        >
          下一页 ›
        </button>
      </div>
    </div>

    <!-- children -->
    <div v-if="isContainer && expanded" class="ml-[18px] border-l border-border-dim/40 pl-1">
      <ProtoNode
        v-for="(c, i) in visibleChildren"
        :key="`${c.name}-${i}`"
        :node="c"
        :depth="depth + 1"
        :search="search"
      />
      <div v-if="visibleChildren.length === 0 && search" class="text-text-dim text-[11px] px-2">
        （无匹配子项）
      </div>
    </div>
  </div>
</template>
