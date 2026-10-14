<script setup lang="ts">
// 可拖拽左右分隔 + 详情最大化
import { computed, ref } from 'vue'

const props = defineProps<{ initial?: number }>()
const ratio = ref(props.initial ?? 0.58)
const container = ref<HTMLElement | null>(null)
const dragging = ref(false)
const maximized = ref(false)

const leftStyle = computed(() => {
  if (maximized.value) return { flex: '0 0 0', minWidth: '0' }
  return { flex: `0 0 calc(${(ratio.value * 100).toFixed(2)}% - 3px)` }
})
const rightStyle = computed(() => {
  if (maximized.value) return { flex: '1 1 auto' }
  return { flex: '1 1 auto' }
})

function onMouseDown() {
  dragging.value = true
  const move = (ev: MouseEvent) => {
    const el = container.value
    if (!el) return
    const rect = el.getBoundingClientRect()
    ratio.value = Math.min(0.85, Math.max(0.15, (ev.clientX - rect.left) / rect.width))
  }
  const up = () => {
    dragging.value = false
    window.removeEventListener('mousemove', move)
    window.removeEventListener('mouseup', up)
  }
  window.addEventListener('mousemove', move)
  window.addEventListener('mouseup', up)
}

function toggleMax() {
  maximized.value = !maximized.value
}

defineExpose({ toggleMax, maximized })
</script>

<template>
  <div ref="container" class="flex flex-row h-full min-h-0 relative" :class="{ 'select-none': dragging }">
    <div v-show="!maximized" :style="leftStyle" class="min-w-0 overflow-hidden">
      <slot name="left" />
    </div>

    <!-- 分隔条 -->
    <div
      v-show="!maximized"
      class="w-[6px] cursor-col-resize bg-bg-panel hover:bg-accent/60 transition-colors flex items-center justify-center group shrink-0"
      @mousedown="onMouseDown"
    >
      <div class="h-8 w-[2px] rounded bg-border-dim group-hover:bg-accent" />
    </div>

    <div :style="rightStyle" class="min-w-0 overflow-hidden">
      <slot name="right" />
    </div>
  </div>
</template>
